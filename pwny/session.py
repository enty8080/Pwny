"""
MIT License

Copyright (c) 2020-2024 EntySec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import os
import socket
import pathlib
import threading

from alive_progress import alive_bar

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

from typing import Optional, Union

from pwny.types import *
from pwny.api import *

from pwny.tlv import TLV, HTTPTLV
from pwny.pipes import Pipes
from pwny.spawn import Spawn
from pwny.console import Console

from pex.fs import FS
from pex.ssl import OpenSSL
from pex.string import String

from pex.proto.tlv import (
    TLVClient,
    TLVPacket,
    TLVServerHTTP
)
from pex.proto.http import HTTPListener

from hatsploit.lib.core.session import Session
from hatsploit.lib.loot import Loot


class PwnySessionTemplate(Session, FS, OpenSSL):
    """ Subclass of pwny module.

    This subclass of pwny module represents an implementation
    of the Pwny session for HatSploit Framework.
    """

    def __init__(self) -> None:
        super().__init__({
            'Type': "pwny"
        })

        self.pwny = f'{os.path.dirname(os.path.dirname(__file__))}/pwny/'

        self.pwny_data = self.pwny + 'data/'
        self.pwny_tabs = self.pwny + 'tabs/'
        self.pwny_loot = f'{pathlib.Path.home()}/.pwny/'

        self.pwny_plugins = self.pwny + 'plugins/'
        self.pwny_commands = self.pwny + 'commands/'

        self.templates = self.pwny + 'templates/'

        self.channel = None
        self.uuid = None
        self.terminated = False
        self.reason = TERM_UNKNOWN

        self.pipes = Pipes(self)
        self.console = None

        self.loot = Loot(self.pwny_loot)

    def identify(self) -> None:
        """ Enforce platform and architecture identification
        by calling partially completed sysinfo.

        :return None: None
        """

        result = self.send_command(
            tag=BUILTIN_SYSINFO
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            raise RuntimeError("Failed to identify target system!")

        platform = result.get_string(BUILTIN_TYPE_PLATFORM)
        arch = result.get_string(BUILTIN_TYPE_ARCH)

        if platform.lower() == 'ios':
            platform = 'apple_ios'

        self.info.update({
            'Platform': platform,
            'Arch': arch
        })

    def secure(self, algo: int = ALGO_AES256_CBC) -> bool:
        """ Establish secure TLS communication.

        :param int algo: encryption algorithm to use
        :return bool: True if success else False
        """

        if self.channel.cipher.secure:
            self.print_process("Initializing re-exchange of keys...")

        self.print_process("Generating RSA keys (1/2)")
        key = self.generate_key()

        priv_key = self.dump_key(key)
        pub_key = self.dump_public_key(key)

        self.print_process("Exchanging RSA keys (2/2)")

        result = self.send_command(
            tag=BUILTIN_SECURE,
            args={
                BUILTIN_TYPE_PUBLIC_KEY: pub_key,
                TLV_TYPE_INT: algo
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to exchange keys!")
            return False

        self.print_success("RSA keys exchange success!")
        sym_key = result.get_raw(BUILTIN_TYPE_KEY)

        if not sym_key:
            self.print_error("Symmetric key was not received!")
            return False

        context = serialization.load_pem_private_key(
            priv_key,
            password=None,
        )
        sym_key_plain = context.decrypt(
            sym_key,
            padding.PKCS1v15()
        )

        self.print_success(f"Session secured with {ALGO[algo]}!")
        self.channel.cipher.set_key(sym_key_plain, algo)

        return True

    def unsecure(self) -> None:
        """ Unsecure session.

        :return None: None
        """

        self.print_process("Disabling session encryption...")
        self.send_command(tag=BUILTIN_UNSECURE)

        self.channel.cipher.set_key(None)
        self.print_success("Session encryption disabled!")

    def heartbeat(self) -> bool:
        """ Check the Pwny session heartbeat.

        :return bool: True if the Pwny session is alive
        """

        if not self.channel.running and self.channel.error:
            self.reason = TERM_DEAD
            self.terminated = True

        return not self.terminated

    def execute(self, command: str, output: bool = False) -> Union[None, str]:
        """ Send command to this session.

        :param str command: command to send
        :param bool output: True to wait for output else False
        :return Union[None, str]: None if output is False else output
        """

        result = self.console.pwny_exec(command)

        if output:
            return result

    def download(self, remote_file: str, local_path: str) -> bool:
        """ Download file from the Pwny session.

        :param str remote_file: file to download
        :param str local_path: path to save downloaded file to
        :return bool: True if download succeed
        """

        exists, is_dir = self.exists(local_path)

        if not exists:
            self.check_file(local_path)
            return False

        if is_dir:
            local_path = os.path.abspath(
                '/'.join((local_path, os.path.split(remote_file)[1])))

        try:
            pipe_id = self.pipes.create_pipe(
                pipe_type=FS_PIPE_FILE,
                args={
                    TLV_TYPE_FILENAME: remote_file,
                    FS_TYPE_MODE: 'rb',
                }
            )

        except RuntimeError:
            self.print_error(f"Remote file: {remote_file}: does not exist!")
            return False

        self.pipes.seek_pipe(FS_PIPE_FILE, pipe_id, 0, 2)
        size = self.pipes.tell_pipe(FS_PIPE_FILE, pipe_id)
        self.pipes.seek_pipe(FS_PIPE_FILE, pipe_id, 0, 0)

        self.interrupt()
        with open(local_path, 'wb') as f:
            with alive_bar(int(size / TLV_FILE_CHUNK) + 1, receipt=False,
                           ctrl_c=False, monitor="{percent:.0%}", stats=False,
                           title=os.path.split(remote_file)[1]) as bar:
                while size > 0:
                    bar()

                    chunk = min(TLV_FILE_CHUNK, size)
                    buffer = self.pipes.read_pipe(FS_PIPE_FILE, pipe_id, chunk)
                    f.write(buffer)
                    size -= chunk

        self.pipes.destroy_pipe(FS_PIPE_FILE, pipe_id)
        self.resume()
        return True

    def upload(self, local_file: str, remote_path: str) -> bool:
        """ Upload file to the Pwny session.

        :param str local_file: file to upload
        :param str remote_path: path to save uploaded file to
        :return bool: True if upload succeed
        """

        self.check_file(local_file)

        with open(local_file, 'rb') as f:
            buffer = f.read()
            size = len(buffer)

            pipe_id = self.pipes.create_pipe(
                pipe_type=FS_PIPE_FILE,
                args={
                    TLV_TYPE_FILENAME: remote_path,
                    FS_TYPE_MODE: 'wb',
                }
            )

            self.interrupt()
            with alive_bar(int(size / TLV_FILE_CHUNK) + 1, receipt=False,
                           ctrl_c=False, monitor="{percent:.0%}", stats=False,
                           title=os.path.split(local_file)[1]) as bar:
                for step in range(0, size, TLV_FILE_CHUNK):
                    bar()

                    chunk = buffer[step:step + TLV_FILE_CHUNK]
                    self.pipes.write_pipe(FS_PIPE_FILE, pipe_id, chunk)

            self.pipes.destroy_pipe(FS_PIPE_FILE, pipe_id)
            self.resume()
            return True

    def spawn(self, path: str, args: list = [], search: list = []) -> bool:
        """ Execute path.

        :param str path: path to execute
        :param list args: command-line arguments
        :param list search: list of paths to search for binary in
        :return bool: True if success else False
        """

        spawn = Spawn(self)

        if not os.path.isabs(path):
            for search_path in search:
                search_path = spawn.search_path(search_path, path)

                if search_path:
                    path = search_path
                    break

        return spawn.spawn(path, args)

    def interrupt(self) -> None:
        """ Interrupt all session events.

        :return None: None
        """

        return

    def resume(self) -> None:
        """ Resume all session events.

        :return None: None
        """

        return

    def interact(self, banner: bool = False,
                 tip: bool = True,
                 prompt: Optional[str] = None,
                 motd: Optional[str] = None) -> None:
        """ Interact with the Pwny session.

        :param bool banner: True to display banner else False
        :param bool tip: True to display tip else False
        :param Optional[str] prompt: custom prompt message
        :param Optional[str] motd: custom message of the day
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        if not self.console:
            raise RuntimeError("Not yet ready for interaction!")

        self.console.set_banner(banner)
        self.console.set_tip(tip)

        if prompt:
            self.console.set_prompt(prompt)
        if motd:
            self.console.set_motd(motd)

        self.resume()
        self.console.pwny_console()
        self.interrupt()


class PwnyHTTPSession(PwnySessionTemplate):
    """ Subclass of pwny module.

    This subclass of pwny module represents an implementation
    of the Pwny HTTP session for HatSploit Framework.
    """

    def __init__(self) -> None:
        super().__init__()

    def open(self, server: HTTPListener) -> None:
        """ Open the Pwny session.

        :param HTTPListener server: server to open session with
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        self.channel = HTTPTLV(TLVServerHTTP(server))
        self.channel.queue_start()

        self.redirect()

        tlv = self.send_command(BUILTIN_UUID)
        self.uuid = tlv.get_string(TLV_TYPE_UUID)

        if not self.uuid:
            raise RuntimeError("No UUID received or UUID broken!")

        self.loot.create_loot()

        if not self.info['Platform'] and not self.info['Arch']:
            self.identify()

        self.console = Console(self)
        self.console.start_pwny()

    def redirect(self) -> Union[str, None]:
        """ Generate new URL path and redirect client to it.

        :return str: new URL path
        """

        urlpath = String().random_string(16)

        result = self.send_command(
            tag=NET_GET_TUNNEL
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Unable to obtain current tunnel ID!")
            return

        tunnel = result.get_int(NET_TYPE_ID)
        uri = result.get_string(NET_TYPE_URI).split('|')  # In case if flags are set
        new_uri = uri[0] + urlpath

        if len(uri) == 2:
            new_uri += '|' + uri[1]

        result = self.send_command(
            tag=NET_RESTART_TUNNEL,
            args={
                NET_TYPE_ID: tunnel,
                NET_TYPE_URI: new_uri
            }
        )

        self.print_success(f"Redirected client to /{urlpath}!")

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to perform redirect, perhaps incompatible session!")
            return

        self.channel.redirect(urlpath)
        return urlpath

    def close(self) -> None:
        """ Close the Pwny session.

        :return None: None
        """

        self.channel.queue_stop()
        self.reason = TERM_CLOSED
        self.terminated = True

    def send_command(self, tag: int, args: dict = {}, plugin: Optional[int] = None) -> TLVPacket:
        """ Send command to the Pwny session.

        :param int tag: tag
        :param dict args: command arguments with their types
        :param Optional[int] plugin: plugin ID if tag is presented within the plugin
        :return TLVPacket: packets
        """

        tlv = TLVPacket()

        if plugin is not None:
            tlv.add_int(TLV_TYPE_TAB_ID, plugin)

        tlv.add_int(TLV_TYPE_TAG, tag)
        tlv.add_from_dict(args)

        try:
            self.channel.send(tlv)

        except Exception as e:
            self.terminated = True
            self.reason = str(e)

            raise RuntimeWarning(f"Connection terminated ({self.reason}).")

        query = {
            TLV_TYPE_TAG: tag
        }

        if PIPE_TYPE_ID in args and PIPE_TYPE_TYPE in args:
            query.update({
                PIPE_TYPE_TYPE: args[PIPE_TYPE_TYPE],
                PIPE_TYPE_ID: args[PIPE_TYPE_ID],
            })

        if plugin is not None:
            query.update({
                TLV_TYPE_TAB_ID: plugin
            })

        response = TLVPacket()

        self.channel.create_event(
            target=response,
            query=query,
            noapi=False,
            ttl=1,
        )

        while not response:
            pass

        return response


class PwnySession(PwnySessionTemplate):
    """ Subclass of pwny module.

    This subclass of pwny module represents an implementation
    of the Pwny TCP session for HatSploit Framework.
    """

    def __init__(self) -> None:
        super().__init__()

    def open(self, client: Union[socket.socket, list]) -> None:
        """ Open the Pwny session.

        :param Union[socket.socket, list] client: client to open session with or
        double client (read/write)
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        if isinstance(client, socket.socket):
            self.channel = TLV(TLVClient(client))

        else:
            self.print_process("Using dual TCP negotiation...")
            self.channel = TLV(
                (
                    TLVClient(client[0]),
                    TLVClient(client[1])
                )
            )

        self.resume()

        tlv = self.send_command(BUILTIN_UUID)
        self.uuid = tlv.get_string(TLV_TYPE_UUID)

        if not self.uuid:
            raise RuntimeError("No UUID received or UUID broken!")

        self.loot.create_loot()

        if not self.info['Platform'] and not self.info['Arch']:
            self.identify()

        self.console = Console(self)
        self.console.start_pwny()

    def close(self) -> None:
        """ Close the Pwny session.

        :return None: None
        """

        self.interrupt()
        self.channel.close()

        self.reason = TERM_CLOSED
        self.terminated = True

    def interrupt(self) -> None:
        """ Interrupt all session events.

        :return None: None
        """

        self.channel.queue_interrupt()

    def resume(self) -> None:
        """ Resume all session events.

        :return None: None
        """

        self.channel.queue_resume()

    def send_command(self, tag: int, args: dict = {}, plugin: Optional[int] = None) -> TLVPacket:
        """ Send command to the Pwny session.

        :param int tag: tag
        :param dict args: command arguments with their types
        :param Optional[int] plugin: plugin ID if tag is presented within the plugin
        :return TLVPacket: packets
        """

        tlv = TLVPacket()

        if plugin is not None:
            tlv.add_int(TLV_TYPE_TAB_ID, plugin)

        tlv.add_int(TLV_TYPE_TAG, tag)
        tlv.add_from_dict(args)

        try:
            self.channel.send(tlv)

        except Exception as e:
            self.terminated = True
            self.reason = str(e)

            raise RuntimeWarning(f"Connection terminated ({self.reason}).")

        query = {
            TLV_TYPE_TAG: tag
        }

        if PIPE_TYPE_ID in args and PIPE_TYPE_TYPE in args:
            query.update({
                PIPE_TYPE_TYPE: args[PIPE_TYPE_TYPE],
                PIPE_TYPE_ID: args[PIPE_TYPE_ID],
            })

        if plugin is not None:
            query.update({
                TLV_TYPE_TAB_ID: plugin
            })

        if self.channel.running:
            response = TLVPacket()

            self.channel.create_event(
                target=response,
                query=query,
                noapi=False,
                ttl=1,
            )

            while not response:
                pass

            return response

        while True:
            response = self.channel.read()

            if self.channel.tlv_query(response, query):
                break

            self.channel.queue.append(response)

        return response
