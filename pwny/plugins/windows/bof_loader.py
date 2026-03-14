"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import struct

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin

BOF_BASE = 33

BOF_EXECUTE = tlv_custom_tag(API_CALL_STATIC, BOF_BASE, API_CALL)

# TLV_TYPE_BYTES is used for the COFF object file
# TLV_TYPE_BYTES + 1 is used for the packed argument buffer
BOF_TYPE_ARGS = TLV_TYPE_BYTES + 1


class BOFPacker:
    """Pack arguments for BOF entry points using Cobalt Strike's
    bof_pack convention: length-prefixed typed values."""

    def __init__(self):
        self.buffer = b''

    def add_int(self, value):
        self.buffer += struct.pack('<I', value & 0xFFFFFFFF)

    def add_short(self, value):
        self.buffer += struct.pack('<H', value & 0xFFFF)

    def add_str(self, value):
        if isinstance(value, str):
            value = value.encode('utf-8') + b'\x00'
        self.buffer += struct.pack('<I', len(value)) + value

    def add_wstr(self, value):
        if isinstance(value, str):
            value = value.encode('utf-16-le') + b'\x00\x00'
        self.buffer += struct.pack('<I', len(value)) + value

    def add_bytes(self, value):
        self.buffer += struct.pack('<I', len(value)) + value

    def get(self):
        return self.buffer


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "BOF Loader Plugin",
            'Plugin': "bof_loader",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "Execute a Beacon Object File (COFF .o) in-memory.",
        })

        self.commands = [
            Command({
                'Category': "manage",
                'Name': "bof",
                'Description': "Execute a Beacon Object File (COFF .o) in-memory.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('file',),
                        {
                            'help': "Path to the COFF object file (.o).",
                            'type': str,
                        }
                    ),
                    (
                        ('-a', '--args'),
                        {
                            'help': "Hex-encoded argument buffer for go().",
                            'metavar': 'HEX',
                        }
                    ),
                    (
                        ('-s', '--str-args'),
                        {
                            'help': "Pass string arguments (packed as bof_pack z-strings).",
                            'nargs': '*',
                            'metavar': 'STR',
                        }
                    ),
                ]
            })
        ]

    def bof(self, args):
        try:
            with open(args.file, 'rb') as f:
                obj_data = f.read()
        except (IOError, OSError) as e:
            self.print_error("Cannot read object file: %s" % str(e))
            return

        tlv_args = {
            TLV_TYPE_BYTES: obj_data,
        }

        # Build argument buffer
        arg_buf = b''

        if args.args:
            try:
                arg_buf = bytes.fromhex(args.args)
            except ValueError:
                self.print_error("Invalid hex argument buffer!")
                return

        elif args.str_args:
            packer = BOFPacker()
            for s in args.str_args:
                packer.add_str(s)
            arg_buf = packer.get()

        if arg_buf:
            tlv_args[BOF_TYPE_ARGS] = arg_buf

        self.print_process("Executing BOF (%d bytes)..." % len(obj_data))

        result = self.session.send_command(
            tag=BOF_EXECUTE,
            plugin=self.plugin,
            args=tlv_args,
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("BOF execution failed!")
            return

        self.print_success("BOF executed successfully.")

    def load(self):
        pass
