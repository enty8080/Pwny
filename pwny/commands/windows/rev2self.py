"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

TOKEN_BASE = 21

TOKEN_REV2SELF = tlv_custom_tag(API_CALL_STATIC, TOKEN_BASE, API_CALL + 1)


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "escalate",
            'Name': "rev2self",
            'Authors': [
                'EntySec - command developer',
            ],
            'Description': "Revert to original process token (undo steal_token/getsystem).",
        })

    def run(self, _):
        result = self.session.send_command(tag=TOKEN_REV2SELF)

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to revert to self!")
            return

        self.print_success("Reverted to original process token.")
