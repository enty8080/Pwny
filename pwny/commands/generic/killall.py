"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from hatsploit.lib.command import Command


class HatSploitCommand(Command):
    def __init__(self):
        super().__init__()

        self.details = {
            'Category': "manage",
            'Name': "killall",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Kill process by name.",
            'Usage': "killall <name>",
            'MinArgs': 1
        }

    def run(self, argc, argv):
        result = self.session.send_command(
            tag=PROCESS_KILLALL,
            args={
                PROCESS_TYPE_PID_NAME: argv[1]
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(f"Process: {str(argv[1])}: does not exist!")
            return
