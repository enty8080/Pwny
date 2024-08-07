"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

UI_BASE = 6

UI_SAY = tlv_custom_tag(API_CALL_STATIC, UI_BASE, API_CALL + 5)


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "UI",
            'Name': "say",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Convert message to speech.",
            'Usage': "say <message>",
            'MinArgs': 1
        })

    def run(self, args):
        self.session.send_command(
            tag=UI_SAY,
            args={
                TLV_TYPE_STRING: args[1]
            }
        )
