"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

SERVICES_BASE = 19

SERVICES_LIST = tlv_custom_tag(API_CALL_STATIC, SERVICES_BASE, API_CALL)

TLV_TYPE_SVC_NAME = tlv_custom_type(TLV_TYPE_STRING, SERVICES_BASE, API_TYPE)
TLV_TYPE_SVC_DISPLAY = tlv_custom_type(TLV_TYPE_STRING, SERVICES_BASE, API_TYPE + 1)
TLV_TYPE_SVC_STATE = tlv_custom_type(TLV_TYPE_INT, SERVICES_BASE, API_TYPE)
TLV_TYPE_SVC_TYPE = tlv_custom_type(TLV_TYPE_INT, SERVICES_BASE, API_TYPE + 1)
TLV_TYPE_SVC_PID = tlv_custom_type(TLV_TYPE_INT, SERVICES_BASE, API_TYPE + 2)
TLV_TYPE_SVC_GROUP = tlv_custom_type(TLV_TYPE_GROUP, SERVICES_BASE, API_TYPE)

SERVICE_STOPPED = 1
SERVICE_START_PENDING = 2
SERVICE_STOP_PENDING = 3
SERVICE_RUNNING = 4
SERVICE_CONTINUE_PENDING = 5
SERVICE_PAUSE_PENDING = 6
SERVICE_PAUSED = 7

STATE_NAMES = {
    SERVICE_STOPPED: 'Stopped',
    SERVICE_START_PENDING: 'Starting',
    SERVICE_STOP_PENDING: 'Stopping',
    SERVICE_RUNNING: 'Running',
    SERVICE_CONTINUE_PENDING: 'Continuing',
    SERVICE_PAUSE_PENDING: 'Pausing',
    SERVICE_PAUSED: 'Paused',
}


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "gather",
            'Name': "services",
            'Authors': [
                'EntySec - command developer',
            ],
            'Description': "Enumerate Windows services.",
            'MinArgs': 1,
            'Options': [
                (
                    ('-l', '--list'),
                    {
                        'help': "List all services.",
                        'action': 'store_true',
                    }
                ),
                (
                    ('-r', '--running'),
                    {
                        'help': "Show only running services.",
                        'action': 'store_true',
                    }
                ),
                (
                    ('-f', '--filter'),
                    {
                        'help': "Filter services by name substring.",
                        'metavar': 'NAME',
                    }
                ),
            ]
        })

    def run(self, args):
        result = self.session.send_command(tag=SERVICES_LIST)

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to enumerate services!")
            return

        headers = ('Name', 'Display Name', 'State', 'PID')
        data = []

        while True:
            entry = result.get_tlv(TLV_TYPE_SVC_GROUP)
            if entry is None:
                break

            name_raw = entry.get_raw(TLV_TYPE_SVC_NAME)
            display_raw = entry.get_raw(TLV_TYPE_SVC_DISPLAY)
            name = name_raw.decode('utf-8', errors='replace') if name_raw else ''
            display = display_raw.decode('utf-8', errors='replace') if display_raw else ''
            state = entry.get_int(TLV_TYPE_SVC_STATE) or 0
            pid = entry.get_int(TLV_TYPE_SVC_PID) or 0

            if args.running and state != SERVICE_RUNNING:
                continue

            if args.filter and args.filter.lower() not in name.lower():
                continue

            state_name = STATE_NAMES.get(state, f'Unknown({state})')
            pid_str = str(pid) if pid > 0 else '-'

            data.append((name, display, state_name, pid_str))

        if not data:
            self.print_warning("No matching services found.")
            return

        self.print_table("Services", headers, *data)
