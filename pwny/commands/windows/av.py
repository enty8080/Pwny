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
TLV_TYPE_SVC_PID = tlv_custom_type(TLV_TYPE_INT, SERVICES_BASE, API_TYPE + 2)
TLV_TYPE_SVC_GROUP = tlv_custom_type(TLV_TYPE_GROUP, SERVICES_BASE, API_TYPE)

PROCESS_BASE = 2
PROCESS_LIST = tlv_custom_tag(API_CALL_STATIC, PROCESS_BASE, API_CALL)
PROCESS_TYPE_PID_NAME = tlv_custom_type(TLV_TYPE_STRING, PROCESS_BASE, API_TYPE)

SERVICE_RUNNING = 4

# Known AV/EDR vendor signatures
AV_SIGNATURES = {
    'Windows Defender': [
        'windefend', 'msmpeng', 'mssense', 'securityhealthservice',
        'sense', 'WdNisSvc',
    ],
    'Norton': [
        'norton', 'symantec', 'sepmaster', 'smc', 'ccsvchst', 'nswscsvc',
    ],
    'McAfee': [
        'mcafee', 'masvc', 'mfemms', 'macmnsvc', 'mfefire',
    ],
    'Kaspersky': [
        'kaspersky', 'avp', 'kavfs', 'klnagent',
    ],
    'Bitdefender': [
        'bitdefender', 'bdagent', 'vsserv', 'updatesrv',
    ],
    'ESET': [
        'eset', 'ekrn', 'egui',
    ],
    'Avast/AVG': [
        'avast', 'avg', 'avastsvc', 'avgsvc', 'avgnt',
    ],
    'Trend Micro': [
        'trendmicro', 'ntrtscan', 'tmccsf', 'tmlisten', 'tmsysev',
    ],
    'Sophos': [
        'sophos', 'savservice', 'sophossps',
    ],
    'CrowdStrike': [
        'crowdstrike', 'csfalconservice', 'csagent', 'csfalcon',
    ],
    'SentinelOne': [
        'sentinelagent', 'sentinelone', 'sentinelhelper',
    ],
    'Carbon Black': [
        'carbonblack', 'cbdefense', 'cbstream', 'cb.exe',
    ],
    'Cylance': [
        'cylance', 'cyoptics', 'cyprotect',
    ],
    'Malwarebytes': [
        'malwarebytes', 'mbamservice', 'mbam',
    ],
    'Webroot': [
        'webroot', 'wrsa', 'wrsvc',
    ],
    'F-Secure': [
        'fsecure', 'fsgk32', 'fsav32', 'fsdfwd',
    ],
    'Panda': [
        'panda', 'pavsrv', 'psanhost',
    ],
    'Comodo': [
        'comodo', 'cmdagent', 'cavwp',
    ],
}


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "gather",
            'Name': "av",
            'Authors': [
                'EntySec - command developer',
            ],
            'Description': "Detect installed antivirus and EDR products.",
        })

    def run(self, _):
        result = self.session.send_command(tag=SERVICES_LIST)

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to enumerate services!")
            return

        services = []
        while True:
            entry = result.get_tlv(TLV_TYPE_SVC_GROUP)
            if entry is None:
                break

            name = entry.get_string(TLV_TYPE_SVC_NAME) or ''
            display = entry.get_string(TLV_TYPE_SVC_DISPLAY) or ''
            state = entry.get_int(TLV_TYPE_SVC_STATE) or 0
            pid = entry.get_int(TLV_TYPE_SVC_PID) or 0

            services.append((name, display, state, pid))

        detected = {}

        for svc_name, svc_display, svc_state, svc_pid in services:
            combined = (svc_name + ' ' + svc_display).lower()

            for vendor, signatures in AV_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in combined:
                        if vendor not in detected:
                            detected[vendor] = []
                        state_str = 'Running' if svc_state == SERVICE_RUNNING else 'Stopped'
                        detected[vendor].append((svc_name, svc_display, state_str))
                        break

        if not detected:
            self.print_warning("No known AV/EDR products detected.")
            return

        for vendor, entries in detected.items():
            self.print_information(f"%bold{vendor}%end")
            for svc_name, svc_display, state_str in entries:
                status_color = '%green' if state_str == 'Running' else '%red'
                self.print_information(
                    f"  {svc_name} ({svc_display}) [{status_color}{state_str}%end]"
                )
