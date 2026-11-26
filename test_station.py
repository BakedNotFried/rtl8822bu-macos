from contextlib import ExitStack
import os
import socket
import threading
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import station


class StationTest(unittest.TestCase):
    def test_setup_reply(self):
        read, write = os.pipe()
        try:
            os.write(write, b'READY\nERROR adapter-unavailable\n')
            self.assertEqual(station.read_line(read, 1), b'READY')
            with self.assertRaisesRegex(RuntimeError, 'adapter-unavailable'):
                station.read_line(read, 1)
        finally:
            os.close(write)
            os.close(read)

    def test_simultaneous_framed_traffic(self):
        with ExitStack() as pool:
            def pair():
                a, b = socket.socketpair()
                return pool.enter_context(a), pool.enter_context(b)
            local, helper = pair()
            output, radio_out = pair()
            input_, radio_in = pair()
            for sock in [helper, radio_out, radio_in]:
                sock.settimeout(3)
            process = SimpleNamespace(stdout=output, stdin=input_)
            errors = []
            def run():
                try:
                    station.relay(process, local, 'feth0')
                except RuntimeError as exc:
                    errors.append(str(exc))
            with patch('station.subprocess.run', return_value=SimpleNamespace(stdout='', returncode=1)):
                actor = threading.Thread(target=run, daemon=True)
                actor.start()
                frame = bytes.fromhex('000e') + bytes(range(14))
                helper.sendall(frame[:1])
                radio_out.sendall(frame)
                helper.sendall(frame[1:])
                self.assertEqual(station.read_exact(radio_in, len(frame)), frame)
                self.assertEqual(station.read_exact(helper, len(frame)), frame)
                radio_out.shutdown(socket.SHUT_WR)
                actor.join(3)
            self.assertEqual(errors, ['Station link closed.'])


if __name__ == '__main__':
    unittest.main()
