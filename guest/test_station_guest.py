"""Offline tests for the guest protocol. No wireless interface is accessed."""
import os
import runpy
import unittest
from pathlib import Path


guest = runpy.run_path(str(Path(__file__).with_name("station-guest")))
MAC = bytes.fromhex("020000000001")
AP = bytes.fromhex("020000000002")


class GuestTests(unittest.TestCase):
    def read_request(self, line):
        reader, writer = os.pipe()
        try:
            os.write(writer, line)
            os.close(writer)
            return guest["join_request"](reader)
        finally:
            os.close(reader)

    def test_join_request(self):
        name, key = b"41420043", b"01" * 32
        ssid, psk = self.read_request(b"JOIN " + name + b" " + key + b"\n")
        self.assertEqual((ssid, psk), (name,key))
        cfg = guest["wpa_config"](ssid,psk,"/run/station-test")
        self.assertIn(b"\nssid=" + name + b"\n",cfg)
        self.assertIn(b"\npairwise=CCMP\ngroup=CCMP\n",cfg)
        self.assertNotIn(b" 5180",cfg)
        for line in (b"JOIN a " + key, b"JOIN 00 " + key[:-1], b"x"*140):
            with self.assertRaises(guest["SessionError"]):
                self.read_request(line + b"\n")

    def test_peer_network(self):
        mac = "02:00:00:00:00:01"
        current = {b"wpa_state":b"COMPLETED",b"id":b"0",b"key_mgmt":b"WPA2-PSK",
                   b"pairwise_cipher":b"CCMP",b"group_cipher":b"CCMP",b"freq":b"2417",
                   b"address":mac.encode(),b"bssid":b"02:00:00:00:00:02"}
        verify = guest["verify_association"]
        self.assertTrue(verify(current,mac))
        for field, value in ((b"freq",b"5180"),(b"group_cipher",b"TKIP"),
                             (b"id",b"1"),(b"wpa_state",b"DISCONNECTED"),
                             (b"key_mgmt",b"SAE"),(b"address",b"02:00:00:00:00:33")):
            self.assertFalse(verify({**current,field:value},mac))

    def test_protocol_frames(self):
        arp = bytes.fromhex("0001080006040001") + MAC + bytes(14)
        frame = b"\xff"*6 + MAC + b"\x08\x06" + arp
        accept = guest["valid_frame"]
        self.assertTrue(accept(frame,MAC,True))
        self.assertFalse(accept(frame,AP,True))
        self.assertTrue(accept(frame,MAC,False))
        self.assertFalse(accept(AP + frame[6:],MAC,False))
        self.assertFalse(accept(frame[:12] + b"\x88\x8e" + frame[14:],MAC,True))
        self.assertFalse(accept(frame[:-1],MAC,True))
        self.assertFalse(accept(bytes(1515),MAC,True))
        ip = AP + MAC + b"\x08\x00" + bytes.fromhex("45000014") + bytes(16)
        self.assertTrue(accept(ip,MAC,True))
        self.assertFalse(accept(ip[:-1],MAC,True))

        records = [len(f).to_bytes(2,"big") + f for f in (frame, ip)]
        pending = bytearray(records[0] + records[1][:7])
        self.assertEqual(list(guest["host_frames"](pending)),[frame])
        self.assertEqual(bytes(pending),records[1][:7])
        pending.extend(records[1][7:])
        self.assertEqual(list(guest["host_frames"](pending)),[ip])
        self.assertFalse(pending)
        with self.assertRaises(guest["SessionError"]):
            list(guest["host_frames"](bytearray(b"\xff\xff")))


if __name__ == "__main__":
    unittest.main()
