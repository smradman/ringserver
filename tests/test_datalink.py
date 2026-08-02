"""DataLink protocol tests for ringserver."""

import re
import socket
import time
import unittest
import uuid

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ringtest

ID_RE = re.compile(
    r"^ID DataLink v(\d+\.\d+) \(RingServer/[\d.]+\) :: "
    r"DLPROTO:(\d+\.\d+) PACKETSIZE:(\d+) WRITE$")


def unique(label):
    """Return a short, collision-free stream ID prefix."""
    return f"{label}{uuid.uuid4().hex[:8].upper()}"


class TestDataLink(unittest.TestCase):
    """DataLink protocol conformance tests against a live ringserver."""

    @classmethod
    def setUpClass(cls):
        cls.server = ringtest.Server(protocols="DataLink").start()
        # Deliberately triggered client errors (bad stream ID length, bad
        # READ argument) are logged by the server; don't fail on them.
        cls.server.ignore_log_patterns.append(r"stream ID too long")
        cls.server.ignore_log_patterns.append(r"Error parsing READ parameters")

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _conn(self, **kwargs):
        """Open a DataLinkConn to the shared server, closed on test end."""
        conn = ringtest.DataLinkConn(self.server.port, **kwargs)
        self.addCleanup(conn.close)
        return conn

    # -- handshake ------------------------------------------------------

    def test_id_handshake(self):
        conn = self._conn()
        match = ID_RE.match(conn.id_response)
        self.assertIsNotNone(match, conn.id_response)
        self.assertEqual(match.group(3), "512")

    # -- write / read -----------------------------------------------------

    def test_write_ack_pktids_increase(self):
        conn = self._conn()
        streamid = f"{unique('WR')}/RAW"
        pid1 = conn.write(streamid, ringtest.make_ms2())
        pid2 = conn.write(streamid, ringtest.make_ms2())
        self.assertGreater(pid2, pid1)

    def test_write_noack_is_stored(self):
        conn = self._conn()
        streamid = f"{unique('NA')}/RAW"
        payload = ringtest.make_ms2()

        result = conn.write(streamid, payload, flags="N")
        self.assertIsNone(result)

        acked_pid = conn.write(streamid, ringtest.make_ms2(), flags="A")
        header, data = conn.read(acked_pid - 1)
        self.assertTrue(header.startswith("PACKET"), header)
        self.assertEqual(data, payload)

    def test_read_missing_and_invalid_id(self):
        conn = self._conn()

        header, payload = conn.read(2**63 - 1)
        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"not found", payload)

        conn.send("READ notanumber")
        header, _ = conn.recv()
        self.assertTrue(header.startswith("ERROR"), header)

    def test_byte_exact_binary_payload(self):
        conn = self._conn()
        streamid = f"{unique('BIN')}/RAW"
        payload = bytes(range(256)) + b"\x00\xff" * 10

        pid = conn.write(streamid, payload)
        header, data = conn.read(pid)
        self.assertTrue(header.startswith("PACKET"), header)
        self.assertEqual(data, payload)

    # -- positioning --------------------------------------------------------

    def test_position_set_explicit_resumes_after(self):
        conn = self._conn()
        streamid = f"{unique('POS')}/RAW"
        pid_a = conn.write(streamid, ringtest.make_ms2())
        pid_b = conn.write(streamid, ringtest.make_ms2())

        reader = self._conn()
        header = reader.position_set(str(pid_a))
        self.assertTrue(header.startswith(f"OK {pid_a} "), header)

        reader.stream()
        header, _ = reader.recv()
        self.assertTrue(header.startswith(f"PACKET {streamid} {pid_b} "), header)
        reader.endstream()

    def test_position_set_latest_matches_last_write(self):
        conn = self._conn()
        streamid = f"{unique('LAT')}/RAW"
        pid = conn.write(streamid, ringtest.make_ms2())

        header = conn.position_set("LATEST")
        self.assertTrue(header.startswith(f"OK {pid} "), header)

    def test_position_after_future_positions_to_latest_and_streams(self):
        conn = self._conn()
        streamid = f"{unique('FUT')}/RAW"
        conn.write(streamid, ringtest.make_ms2())

        future_us = int((time.time() + 3600) * 1_000_000)
        conn.send(f"POSITION AFTER {future_us}")
        header, payload = conn.recv()
        self.assertTrue(header.startswith("OK 0 "), header)
        self.assertIn(b"LATEST", payload)

        conn.stream()
        writer = self._conn()
        pid = writer.write(streamid, ringtest.make_ms2())

        header, _ = conn.recv()
        self.assertTrue(header.startswith(f"PACKET {streamid} {pid} "), header)
        conn.endstream()

    # -- match / reject -------------------------------------------------

    def test_match_reject_filtering_end_to_end(self):
        prefix = unique("MR")
        stream_a = f"{prefix}A/RAW"
        stream_b = f"{prefix}B/RAW"

        writer = self._conn()
        writer.write(stream_a, ringtest.make_ms2())
        pid_b1 = writer.write(stream_b, ringtest.make_ms2())

        reader = self._conn()
        header = reader.match(f"{prefix}A")
        self.assertTrue(header.startswith("OK 1 "), header)

        # Position past everything written so far; only genuinely new
        # matching packets should be delivered once streaming starts.
        reader.position_set(str(pid_b1))
        reader.stream()

        pid_a2 = writer.write(stream_a, ringtest.make_ms2())
        writer.write(stream_b, ringtest.make_ms2())

        header, _ = reader.recv()
        self.assertTrue(header.startswith(f"PACKET {stream_a} {pid_a2} "), header)
        reader.endstream()

    def test_match_bare_clears_filter(self):
        conn = self._conn()
        before = int(conn.match().split()[1])

        conn.write(f"{unique('CLRA')}/RAW", ringtest.make_ms2())
        conn.write(f"{unique('CLRB')}/RAW", ringtest.make_ms2())

        after = int(conn.match().split()[1])
        self.assertEqual(after, before + 2)

    # -- stream / endstream -----------------------------------------------

    def test_stream_endstream_returns_to_command_mode(self):
        conn = self._conn()
        conn.stream()
        header = conn.endstream()
        self.assertTrue(header.startswith("ENDSTREAM"), header)

        header, _ = conn.info("STATUS")
        self.assertTrue(header.startswith("INFO STATUS"), header)

    # -- info ------------------------------------------------------------

    def test_info_status(self):
        conn = self._conn()
        header, root = conn.info("STATUS")
        self.assertTrue(header.startswith("INFO STATUS"), header)
        self.assertEqual(root.tag, "DataLink")
        self.assertIsNotNone(root.find("Status"))

    def test_info_streams_contains_written_stream(self):
        conn = self._conn()
        streamid = f"{unique('INF')}/RAW"
        conn.write(streamid, ringtest.make_ms2())

        header, root = conn.info("STREAMS")
        self.assertTrue(header.startswith("INFO STREAMS"), header)
        names = [s.get("Name") for s in root.find("StreamList").findall("Stream")]
        self.assertIn(streamid, names)

    def test_info_connections(self):
        conn = self._conn()
        header, root = conn.info("CONNECTIONS")
        self.assertTrue(header.startswith("INFO CONNECTIONS"), header)
        self.assertIsNotNone(root.find("ConnectionList"))

    # -- error handling ----------------------------------------------------

    def test_oversize_write_rejected(self):
        conn = self._conn()
        streamid = f"{unique('BIG')}/RAW"
        payload = b"x" * 600
        now_us = int(time.time() * 1_000_000)

        conn.send(f"WRITE {streamid} {now_us} {now_us + 1000} A {len(payload)}", payload)
        header, resp = conn.recv()
        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"too large", resp)

    def test_overlong_streamid_rejected(self):
        conn = self._conn()
        streamid = "A" * 70 + "/RAW"
        payload = ringtest.make_ms2()
        now_us = int(time.time() * 1_000_000)

        conn.send(f"WRITE {streamid} {now_us} {now_us + 1000} A {len(payload)}", payload)
        header, resp = conn.recv()
        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"stream ID", resp)

    def test_unrecognized_command(self):
        conn = self._conn()
        conn.send("BOGUS")
        header, resp = conn.recv()
        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"Unrecognized", resp)

    def test_bye_closes_connection(self):
        conn = self._conn()
        conn.send("BYE")
        self.assertEqual(conn.sock.recv(10), b"")

    def test_legacy_streamid_translation(self):
        conn = self._conn()
        pid = conn.write("XX_TEST__BHZ/MSEED", ringtest.make_ms2())

        header, _ = conn.read(pid)
        streamid = header.split()[1]
        self.assertEqual(streamid, "FDSN:XX_TEST__B_H_Z/MSEED")
        self.assertTrue(streamid.startswith("FDSN:XX_TEST"))
        self.assertTrue(streamid.endswith("B_H_Z/MSEED"))

    def test_half_close_write_ack(self):
        conn = self._conn()
        streamid = f"{unique('HC')}/RAW"
        payload = ringtest.make_ms2()
        now_us = int(time.time() * 1_000_000)

        conn.send(f"WRITE {streamid} {now_us} {now_us + 1000} A {len(payload)}", payload)
        conn.sock.shutdown(socket.SHUT_WR)

        header, _ = conn.recv()
        self.assertTrue(header.startswith("OK"), header)


if __name__ == "__main__":
    unittest.main()
