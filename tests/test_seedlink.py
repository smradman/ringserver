"""SeedLink v3/v4 protocol tests for ringserver."""

import json
import socket
import unittest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ringtest

BHZ_STREAMID = "FDSN:XX_TEST_00_B_H_Z/MSEED"
BHN_STREAMID = "FDSN:XX_TEST_00_B_H_N/MSEED"


class TestSeedLink(unittest.TestCase):
    """SeedLink v3/v4 protocol conformance tests against a live ringserver."""

    @classmethod
    def setUpClass(cls):
        cls.server = ringtest.Server(protocols="DataLink SeedLink").start()
        # Deliberately triggered client errors (bad SELECT pattern) are
        # logged by the server; don't fail on them.
        cls.server.ignore_log_patterns.append(
            r"Error, select pattern contains illegal characters")

        dl = ringtest.DataLinkConn(cls.server.port)

        # BHZ backlog, with one invalid (non-miniSEED) record spliced into
        # the middle to verify the payload-validity filter mid-stream.
        # cls.bhz_records is in local-sequence order (0..7) and holds
        # (ring_pktid, record_bytes) tuples for byte-exact comparison.
        cls.bhz_records = []
        for i in range(3):
            record = ringtest.make_ms2(chan="BHZ", seq=i)
            pktid = dl.write(BHZ_STREAMID, record)
            cls.bhz_records.append((pktid, record))

        cls.junk_pktid = dl.write(BHZ_STREAMID, b"X" * 512)

        for i in range(3, 8):
            record = ringtest.make_ms2(chan="BHZ", seq=i)
            pktid = dl.write(BHZ_STREAMID, record)
            cls.bhz_records.append((pktid, record))

        # BHN backlog, excluded by the "00BHZ" / "00_B_H_Z" selectors used
        # throughout these tests.
        cls.bhn_records = []
        for i in range(4):
            record = ringtest.make_ms2(chan="BHN", seq=i)
            pktid = dl.write(BHN_STREAMID, record)
            cls.bhn_records.append((pktid, record))

        dl.close()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _slconn(self, **kwargs):
        """Open a SeedLinkConn to the shared server, closed on test end."""
        conn = ringtest.SeedLinkConn(self.server.port, **kwargs)
        self.addCleanup(conn.close)
        return conn

    # -- negotiation ------------------------------------------------------

    def test_hello(self):
        conn = self._slconn()
        id_line, desc_line = conn.hello()
        self.assertTrue(id_line.startswith("SeedLink v4.0 (RingServer/"), id_line)
        self.assertIn("SLPROTO:4.0 SLPROTO:3.1", id_line)
        self.assertTrue(desc_line)

    def test_v3_unknown_command_is_bare_error(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("BOGUS"), "ERROR")

    def test_v3_bad_select_is_bare_error(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SELECT ((("), "ERROR")

    def test_v4_unknown_command_reports_unsupported(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertTrue(conn.cmd("BOGUS").startswith("ERROR UNSUPPORTED"))

    def test_bye_closes_connection(self):
        conn = self._slconn()
        conn.sendline("BYE")
        conn.sock.settimeout(3)
        self.assertEqual(conn.sock.recv(16), b"")

    # -- v3 streaming -------------------------------------------------------

    def test_v3_stream_backlog_select_bhz(self):
        # Resume starting at the second written BHZ record; the first
        # record's packet ID (1) can't be used to resume since sequence
        # numbers resume from lastpacket+1 and 1-1=0 does not exist.
        start_pktid, expected = self.bhz_records[1][0], self.bhz_records[1:]

        conn = self._slconn()
        self.assertEqual(conn.cmd("STATION TEST XX"), "OK")
        self.assertEqual(conn.cmd("SELECT 00BHZ"), "OK")
        self.assertEqual(conn.cmd(f"DATA {start_pktid:06x}"), "OK")
        conn.sendline("END")

        prev_seq = None
        for pktid, record in expected:
            frame = conn.recv_v3()
            self.assertEqual(frame["kind"], "data")
            self.assertEqual(frame["seq"], pktid & 0xFFFFFF)
            self.assertEqual(frame["record"], record)
            if prev_seq is not None:
                self.assertGreater(frame["seq"], prev_seq)
            prev_seq = frame["seq"]

        # Nothing else follows: BHN and the junk record are excluded.
        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v3()

    def test_v3_resume_data_seq_starts_at_requested_sequence(self):
        # DATA <seq> resumes AT the requested sequence (inclusive), not
        # after it: requesting a mid-backlog packet ID yields that same
        # record first, followed only by later ones.
        start_pktid, expected = self.bhz_records[4][0], self.bhz_records[4:]

        conn = self._slconn()
        self.assertEqual(conn.cmd("STATION TEST XX"), "OK")
        self.assertEqual(conn.cmd("SELECT 00BHZ"), "OK")
        self.assertEqual(conn.cmd(f"DATA {start_pktid:06x}"), "OK")
        conn.sendline("END")

        first = conn.recv_v3()
        self.assertEqual(first["seq"], start_pktid & 0xFFFFFF)
        self.assertEqual(first["record"], expected[0][1])

        for pktid, record in expected[1:]:
            frame = conn.recv_v3()
            self.assertEqual(frame["seq"], pktid & 0xFFFFFF)
            self.assertEqual(frame["record"], record)

        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v3()

    def test_v3_fetch_dialup_ends_with_literal_end(self):
        start_pktid, expected = self.bhz_records[1][0], self.bhz_records[1:]

        conn = self._slconn()
        self.assertEqual(conn.cmd("STATION TEST XX"), "OK")
        self.assertEqual(conn.cmd("SELECT 00BHZ"), "OK")
        self.assertEqual(conn.cmd(f"FETCH {start_pktid:06x}"), "OK")
        conn.sendline("END")

        for pktid, record in expected:
            frame = conn.recv_v3()
            self.assertEqual(frame["kind"], "data")
            self.assertEqual(frame["record"], record)

        # Dial-up mode signals end-of-backlog with a literal "END" and
        # disconnects.
        self.assertEqual(conn.recv_v3()["kind"], "end")
        conn.sock.settimeout(3)
        self.assertEqual(conn.sock.recv(16), b"")

    # -- v3 INFO ------------------------------------------------------------

    def test_v3_info_id_and_capabilities(self):
        conn = self._slconn()

        conn.sendline("INFO ID")
        root = conn.collect_info_v3()
        self.assertEqual(root.tag, "seedlink")
        self.assertTrue(root.attrib["software"].startswith("SeedLink v4.0 (RingServer/"))
        self.assertTrue(root.attrib["organization"])

        conn.sendline("INFO CAPABILITIES")
        root = conn.collect_info_v3()
        names = {cap.attrib["name"] for cap in root.findall("capability")}
        self.assertIn("dialup", names)
        self.assertIn("info:streams", names)

    def test_v3_info_streams(self):
        conn = self._slconn()
        conn.sendline("INFO STREAMS")
        root = conn.collect_info_v3()

        stations = {st.attrib["name"]: st for st in root.findall("station")}
        self.assertIn("TEST", stations)
        self.assertEqual(stations["TEST"].attrib["network"], "XX")

        seednames = {s.attrib["seedname"] for s in stations["TEST"].findall("stream")}
        self.assertEqual(seednames, {"BHZ", "BHN"})

    def test_v3_info_connections(self):
        conn = self._slconn()
        conn.sendline("INFO CONNECTIONS")
        root = conn.collect_info_v3()

        stations = root.findall("station")
        self.assertTrue(any(st.attrib["name"] == "CLIENT" for st in stations))
        client = next(st for st in stations if st.attrib["name"] == "CLIENT")
        connection = client.find("connection")
        self.assertIsNotNone(connection)
        self.assertEqual(connection.attrib["host"], "127.0.0.1")

    # -- v4 streaming -------------------------------------------------------

    def test_v4_stream_backlog_select(self):
        start_pktid, expected = self.bhz_records[1][0], self.bhz_records[1:]

        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("USERAGENT test/1.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z"), "OK")
        self.assertEqual(conn.cmd(f"DATA {start_pktid}"), "OK")
        conn.sendline("END")

        prev_pktid = None
        for pktid, record in expected:
            frame = conn.recv_v4()
            self.assertEqual(frame["kind"], "data")
            self.assertEqual(frame["format"], "2")
            self.assertEqual(frame["subformat"], "D")
            self.assertEqual(frame["staid"], "XX_TEST")
            self.assertEqual(frame["pktid"], pktid)
            self.assertEqual(frame["payload"], record)
            if prev_pktid is not None:
                self.assertGreater(frame["pktid"], prev_pktid)
            prev_pktid = frame["pktid"]

        # Nothing else follows: BHN and the junk record are excluded.
        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v4()

    # -- v4 INFO --------------------------------------------------------------

    def test_v4_info_id(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        conn.sendline("INFO ID")
        frame = conn.recv_v4()

        self.assertEqual(frame["kind"], "info")
        self.assertEqual(frame["format"], "J")
        doc = json.loads(frame["payload"].decode("utf-8"))
        self.assertTrue(doc["software"].startswith("SeedLink v4.0 (RingServer/"))
        self.assertIn("organization", doc)
        self.assertIn("server_start", doc)

    def test_v4_info_streams(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        conn.sendline("INFO STREAMS")
        frame = conn.recv_v4()

        doc = json.loads(frame["payload"].decode("utf-8"))
        stations = {s["id"]: s for s in doc["station"]}
        self.assertIn("XX_TEST", stations)
        stream_ids = {s["id"] for s in stations["XX_TEST"]["stream"]}
        self.assertEqual(stream_ids, {"00_B_H_Z", "00_B_H_N"})


if __name__ == "__main__":
    unittest.main()
