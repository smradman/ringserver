"""SeedLink v3/v4 protocol tests for ringserver."""

import calendar
import json
import socket
import time
import unittest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ringtest

BHZ_STREAMID = "FDSN:XX_TEST_00_B_H_Z/MSEED"
BHN_STREAMID = "FDSN:XX_TEST_00_B_H_N/MSEED"

# Fixed base time for the v4 conformance tests below, giving deterministic
# time-window arithmetic independent of wall-clock time.
T0_US = int(calendar.timegm(time.strptime(
    "2026-07-01T00:00:00Z", "%Y-%m-%dT%H:%M:%SZ"))) * 1_000_000


def iso_us(epoch_us):
    """Format a microsecond epoch timestamp as a SeedLink v4 time string."""
    seconds, micros = divmod(epoch_us, 1_000_000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds)) + ".%06dZ" % micros


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
        # Resuming at the first record's packet ID yields the full backlog.
        start_pktid, expected = self.bhz_records[0][0], self.bhz_records[0:]

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
        start_pktid, expected = self.bhz_records[0][0], self.bhz_records[0:]

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
        start_pktid, expected = self.bhz_records[0][0], self.bhz_records[0:]

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


class TestSeedLinkAllStationResume(unittest.TestCase):
    """SeedLink v3 all-station (classic uni-station) resume semantics.

    All-station mode is entered by skipping STATION entirely: HELLO (if
    sent at all) followed directly by `DATA <seq hex>`.  Unlike the
    per-station STATION/SELECT/DATA/END negotiation, an all-station DATA
    command triggers ring configuration and streaming immediately, with
    no reply and no END required.

    Each test gets its own server since the resume-to-live-edge case
    writes a new record mid-test and needs a known, isolated ring state.
    """

    def setUp(self):
        self.server = ringtest.Server(protocols="DataLink SeedLink").start()
        self.addCleanup(self.server.stop)

        dl = ringtest.DataLinkConn(self.server.port)
        self.bhz_records = []
        for i in range(5):
            record = ringtest.make_ms2(chan="BHZ", seq=i)
            pktid = dl.write(BHZ_STREAMID, record)
            self.bhz_records.append((pktid, record))
        dl.close()

    def _slconn(self, **kwargs):
        """Open a SeedLinkConn to this test's server, closed on test end."""
        conn = ringtest.SeedLinkConn(self.server.port, **kwargs)
        self.addCleanup(conn.close)
        return conn

    def test_all_station_data_resumes_mid_backlog_inclusive(self):
        # All-station DATA <seq> starts streaming immediately: no reply,
        # no END, resuming AT the requested sequence (inclusive).
        start_pktid, expected = self.bhz_records[2][0], self.bhz_records[2:]

        conn = self._slconn()
        conn.sendline(f"DATA {start_pktid:06x}")

        prev_seq = None
        for pktid, record in expected:
            frame = conn.recv_v3()
            self.assertEqual(frame["kind"], "data")
            self.assertEqual(frame["seq"], pktid & 0xFFFFFF)
            self.assertEqual(frame["record"], record)
            if prev_seq is not None:
                self.assertGreater(frame["seq"], prev_seq)
            prev_seq = frame["seq"]

        # Nothing else follows.
        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v3()

    def test_all_station_data_resumes_at_earliest_inclusive(self):
        # Resuming at the earliest packet ID must still deliver the whole
        # backlog starting at that record, inclusive.
        start_pktid, expected = self.bhz_records[0][0], self.bhz_records[0:]

        conn = self._slconn()
        conn.sendline(f"DATA {start_pktid:06x}")

        for pktid, record in expected:
            frame = conn.recv_v3()
            self.assertEqual(frame["kind"], "data")
            self.assertEqual(frame["seq"], pktid & 0xFFFFFF)
            self.assertEqual(frame["record"], record)

        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v3()

    def test_all_station_data_stale_sequence_resumes_at_live_edge(self):
        # A resume sequence that is not in the ring and is not the next
        # expected packet must not replay the backlog: it resumes at the
        # live edge instead.  Packet IDs start at 1, so 0 is guaranteed
        # to be below the earliest packet ever written.
        conn = self._slconn()
        conn.sendline("DATA 000000")

        # No backlog is delivered for the unvalidated resume point.
        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v3()

        # A record written after connecting is delivered once live.
        dl = ringtest.DataLinkConn(self.server.port)
        self.addCleanup(dl.close)
        newrecord = ringtest.make_ms2(chan="BHZ", seq=99)
        newpktid = dl.write(BHZ_STREAMID, newrecord)

        conn.sock.settimeout(10)
        frame = conn.recv_v3()
        self.assertEqual(frame["kind"], "data")
        self.assertEqual(frame["seq"], newpktid & 0xFFFFFF)
        self.assertEqual(frame["record"], newrecord)


class TestSeedLinkV4DataVariants(unittest.TestCase):
    """SeedLink v4 DATA command variants: ALL, bare, unavailable sequence,
    argument errors, and dial-up (ENDFETCH) framing.

    Each test gets its own server: several tests write additional records
    into the ring mid-test, and each needs a known, isolated starting state
    (mirroring TestSeedLinkAllStationResume).
    """

    def setUp(self):
        self.server = ringtest.Server(protocols="DataLink SeedLink").start()
        self.addCleanup(self.server.stop)
        # Deliberately triggered client argument errors are logged by the
        # server; don't fail on them.
        self.server.ignore_log_patterns.append(
            r"Error parsing sequence number for DATA")
        self.server.ignore_log_patterns.append(r"Error parsing time in DATA")
        self.server.ignore_log_patterns.append(r"Cannot parse time string")

        dl = ringtest.DataLinkConn(self.server.port)
        self.bhz_records = []
        for i in range(5):
            record = ringtest.make_ms2(chan="BHZ", seq=i)
            pktid = dl.write(BHZ_STREAMID, record)
            self.bhz_records.append((pktid, record))
        dl.close()

    def _slconn(self, **kwargs):
        conn = ringtest.SeedLinkConn(self.server.port, **kwargs)
        self.addCleanup(conn.close)
        return conn

    def test_data_all_delivers_from_earliest(self):
        # Per spec, DATA ALL resumes from the earliest packet in the ring.
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z"), "OK")
        self.assertEqual(conn.cmd("DATA ALL"), "OK")
        conn.sendline("END")

        for pktid, record in self.bhz_records:
            frame = conn.recv_v4()
            self.assertEqual(frame["kind"], "data")
            self.assertEqual(frame["pktid"], pktid)
            self.assertEqual(frame["payload"], record)

        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v4()

    def test_bare_data_starts_at_next_available(self):
        # An omitted sequence resumes at the next packet to arrive, not
        # at the start of the backlog.
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z"), "OK")
        self.assertEqual(conn.cmd("DATA"), "OK")
        conn.sendline("END")

        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v4()

        dl = ringtest.DataLinkConn(self.server.port)
        self.addCleanup(dl.close)
        newrecord = ringtest.make_ms2(chan="BHZ", seq=99)
        newpktid = dl.write(BHZ_STREAMID, newrecord)

        conn.sock.settimeout(10)
        frame = conn.recv_v4()
        self.assertEqual(frame["kind"], "data")
        self.assertEqual(frame["pktid"], newpktid)
        self.assertEqual(frame["payload"], newrecord)

    def test_data_unavailable_seq_uses_next_available(self):
        # A sequence that is neither in the ring nor the next expected
        # packet must not replay the backlog.
        unavailable_seq = self.bhz_records[-1][0] + 1000

        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z"), "OK")
        self.assertEqual(conn.cmd(f"DATA {unavailable_seq}"), "OK")
        conn.sendline("END")

        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v4()

        dl = ringtest.DataLinkConn(self.server.port)
        self.addCleanup(dl.close)
        newrecord = ringtest.make_ms2(chan="BHZ", seq=99)
        newpktid = dl.write(BHZ_STREAMID, newrecord)

        conn.sock.settimeout(10)
        frame = conn.recv_v4()
        self.assertEqual(frame["kind"], "data")
        self.assertEqual(frame["pktid"], newpktid)
        self.assertEqual(frame["payload"], newrecord)

    def test_data_invalid_sequence_error(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertTrue(conn.cmd("DATA notanumber").startswith("ERROR ARGUMENTS"))

    def test_data_bad_time_error(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertTrue(conn.cmd("DATA 1 not-a-time").startswith("ERROR ARGUMENTS"))

    def test_data_too_many_arguments_error(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        cmd = ("DATA 1 2026-07-01T00:00:00.000000Z "
               "2026-07-01T00:01:00.000000Z extra")
        self.assertTrue(conn.cmd(cmd).startswith("ERROR ARGUMENTS"))

    def test_endfetch_dialup_sends_backlog_then_end(self):
        start_pktid = self.bhz_records[0][0]

        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z"), "OK")
        self.assertEqual(conn.cmd(f"DATA {start_pktid}"), "OK")
        conn.sendline("ENDFETCH")

        for pktid, record in self.bhz_records:
            frame = conn.recv_v4()
            self.assertEqual(frame["kind"], "data")
            self.assertEqual(frame["pktid"], pktid)
            self.assertEqual(frame["payload"], record)

        # Dial-up mode signals end-of-backlog with a literal END frame and
        # disconnects.
        self.assertEqual(conn.recv_v4()["kind"], "end")
        conn.sock.settimeout(3)
        self.assertEqual(conn.sock.recv(16), b"")


class TestSeedLinkV4TimeWindows(unittest.TestCase):
    """SeedLink v4 time-windowed transfers.

    Five BHZ records with contiguous, non-overlapping 10-second data
    windows: datastart = T0+0,10,20,30,40s and dataend = datastart+10s.
    """

    @classmethod
    def setUpClass(cls):
        cls.server = ringtest.Server(protocols="DataLink SeedLink").start()

        dl = ringtest.DataLinkConn(cls.server.port)
        cls.bhz_records = []
        for i in range(5):
            record = ringtest.make_ms2(chan="BHZ", seq=i)
            datastart = T0_US + i * 10_000_000
            dataend = datastart + 10_000_000
            pktid = dl.write(BHZ_STREAMID, record, datastart=datastart, dataend=dataend)
            cls.bhz_records.append((pktid, record))
        dl.close()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _slconn(self, **kwargs):
        conn = ringtest.SeedLinkConn(self.server.port, **kwargs)
        self.addCleanup(conn.close)
        return conn

    def test_time_positioning_window_then_end(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z"), "OK")
        cmd = f"DATA 0 {iso_us(T0_US + 10_000_000)} {iso_us(T0_US + 35_000_000)}"
        self.assertEqual(conn.cmd(cmd), "OK")
        conn.sendline("END")

        expected = self.bhz_records[1:4]
        for pktid, record in expected:
            frame = conn.recv_v4()
            self.assertEqual(frame["kind"], "data")
            self.assertEqual(frame["pktid"], pktid)
            self.assertEqual(frame["payload"], record)

        self.assertEqual(conn.recv_v4()["kind"], "end")
        conn.sock.settimeout(3)
        self.assertEqual(conn.sock.recv(16), b"")

    def test_data_seq_with_end_time_stops_at_window_end(self):
        start_pktid = self.bhz_records[0][0]

        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z"), "OK")
        cmd = f"DATA {start_pktid} {iso_us(T0_US)} {iso_us(T0_US + 25_000_000)}"
        self.assertEqual(conn.cmd(cmd), "OK")
        conn.sendline("END")

        expected = self.bhz_records[0:3]
        for pktid, record in expected:
            frame = conn.recv_v4()
            self.assertEqual(frame["kind"], "data")
            self.assertEqual(frame["pktid"], pktid)
            self.assertEqual(frame["payload"], record)

        self.assertEqual(conn.recv_v4()["kind"], "end")
        conn.sock.settimeout(3)
        self.assertEqual(conn.sock.recv(16), b"")

    def test_data_all_with_window_filters_pre_window_packets(self):
        # Per spec, only packets whose data end time is after the window
        # start time are delivered: record 0 (dataend == start) is excluded.
        # PREDICTED FAIL: the implementation is expected to deliver
        # pre-window packets when a packet-ID start position exists.
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z"), "OK")
        cmd = f"DATA ALL {iso_us(T0_US + 15_000_000)} {iso_us(T0_US + 35_000_000)}"
        self.assertEqual(conn.cmd(cmd), "OK")
        conn.sendline("END")

        expected = self.bhz_records[1:4]
        for pktid, record in expected:
            frame = conn.recv_v4()
            self.assertEqual(frame["kind"], "data")
            self.assertEqual(frame["pktid"], pktid)
            self.assertEqual(frame["payload"], record)

        self.assertEqual(conn.recv_v4()["kind"], "end")
        conn.sock.settimeout(3)
        self.assertEqual(conn.sock.recv(16), b"")


class TestSeedLinkV4MultiStation(unittest.TestCase):
    """SeedLink v4 multi-station requests: per-station STATION/SELECT/DATA
    blocks, station wildcards, and resume across a reconnect.

    Backlogs for XX_TEST and XX_OTHR are interleaved in the ring: 3 BHZ
    records each, followed by 1 BHN record each.
    """

    @classmethod
    def setUpClass(cls):
        cls.server = ringtest.Server(protocols="DataLink SeedLink").start()
        # A test connection left idle (no data ever matched) and closed at
        # its read timeout can surface as a reset on the server side;
        # don't fail the run on that expected side effect.
        cls.server.ignore_log_patterns.append(
            r"Error receiving data from client: Connection reset by peer")

        dl = ringtest.DataLinkConn(cls.server.port)
        cls.test_bhz = []
        cls.othr_bhz = []
        for i in range(3):
            test_record = ringtest.make_ms2(sta="TEST", chan="BHZ", seq=i)
            test_pktid = dl.write("FDSN:XX_TEST_00_B_H_Z/MSEED", test_record)
            cls.test_bhz.append((test_pktid, test_record))

            othr_record = ringtest.make_ms2(sta="OTHR", chan="BHZ", seq=i)
            othr_pktid = dl.write("FDSN:XX_OTHR_00_B_H_Z/MSEED", othr_record)
            cls.othr_bhz.append((othr_pktid, othr_record))

        cls.test_bhn_record = ringtest.make_ms2(sta="TEST", chan="BHN", seq=0)
        cls.test_bhn_pktid = dl.write("FDSN:XX_TEST_00_B_H_N/MSEED", cls.test_bhn_record)
        cls.othr_bhn_record = ringtest.make_ms2(sta="OTHR", chan="BHN", seq=0)
        cls.othr_bhn_pktid = dl.write("FDSN:XX_OTHR_00_B_H_N/MSEED", cls.othr_bhn_record)
        dl.close()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _slconn(self, **kwargs):
        conn = ringtest.SeedLinkConn(self.server.port, **kwargs)
        self.addCleanup(conn.close)
        return conn

    def test_two_stations_receive_both_backlogs(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z"), "OK")
        self.assertEqual(conn.cmd("DATA ALL"), "OK")
        self.assertEqual(conn.cmd("STATION XX_OTHR"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z"), "OK")
        self.assertEqual(conn.cmd("DATA ALL"), "OK")
        conn.sendline("END")

        received = []
        for _ in range(6):
            frame = conn.recv_v4()
            self.assertEqual(frame["kind"], "data")
            received.append((frame["staid"], frame["pktid"]))

        expected = ({("XX_TEST", pktid) for pktid, _ in self.test_bhz} |
                    {("XX_OTHR", pktid) for pktid, _ in self.othr_bhz})
        self.assertEqual(set(received), expected)

        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v4()

    def test_station_wildcard_matches_multiple(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_*"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z"), "OK")
        self.assertEqual(conn.cmd("DATA ALL"), "OK")
        conn.sendline("END")

        received = []
        for _ in range(6):
            frame = conn.recv_v4()
            self.assertEqual(frame["kind"], "data")
            received.append((frame["staid"], frame["pktid"]))

        expected = ({("XX_TEST", pktid) for pktid, _ in self.test_bhz} |
                    {("XX_OTHR", pktid) for pktid, _ in self.othr_bhz})
        self.assertEqual(set(received), expected)

        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v4()

    def test_multistation_resume_after_disconnect(self):
        # Stations do not have independent sequences: packet IDs are a
        # single global series, so a client that disconnects mid-stream
        # holds per-station resume points sharing one global cutoff.  On
        # reconnect the server resumes from the newest validated point,
        # continuing the stream with no gaps and no duplicates.
        global_order = sorted(
            [("XX_TEST", pktid, record) for pktid, record in self.test_bhz] +
            [("XX_OTHR", pktid, record) for pktid, record in self.othr_bhz],
            key=lambda entry: entry[1])

        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z"), "OK")
        self.assertEqual(conn.cmd("DATA ALL"), "OK")
        self.assertEqual(conn.cmd("STATION XX_OTHR"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z"), "OK")
        self.assertEqual(conn.cmd("DATA ALL"), "OK")
        conn.sendline("END")

        # Receive the first half of the backlog, tracking per-station
        # positions as a client state file would.
        last_received = {}
        for staid, pktid, _record in global_order[:3]:
            frame = conn.recv_v4()
            self.assertEqual(frame["kind"], "data")
            self.assertEqual(frame["staid"], staid)
            self.assertEqual(frame["pktid"], pktid)
            last_received[staid] = pktid
        conn.close()

        # Reconnect and resume each station at its next sequence.
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z"), "OK")
        self.assertEqual(conn.cmd(f"DATA {last_received['XX_TEST'] + 1}"), "OK")
        self.assertEqual(conn.cmd("STATION XX_OTHR"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z"), "OK")
        self.assertEqual(conn.cmd(f"DATA {last_received['XX_OTHR'] + 1}"), "OK")
        conn.sendline("END")

        # The remainder arrives exactly once and in order.
        for staid, pktid, record in global_order[3:]:
            frame = conn.recv_v4()
            self.assertEqual(frame["kind"], "data")
            self.assertEqual(frame["staid"], staid)
            self.assertEqual(frame["pktid"], pktid)
            self.assertEqual(frame["payload"], record)

        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v4()

    def test_station_limit_reports_error_limit(self):
        # SLMAXSTATIONS is 10000; requesting one more must report ERROR LIMIT.
        self.server.ignore_log_patterns.append(r"Station limit of \d+ reached")

        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")

        total = 10001
        chunk = 500
        replies = []
        sent = 0
        while sent < total:
            n = min(chunk, total - sent)
            for i in range(sent, sent + n):
                conn.sendline(f"STATION XX_S{i}")
            for _ in range(n):
                replies.append(conn.recvline())
            sent += n

        self.assertEqual(len(replies), total)
        for reply in replies[:10000]:
            self.assertEqual(reply, "OK")
        self.assertTrue(replies[10000].startswith("ERROR LIMIT"))


class TestSeedLinkV4Select(unittest.TestCase):
    """SeedLink v4 SELECT command: negation, multiple patterns, atomicity,
    filter precedence, global (station-less) selection, and the label
    extension.

    XX_TEST backlog: one BHZ and one BHN record on /MSEED, plus one record
    on the labeled stream FDSN:XX_TEST_00_B_H_E/MSEED/RAW.
    """

    @classmethod
    def setUpClass(cls):
        cls.server = ringtest.Server(protocols="DataLink SeedLink").start()
        cls.server.ignore_log_patterns.append(
            r"Error, select pattern contains illegal characters")
        # A test connection left idle (no data ever matched) and closed at
        # its read timeout can surface as a reset on the server side;
        # don't fail the run on that expected side effect.
        cls.server.ignore_log_patterns.append(
            r"Error receiving data from client: Connection reset by peer")

        dl = ringtest.DataLinkConn(cls.server.port)
        cls.bhz_record = ringtest.make_ms2(chan="BHZ", seq=0)
        cls.bhz_pktid = dl.write(BHZ_STREAMID, cls.bhz_record)
        cls.bhn_record = ringtest.make_ms2(chan="BHN", seq=0)
        cls.bhn_pktid = dl.write(BHN_STREAMID, cls.bhn_record)
        cls.bhe_record = ringtest.make_ms2(chan="BHE", seq=0)
        cls.bhe_pktid = dl.write("FDSN:XX_TEST_00_B_H_E/MSEED/RAW", cls.bhe_record)
        dl.close()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _slconn(self, **kwargs):
        conn = ringtest.SeedLinkConn(self.server.port, **kwargs)
        self.addCleanup(conn.close)
        return conn

    def test_select_negation(self):
        # Selected iff any non-negated pattern matches AND no negated
        # pattern matches.
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT *_B_H_?"), "OK")
        self.assertEqual(conn.cmd("SELECT !00_B_H_N"), "OK")
        self.assertEqual(conn.cmd("DATA ALL"), "OK")
        conn.sendline("END")

        frame = conn.recv_v4()
        self.assertEqual(frame["kind"], "data")
        self.assertEqual(frame["pktid"], self.bhz_pktid)
        self.assertEqual(frame["payload"], self.bhz_record)

        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v4()

    def test_select_multiple_patterns_single_command(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z !00_B_H_N"), "OK")
        self.assertEqual(conn.cmd(f"DATA {self.bhz_pktid}"), "OK")
        conn.sendline("END")

        frame = conn.recv_v4()
        self.assertEqual(frame["kind"], "data")
        self.assertEqual(frame["pktid"], self.bhz_pktid)
        self.assertEqual(frame["payload"], self.bhz_record)

        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v4()

    def test_select_atomic_on_pattern_error(self):
        # A SELECT command with an invalid pattern must not partially
        # apply: the valid pattern in the same command is discarded too.
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertTrue(conn.cmd("SELECT 00_B_H_Z (((").startswith("ERROR"))
        self.assertEqual(conn.cmd("DATA ALL"), "OK")
        conn.sendline("END")

        received = set()
        for _ in range(2):
            frame = conn.recv_v4()
            self.assertEqual(frame["kind"], "data")
            received.add(frame["pktid"])
        self.assertEqual(received, {self.bhz_pktid, self.bhn_pktid})

        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v4()

    def test_select_first_matching_filter_wins(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z:3 *:native"), "OK")
        start_pktid = min(self.bhz_pktid, self.bhn_pktid)
        self.assertEqual(conn.cmd(f"DATA {start_pktid}"), "OK")
        conn.sendline("END")

        formats = {}
        for _ in range(2):
            frame = conn.recv_v4()
            self.assertEqual(frame["kind"], "data")
            formats[frame["pktid"]] = frame["format"]

        self.assertEqual(formats[self.bhz_pktid], "3")
        self.assertEqual(formats[self.bhn_pktid], "2")

        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v4()

    def test_global_select_before_station(self):
        # A SELECT issued with no preceding STATION applies globally to
        # the whole ring (all-station mode).
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z"), "OK")
        conn.sendline("DATA ALL")
        conn.sendline("END")

        frame = conn.recv_v4()
        self.assertEqual(frame["kind"], "data")
        self.assertEqual(frame["pktid"], self.bhz_pktid)
        self.assertEqual(frame["payload"], self.bhz_record)

        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v4()

    def test_empty_select_error(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertTrue(conn.cmd("SELECT").startswith("ERROR ARGUMENTS"))

    def test_select_negated_pattern_with_filter_accepted(self):
        # The v4 spec does not permit a ":filter" suffix on a negated (!)
        # pattern, but ringserver deliberately accepts it: the suffix may
        # be a stream label, which must be usable in exclusions.  A
        # conversion filter on a negated pattern is accepted and inert;
        # the negation itself still applies.
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT *_B_H_?"), "OK")
        self.assertEqual(conn.cmd("SELECT !00_B_H_N:3"), "OK")
        self.assertEqual(conn.cmd("DATA ALL"), "OK")
        conn.sendline("END")

        frame = conn.recv_v4()
        self.assertEqual(frame["kind"], "data")
        self.assertEqual(frame["pktid"], self.bhz_pktid)
        self.assertEqual(frame["payload"], self.bhz_record)

        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v4()

    def test_select_label_extension(self):
        # Label selectors are a ringserver extension beyond the v4 spec,
        # used to disambiguate multiple streams sharing the same FDSN
        # Source ID (e.g. raw vs. processed feeds of the same channel).
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_E:RAW"), "OK")
        self.assertEqual(conn.cmd("DATA ALL"), "OK")
        conn.sendline("END")

        frame = conn.recv_v4()
        self.assertEqual(frame["kind"], "data")
        self.assertEqual(frame["pktid"], self.bhe_pktid)
        self.assertEqual(frame["payload"], self.bhe_record)

        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v4()


class TestSeedLinkV4Info(unittest.TestCase):
    """SeedLink v4 INFO requests: CAPABILITIES, FORMATS, STATIONS, STREAMS,
    and argument/level error handling.
    """

    @classmethod
    def setUpClass(cls):
        cls.server = ringtest.Server(protocols="DataLink SeedLink").start()

        dl = ringtest.DataLinkConn(cls.server.port)
        cls.bhz_record = ringtest.make_ms2(chan="BHZ", seq=0)
        cls.bhz_pktid = dl.write(BHZ_STREAMID, cls.bhz_record)
        cls.bhn_record = ringtest.make_ms2(chan="BHN", seq=0)
        cls.bhn_pktid = dl.write(BHN_STREAMID, cls.bhn_record)
        dl.close()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _slconn(self, **kwargs):
        conn = ringtest.SeedLinkConn(self.server.port, **kwargs)
        self.addCleanup(conn.close)
        return conn

    def _info(self, conn, itype):
        conn.sendline(f"INFO {itype}")
        frame = conn.recv_v4()
        self.assertEqual(frame["format"], "J")
        return frame, json.loads(frame["payload"].decode("utf-8"))

    def test_info_capabilities(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        frame, doc = self._info(conn, "CAPABILITIES")
        self.assertEqual(frame["subformat"], "I")

        payload_text = json.dumps(doc)
        for cap in ("SLPROTO:4.0", "SLPROTO:3.1", "TIME", "SEQWILDCARD"):
            self.assertIn(cap, payload_text)

    def test_info_formats(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        frame, doc = self._info(conn, "FORMATS")
        self.assertEqual(frame["subformat"], "I")

        self.assertEqual(doc["format"]["2"]["subformat"]["D"], "Data")
        self.assertEqual(doc["format"]["3"]["subformat"]["D"], "Data")
        self.assertIn("native", doc["filter"])
        self.assertIn("3", doc["filter"])

    def test_info_stations(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        frame, doc = self._info(conn, "STATIONS")
        self.assertEqual(frame["subformat"], "I")

        stations = {s["id"]: s for s in doc["station"]}
        self.assertIn("XX_TEST", stations)
        station = stations["XX_TEST"]
        self.assertIn("description", station)
        self.assertEqual(station["start_seq"], min(self.bhz_pktid, self.bhn_pktid))
        self.assertEqual(station["end_seq"], max(self.bhz_pktid, self.bhn_pktid) + 1)

    def test_info_stations_with_pattern(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        _, doc = self._info(conn, "STATIONS XX_*")
        self.assertIn("XX_TEST", {s["id"] for s in doc["station"]})

        conn2 = self._slconn()
        self.assertEqual(conn2.cmd("SLPROTO 4.0"), "OK")
        frame2, doc2 = self._info(conn2, "STATIONS ZZ_*")
        self.assertEqual(frame2["subformat"], "I")
        self.assertEqual(doc2.get("station", []), [])

    def test_info_streams_with_patterns(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        _, doc = self._info(conn, "STREAMS XX_TEST 00_B_H_Z")

        stations = {s["id"]: s for s in doc["station"]}
        self.assertIn("XX_TEST", stations)
        streams = stations["XX_TEST"]["stream"]
        self.assertEqual(len(streams), 1)
        stream = streams[0]
        self.assertEqual(stream["id"], "00_B_H_Z")
        for field in ("id", "format", "subformat", "start_time", "end_time"):
            self.assertIn(field, stream)

    def test_info_no_item_error(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        frame, doc = self._info(conn, "")
        self.assertEqual(frame["subformat"], "E")
        self.assertEqual(doc["error"]["code"], "ARGUMENTS")
        self.assertTrue(doc["error"]["message"])

    def test_info_unrecognized_item_error(self):
        # INFO GAPS was removed in v4; the server must still report it as
        # a structured E-packet error.
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        frame, doc = self._info(conn, "GAPS")
        self.assertEqual(frame["subformat"], "E")
        self.assertIn(doc["error"]["code"], ("ARGUMENTS", "UNSUPPORTED"))

    def test_info_too_many_args_error(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        frame, doc = self._info(conn, "STREAMS XX_TEST 00_B_H_Z D extra")
        self.assertEqual(frame["subformat"], "E")
        self.assertEqual(doc["error"]["code"], "ARGUMENTS")


class TestSeedLinkV4InfoUntrusted(unittest.TestCase):
    """SeedLink v4 INFO CONNECTIONS from an untrusted client."""

    @classmethod
    def setUpClass(cls):
        cls.server = ringtest.Server(
            protocols="DataLink SeedLink",
            env={"RS_TRUSTED_IP": "192.0.2.1"}).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _slconn(self, **kwargs):
        conn = ringtest.SeedLinkConn(self.server.port, **kwargs)
        self.addCleanup(conn.close)
        return conn

    def test_info_connections_unauthorized(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        conn.sendline("INFO CONNECTIONS")
        frame = conn.recv_v4()
        self.assertEqual(frame["format"], "J")
        self.assertEqual(frame["subformat"], "E")
        doc = json.loads(frame["payload"].decode("utf-8"))
        self.assertEqual(doc["error"]["code"], "UNAUTHORIZED")


if __name__ == "__main__":
    unittest.main()
