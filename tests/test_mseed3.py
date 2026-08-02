"""miniSEED 3 ingest, delivery, conversion, and scanning tests for ringserver."""

import json
import os
import re
import socket
import struct
import tempfile
import time
import unittest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ringtest

BHZ2_STREAMID = "FDSN:XX_TEST_00_B_H_Z/MSEED"
BHN3_STREAMID = "FDSN:XX_TEST_00_B_H_N/MSEED3"


class TestMSeed3(unittest.TestCase):
    """miniSEED 3 handling against a live ringserver: DataLink storage,
    SeedLink v4 native delivery, on-the-fly v2->v3 conversion, and INFO
    reporting.
    """

    @classmethod
    def setUpClass(cls):
        cls.server = ringtest.Server(protocols="DataLink SeedLink HTTP").start()

        dl = ringtest.DataLinkConn(cls.server.port)

        # miniSEED 2 backlog, used to exercise on-the-fly v3 conversion.
        # cls.bhz2_records holds (ring_pktid, record_bytes) tuples in
        # local-sequence order for byte-exact comparison.
        cls.bhz2_records = []
        for i in range(3):
            record = ringtest.make_ms2(chan="BHZ", seq=i)
            pktid = dl.write(BHZ2_STREAMID, record)
            cls.bhz2_records.append((pktid, record))

        # Native miniSEED 3 backlog.
        cls.bhn3_records = []
        for i in range(3):
            record = ringtest.make_ms3(chan="BHN", seq=i)
            pktid = dl.write(BHN3_STREAMID, record)
            cls.bhn3_records.append((pktid, record))

        dl.close()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _slconn(self, **kwargs):
        """Open a SeedLinkConn to the shared server, closed on test end."""
        conn = ringtest.SeedLinkConn(self.server.port, **kwargs)
        self.addCleanup(conn.close)
        return conn

    # -- DataLink -------------------------------------------------------------

    def test_datalink_write_read_roundtrip(self):
        dl = ringtest.DataLinkConn(self.server.port)
        self.addCleanup(dl.close)

        for pktid, record in self.bhn3_records:
            header, payload = dl.read(pktid)
            self.assertTrue(header.startswith("PACKET"), header)
            self.assertIn(BHN3_STREAMID, header)
            self.assertEqual(payload, record)
            self.assertEqual(len(payload), 261)

    # -- SeedLink v4 delivery and conversion -----------------------------------

    def test_seedlink_v4_native_mseed3_delivery(self):
        start_pktid, expected = self.bhn3_records[0][0], self.bhn3_records[0:]

        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_N"), "OK")
        self.assertEqual(conn.cmd(f"DATA {start_pktid}"), "OK")
        conn.sendline("END")

        for pktid, record in expected:
            frame = conn.recv_v4()
            self.assertEqual(frame["kind"], "data")
            self.assertEqual(frame["format"], "3")
            self.assertEqual(frame["subformat"], "D")
            self.assertEqual(frame["staid"], "XX_TEST")
            self.assertEqual(frame["pktid"], pktid)
            self.assertEqual(frame["payload"], record)

        # Nothing else follows: the BHZ stream is excluded.
        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v4()

    def test_seedlink_v4_select_3_converts_v2_stream(self):
        start_pktid, expected = self.bhz2_records[0][0], self.bhz2_records[0:]

        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z:3"), "OK")
        self.assertEqual(conn.cmd(f"DATA {start_pktid}"), "OK")
        conn.sendline("END")

        for pktid, _record in expected:
            frame = conn.recv_v4()
            self.assertEqual(frame["kind"], "data")
            self.assertEqual(frame["format"], "3")
            self.assertEqual(frame["pktid"], pktid)

            # Don't assert exact length/bytes: conversion may add extra
            # headers. Instead verify the record is well-formed v3.
            payload = frame["payload"]
            self.assertEqual(payload[0:3], b"MS\x03")
            sidlen = payload[33]
            sid = payload[40:40 + sidlen].decode("ascii")
            self.assertEqual(sid, "FDSN:XX_TEST_00_B_H_Z")
            numsamples = struct.unpack("<I", payload[24:28])[0]
            self.assertEqual(numsamples, 100)
            self.assertEqual(payload[15], 1)

            crc = struct.unpack("<I", payload[28:32])[0]
            check = payload[:28] + b"\x00" * 4 + payload[32:]
            self.assertEqual(crc, ringtest.crc32c(check))

    def test_seedlink_v4_select_native_is_passthrough(self):
        start_pktid, expected = self.bhz2_records[0][0], self.bhz2_records[0:]

        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z:native"), "OK")
        self.assertEqual(conn.cmd(f"DATA {start_pktid}"), "OK")
        conn.sendline("END")

        for pktid, record in expected:
            frame = conn.recv_v4()
            self.assertEqual(frame["kind"], "data")
            self.assertEqual(frame["format"], "2")
            self.assertEqual(frame["pktid"], pktid)
            self.assertEqual(frame["payload"], record)

    def test_seedlink_v4_select_3_noop_on_native_v3(self):
        start_pktid, expected = self.bhn3_records[0][0], self.bhn3_records[0:]

        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_N:3"), "OK")
        self.assertEqual(conn.cmd(f"DATA {start_pktid}"), "OK")
        conn.sendline("END")

        for pktid, record in expected:
            frame = conn.recv_v4()
            self.assertEqual(frame["kind"], "data")
            self.assertEqual(frame["format"], "3")
            self.assertEqual(frame["pktid"], pktid)
            self.assertEqual(frame["payload"], record)

    # -- v4 INFO --------------------------------------------------------------

    def test_v4_info_streams_reports_format(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        conn.sendline("INFO STREAMS")
        frame = conn.recv_v4()

        doc = json.loads(frame["payload"].decode("utf-8"))
        stations = {s["id"]: s for s in doc["station"]}
        self.assertIn("XX_TEST", stations)
        streams = {s["id"]: s for s in stations["XX_TEST"]["stream"]}
        self.assertEqual(streams["00_B_H_Z"]["format"], "2")
        self.assertEqual(streams["00_B_H_N"]["format"], "3")

    def test_v4_info_connections_shows_convert_selector(self):
        # Hold a connection open with a ":3" conversion selector, then
        # verify it's reported from a second connection's perspective.
        holder = self._slconn()
        self.assertEqual(holder.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(holder.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(holder.cmd("SELECT 00_B_H_Z:3"), "OK")

        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        conn.sendline("INFO CONNECTIONS")
        frame = conn.recv_v4()

        doc = json.loads(frame["payload"].decode("utf-8"))
        seedlink_clients = [c for c in doc["connections"]["client"]
                             if c["type"].startswith("SeedLink")]

        station = None
        for client in seedlink_clients:
            for st in client.get("station", []):
                if st["id"] == "XX_TEST":
                    station = st
                    break

        self.assertIsNotNone(station)
        self.assertIn("00_B_H_Z:3", station["selector"])


class TestMSeed3Scan(unittest.TestCase):
    """`-MSSCAN` directory scanning of miniSEED 3 files, alone and mixed
    with miniSEED 2 in the same file.
    """

    def test_mseedscan_v3_file(self):
        with tempfile.TemporaryDirectory(prefix="ringtest-scan3-") as scandir:
            server = ringtest.Server(
                protocols="DataLink SeedLink HTTP",
                extra_args=["-MSSCAN", str(scandir)]).start()
            try:
                records = b"".join(
                    ringtest.make_ms3(chan="BHZ", seq=seq) for seq in (1, 2, 3))

                tmp_path = os.path.join(scandir, ".tmp")
                final_path = os.path.join(scandir, "test.mseed3")
                with open(tmp_path, "wb") as f:
                    f.write(records)
                os.rename(tmp_path, final_path)

                expected_id = None
                deadline = time.time() + 20
                while time.time() < deadline and expected_id is None:
                    status, _, body = ringtest.http_get(server.port, "/streamids")
                    if status == 200:
                        for line in body.decode().splitlines():
                            if "MSEED3" in line:
                                expected_id = line.strip()
                                break
                    if expected_id is None:
                        time.sleep(0.5)

                if expected_id is None:
                    self.fail("mseedscan did not surface a v3 stream for the "
                              "scanned file within 20s; server log:\n"
                              + server.log_text())

                self.assertEqual(expected_id, "FDSN:XX_TEST_00_B_H_Z/MSEED3")

                # The reply's packet ID is the earliest packet in the ring;
                # READ it directly to verify the first scanned record. This
                # also exercises the scanner's variable-length ms3_detect
                # framing across the three concatenated records.
                dl = ringtest.DataLinkConn(server.port)
                match_header = dl.match(f"^{re.escape(expected_id)}$")
                self.assertTrue(match_header.startswith("OK"), match_header)
                pos_header = dl.position_set("EARLIEST")
                self.assertTrue(pos_header.startswith("OK"), pos_header)
                earliest_pktid = int(pos_header.split()[1])

                header, payload = dl.read(earliest_pktid)
                self.assertTrue(header.startswith("PACKET"), header)
                self.assertEqual(payload, records[:261])
                dl.close()
            finally:
                server.stop()

    def test_mseedscan_mixed_v2_v3_file(self):
        with tempfile.TemporaryDirectory(prefix="ringtest-scanmix-") as scandir:
            server = ringtest.Server(
                protocols="DataLink SeedLink HTTP",
                extra_args=["-MSSCAN", str(scandir)]).start()
            try:
                records = (ringtest.make_ms2(chan="BHZ", seq=1) +
                           ringtest.make_ms3(chan="BHN", seq=1))

                tmp_path = os.path.join(scandir, ".tmp")
                final_path = os.path.join(scandir, "test.mseed")
                with open(tmp_path, "wb") as f:
                    f.write(records)
                os.rename(tmp_path, final_path)

                found = set()
                deadline = time.time() + 20
                while time.time() < deadline and len(found) < 2:
                    status, _, body = ringtest.http_get(server.port, "/streamids")
                    if status == 200:
                        for line in body.decode().splitlines():
                            line = line.strip()
                            if line.endswith("/MSEED") or line.endswith("/MSEED3"):
                                found.add(line)
                    if len(found) < 2:
                        time.sleep(0.5)

                if len(found) < 2:
                    self.fail("mseedscan did not surface both stream versions "
                              "within 20s; server log:\n" + server.log_text())

                self.assertIn("FDSN:XX_TEST_00_B_H_Z/MSEED", found)
                self.assertIn("FDSN:XX_TEST_00_B_H_N/MSEED3", found)
            finally:
                server.stop()


if __name__ == "__main__":
    unittest.main()
