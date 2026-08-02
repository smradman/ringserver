"""HTTP and WebSocket protocol tests for ringserver.

Exercises the plain-text and JSON HTTP endpoints (/id, /streams,
/streamids, /status, /connections), error handling (404/501/400/403),
response framing, gzip content negotiation, the built-in favicon, and
WebSocket transport (upgrade negotiation, rejections, and a full
DataLink round trip carried over WebSocket frames).
"""

import gzip
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ringtest

SERVER_ID = "HTTP Test Server"

# Enough streams to push the /streams response body past the 1 KiB
# gzip threshold.
BULK_STREAM_COUNT = 30


class HTTPTestCase(unittest.TestCase):
    """Tests against a shared DataLink+HTTP server reachable from localhost."""

    @classmethod
    def setUpClass(cls):
        cls.server = ringtest.Server(
            protocols="DataLink HTTP", server_id=SERVER_ID).start()

        dl = ringtest.DataLinkConn(cls.server.port)
        cls.stream_ids = ["HTTPTEST_A/RAW", "HTTPTEST_B/RAW"]
        cls.stream_ids += [f"BULK_{i:02d}/RAW" for i in range(BULK_STREAM_COUNT)]
        for seq, streamid in enumerate(cls.stream_ids, start=1):
            dl.write(streamid, ringtest.make_ms2(seq=seq))
        dl.close()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def get(self, path, headers=None, method="GET"):
        return ringtest.http_get(self.server.port, path, headers=headers,
                                  method=method)

    def test_id_text_plain(self):
        status, headers, body = self.get("/id")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "text/plain")

        text = body.decode("utf-8")
        self.assertIn(SERVER_ID, text)
        self.assertIn("ringserver", text.lower())

        # Response framing: Content-Length matches the body, and the
        # connection is closed after a plain response.
        self.assertEqual(int(headers["content-length"]), len(body))
        self.assertEqual(headers["connection"], "close")

    def test_id_json(self):
        status, headers, body = self.get("/id/json")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/json")

        doc = json.loads(body)
        self.assertEqual(doc["organization"], SERVER_ID)
        self.assertIn("ringserver", doc["software"].lower())
        self.assertIn("server_start", doc)

    def test_streams_text_format(self):
        status, headers, body = self.get("/streams")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "text/plain")

        lines = body.decode("utf-8").splitlines()
        by_id = {}
        for line in lines:
            parts = line.split()
            self.assertEqual(len(parts), 3, f"unexpected line format: {line!r}")
            by_id[parts[0]] = parts[1:]

        for streamid in ("HTTPTEST_A/RAW", "HTTPTEST_B/RAW"):
            self.assertIn(streamid, by_id)

    def test_streamids_text_format(self):
        status, headers, body = self.get("/streamids")
        self.assertEqual(status, 200)

        ids = body.decode("utf-8").splitlines()
        for streamid in self.stream_ids:
            self.assertIn(streamid, ids)

    def test_streamids_match_filter(self):
        status, headers, body = self.get("/streamids?match=HTTPTEST_A")
        self.assertEqual(status, 200)

        ids = body.decode("utf-8").splitlines()
        self.assertIn("HTTPTEST_A/RAW", ids)
        self.assertNotIn("HTTPTEST_B/RAW", ids)
        for i in range(BULK_STREAM_COUNT):
            self.assertNotIn(f"BULK_{i:02d}/RAW", ids)

    def test_streams_json(self):
        status, headers, body = self.get("/streams/json")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/json")

        doc = json.loads(body)
        ids = {entry["id"] for entry in doc["stream"]}
        for streamid in ("HTTPTEST_A/RAW", "HTTPTEST_B/RAW"):
            self.assertIn(streamid, ids)

    def test_status_ok_when_trusted(self):
        status, headers, body = self.get("/status")
        self.assertEqual(status, 200)

        text = body.decode("utf-8")
        self.assertIn(f"Organization: {SERVER_ID}", text)
        self.assertIn("Ring size:", text)

    def test_connections_ok_when_trusted(self):
        status, headers, body = self.get("/connections")
        self.assertEqual(status, 200)
        # Not asserting our own connection appears, just that the
        # response is well-formed text.
        self.assertIsInstance(body.decode("utf-8"), str)

    def test_unknown_path_returns_404(self):
        status, headers, body = self.get("/nope")
        self.assertEqual(status, 404)

    def test_post_method_not_implemented(self):
        status, headers, body = self.get("/id", method="POST")
        self.assertEqual(status, 501)

    def test_streams_gzip_encoding(self):
        identity_status, identity_headers, identity_body = self.get("/streams")
        self.assertEqual(identity_status, 200)
        self.assertGreaterEqual(len(identity_body), 1024)

        status, headers, body = self.get(
            "/streams", headers={"Accept-Encoding": "gzip"})
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-encoding"], "gzip")
        self.assertEqual(gzip.decompress(body), identity_body)

    def test_favicon_ico(self):
        status, headers, body = self.get("/favicon.ico")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "image/x-icon")
        self.assertGreater(len(body), 0)

    def test_websocket_datalink_roundtrip(self):
        ws = ringtest.WebSocketConn(self.server.port, "/datalink",
                                     subprotocol="DataLink1.1")
        try:
            self.assertEqual(ws.status, 101)
            self.assertEqual(ws.headers["sec-websocket-protocol"], "DataLink1.1")

            dl = ringtest.DataLinkConn(0, sock=ws)
            self.assertIsNotNone(dl.id_response)

            record = ringtest.make_ms2(seq=999)
            pktid = dl.write("HTTPTEST_A/RAW", record)
            self.assertIsInstance(pktid, int)

            header, payload = dl.read(pktid)
            self.assertTrue(header.startswith("PACKET"))
            self.assertEqual(payload, record)
        finally:
            ws.close()

    def test_websocket_datalink_10_subprotocol(self):
        ws = ringtest.WebSocketConn(self.server.port, "/datalink",
                                     subprotocol="DataLink1.0")
        try:
            self.assertEqual(ws.status, 101)
            self.assertEqual(ws.headers["sec-websocket-protocol"], "DataLink1.0")

            dl = ringtest.DataLinkConn(0, sock=ws)
            self.assertIsNotNone(dl.id_response)

            record = ringtest.make_ms2(seq=998)
            pktid = dl.write("HTTPTEST_A/RAW", record)
            header, payload = dl.read(pktid)
            self.assertTrue(header.startswith("PACKET"))
            self.assertEqual(payload, record)
        finally:
            ws.close()

    def test_websocket_subprotocol_preference(self):
        ws = ringtest.WebSocketConn(self.server.port, "/datalink",
                                     subprotocol="DataLink1.0, DataLink1.1")
        try:
            self.assertEqual(ws.status, 101)
            self.assertEqual(ws.headers["sec-websocket-protocol"], "DataLink1.1")
        finally:
            ws.close()

    def test_websocket_no_subprotocol(self):
        ws = ringtest.WebSocketConn(self.server.port, "/datalink", subprotocol=None)
        try:
            self.assertEqual(ws.status, 101)
            self.assertNotIn("sec-websocket-protocol", ws.headers)

            dl = ringtest.DataLinkConn(0, sock=ws)
            self.assertIsNotNone(dl.id_response)
        finally:
            ws.close()

    def test_websocket_rejections(self):
        with self.subTest("unsupported version"):
            self.server.ignore_log_patterns.append(
                r"Error negotiating DataLink WebSocket")
            ws = ringtest.WebSocketConn(self.server.port, "/datalink",
                                         subprotocol="DataLink1.1",
                                         version="8", expect_status=400)
            self.assertEqual(ws.status, 400)
            ws.close()

        with self.subTest("seedlink upgrade on non-SeedLink listener"):
            self.server.ignore_log_patterns.append(r"non-SeedLink port")
            ws = ringtest.WebSocketConn(self.server.port, "/seedlink",
                                         subprotocol="SeedLink4.0",
                                         expect_status=400)
            self.assertEqual(ws.status, 400)
            ws.close()


class WebSocketSeedLinkTestCase(unittest.TestCase):
    """SeedLink sessions carried over the /seedlink WebSocket upgrade."""

    @classmethod
    def setUpClass(cls):
        cls.server = ringtest.Server(protocols="DataLink SeedLink HTTP").start()

        dl = ringtest.DataLinkConn(cls.server.port)
        cls.records = []
        for seq in range(1, 5):
            record = ringtest.make_ms2(chan="BHZ", seq=seq)
            pktid = dl.write("FDSN:XX_TEST_00_B_H_Z/MSEED", record)
            cls.records.append((pktid, record))
        dl.close()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _ws_seedlink(self, subprotocol):
        ws = ringtest.WebSocketConn(self.server.port, "/seedlink",
                                    subprotocol=subprotocol)
        self.addCleanup(ws.close)
        self.assertEqual(ws.status, 101)
        self.assertEqual(ws.headers["sec-websocket-protocol"], subprotocol)
        return ringtest.SeedLinkConn(0, sock=ws)

    def test_websocket_seedlink_v3_stream(self):
        # Resume from the second record: the first packet ID cannot be a
        # resume target (see test_seedlink.py).
        start_pktid, expected = self.records[1][0], self.records[1:]

        sl = self._ws_seedlink("SeedLink3.1")
        id_line, _ = sl.hello()
        self.assertIn("SeedLink", id_line)
        self.assertEqual(sl.cmd("STATION TEST XX"), "OK")
        self.assertEqual(sl.cmd(f"DATA {start_pktid:06x}"), "OK")
        sl.sendline("END")

        for pktid, record in expected:
            frame = sl.recv_v3()
            self.assertEqual(frame["kind"], "data")
            self.assertEqual(frame["seq"], pktid & 0xFFFFFF)
            self.assertEqual(frame["record"], record)

    def test_websocket_seedlink_v4_stream(self):
        start_pktid, expected = self.records[1][0], self.records[1:]

        sl = self._ws_seedlink("SeedLink4.0")
        self.assertEqual(sl.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(sl.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(sl.cmd(f"DATA {start_pktid}"), "OK")
        sl.sendline("END")

        for pktid, record in expected:
            frame = sl.recv_v4()
            self.assertEqual(frame["kind"], "data")
            self.assertEqual(frame["format"], "2")
            self.assertEqual(frame["staid"], "XX_TEST")
            self.assertEqual(frame["pktid"], pktid)
            self.assertEqual(frame["payload"], record)

    def test_websocket_seedlink_subprotocol_preference(self):
        ws = ringtest.WebSocketConn(self.server.port, "/seedlink",
                                     subprotocol="SeedLink3.1, SeedLink4.0")
        self.addCleanup(ws.close)
        self.assertEqual(ws.status, 101)
        self.assertEqual(ws.headers["sec-websocket-protocol"], "SeedLink4.0")


class TrustedIPTestCase(unittest.TestCase):
    """Tests for the /status and /connections trust-permission gate."""

    @classmethod
    def setUpClass(cls):
        cls.server = ringtest.Server(
            protocols="DataLink HTTP", server_id=SERVER_ID,
            env={"RS_TRUSTED_IP": "192.0.2.1"}).start()
        cls.server.ignore_log_patterns.append(r"un-trusted client")

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def get(self, path):
        return ringtest.http_get(self.server.port, path)

    def test_status_forbidden_for_untrusted_client(self):
        status, headers, body = self.get("/status")
        self.assertEqual(status, 403)

    def test_connections_forbidden_for_untrusted_client(self):
        status, headers, body = self.get("/connections")
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
