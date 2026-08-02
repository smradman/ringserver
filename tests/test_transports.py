"""TLS transport coverage for ringserver.

Every protocol carried over a TLS listener: DataLink, SeedLink v3/v4,
HTTPS, and WebSocket-over-TLS (wss) sessions.
"""

import socket
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ringtest


class TLSTransportTestCase(unittest.TestCase):
    """Tests against a shared DataLink+SeedLink+HTTP server on a TLS listener."""

    @classmethod
    def setUpClass(cls):
        cls.server = ringtest.Server(
            protocols="DataLink SeedLink HTTP",
            listen_flags="TLS",
            env={
                "RS_TLS_CERT_FILE": str(ringtest.DATA_DIR / "test-cert.pem"),
                "RS_TLS_KEY_FILE": str(ringtest.DATA_DIR / "test-key.pem"),
            }).start()

        # The readiness probe in Server.start() is a plain TCP connect/close,
        # which aborts before any TLS handshake and logs a benign error.
        cls.server.ignore_log_patterns.append(r"Error negotiating TLS")

        dl = ringtest.DataLinkConn(0, sock=cls._tls_sock())
        cls.records = []
        for seq in range(1, 5):
            record = ringtest.make_ms2(chan="BHZ", seq=seq)
            pktid = dl.write("FDSN:XX_TEST_00_B_H_Z/MSEED", record)
            cls.records.append((pktid, record))
        dl.close()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    @classmethod
    def _tls_sock(cls):
        sock = socket.create_connection(("127.0.0.1", cls.server.port), timeout=10)
        tls_sock = ringtest.tls_client_context().wrap_socket(
            sock, server_hostname="127.0.0.1")
        tls_sock.settimeout(10)
        return tls_sock

    def test_datalink_tls(self):
        dl = ringtest.DataLinkConn(0, sock=self._tls_sock())
        self.assertIsNotNone(dl.id_response)

        payload = b"tls-datalink-\x00-payload"
        pktid = dl.write("TLSTEST_A/RAW", payload)

        header, body = dl.read(pktid)
        self.assertTrue(header.startswith("PACKET"), header)
        self.assertEqual(body, payload)
        dl.close()

    def test_seedlink_v3_tls(self):
        # Resuming at the first record's packet ID yields the full backlog.
        start_pktid, expected = self.records[0][0], self.records[0:]

        sl = ringtest.SeedLinkConn(0, sock=self._tls_sock())
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
        sl.close()

    def test_seedlink_v4_tls(self):
        start_pktid, expected = self.records[0][0], self.records[0:]

        sl = ringtest.SeedLinkConn(0, sock=self._tls_sock())
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
        sl.close()

    def test_https_id(self):
        status, headers, body = ringtest.http_get(self.server.port, "/id", tls=True)
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "text/plain")
        self.assertIn("ringserver", body.decode("utf-8").lower())

    def test_https_streams(self):
        status, headers, body = ringtest.http_get(
            self.server.port, "/streams", tls=True)
        self.assertEqual(status, 200)

        ids = {line.split()[0] for line in body.decode("utf-8").splitlines()}
        self.assertIn("FDSN:XX_TEST_00_B_H_Z/MSEED", ids)

    def test_websocket_datalink_wss(self):
        ws = ringtest.WebSocketConn(self.server.port, "/datalink",
                                     subprotocol="DataLink1.1", tls=True)
        self.addCleanup(ws.close)
        self.assertEqual(ws.status, 101)
        self.assertEqual(ws.headers["sec-websocket-protocol"], "DataLink1.1")

        dl = ringtest.DataLinkConn(0, sock=ws)
        record = ringtest.make_ms2(seq=999)
        pktid = dl.write("TLSTEST_A/RAW", record)

        header, payload = dl.read(pktid)
        self.assertTrue(header.startswith("PACKET"), header)
        self.assertEqual(payload, record)

    def _ws_seedlink(self, subprotocol):
        ws = ringtest.WebSocketConn(self.server.port, "/seedlink",
                                     subprotocol=subprotocol, tls=True)
        self.addCleanup(ws.close)
        self.assertEqual(ws.status, 101)
        self.assertEqual(ws.headers["sec-websocket-protocol"], subprotocol)
        return ringtest.SeedLinkConn(0, sock=ws)

    def test_websocket_seedlink_v3_wss(self):
        start_pktid, expected = self.records[0][0], self.records[0:]

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

    def test_websocket_seedlink_v4_wss(self):
        start_pktid, expected = self.records[0][0], self.records[0:]

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


if __name__ == "__main__":
    unittest.main()
