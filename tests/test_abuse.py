"""Misbehaving-client tests: slow-loris stalls, silent connections, junk
input, stalled readers, and connection limits.
"""

import os
import socket
import struct
import sys
import time
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ringtest


def unique(label):
    """Return a short, collision-free stream ID prefix."""
    return f"{label}{uuid.uuid4().hex[:8].upper()}"


class SlowClientTestCase(unittest.TestCase):
    """Clients that connect but never complete a valid request."""

    @classmethod
    def setUpClass(cls):
        cls.server = ringtest.Server(
            protocols="DataLink SeedLink HTTP",
            env={"RS_NETIO_TIMEOUT": "2"}).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _raw_conn(self):
        """Open a raw TCP connection to the shared server, closed on test end."""
        sock = socket.create_connection(("127.0.0.1", self.server.port), timeout=10)
        self.addCleanup(sock.close)
        return sock

    def test_slowloris_datalink_stall(self):
        # A DataLink header body is read with a "must fulfill" receive, which
        # polls the socket directly rather than going through the main loop's
        # incomplete-command clock; a stalled header body is caught by that
        # poll timing out, logged as "Timeout receiving data".
        sock = self._raw_conn()
        sock.sendall(b"DL\x14")

        start = time.time()
        data = sock.recv(16)
        elapsed = time.time() - start

        self.assertEqual(data, b"")
        self.assertLess(elapsed, 8)
        self.assertIn("Timeout receiving data", self.server.log_text())

    def test_slowloris_http_stall(self):
        # Deliberately no line terminator at all: HTTP requests are read a
        # line at a time and only the main loop's incomplete-command clock
        # catches a request line that never completes.
        sock = self._raw_conn()
        sock.sendall(b"GET /status HTTP/1.1")

        start = time.time()
        data = sock.recv(16)
        elapsed = time.time() - start

        self.assertEqual(data, b"")
        self.assertLess(elapsed, 8)
        self.assertIn("Timeout for incomplete command reception",
                       self.server.log_text())

    def test_slowloris_trickle(self):
        # Bytes keep arriving, so the header body's "must fulfill" receive
        # never idles long enough for a single poll to time out; an
        # overall receive deadline (twice the I/O timeout) catches it instead.
        sock = self._raw_conn()
        sock.sendall(b"DL\x40")

        start = time.time()
        failed = False
        try:
            while time.time() - start < 8:
                time.sleep(0.3)
                sock.sendall(b"x")
            data = sock.recv(16)
            failed = data == b""
        except (BrokenPipeError, ConnectionResetError):
            failed = True

        elapsed = time.time() - start
        self.assertTrue(failed, "server did not disconnect a trickling client")
        self.assertLess(elapsed, 8)
        self.assertIn("Total receive deadline exceeded (slow trickle protection)",
                       self.server.log_text())

    def test_slowloris_seedlink_stall(self):
        # A SeedLink command line that never completes is caught by the
        # main loop's incomplete-command clock, as for an HTTP request line,
        # after the connection has been identified as SeedLink.
        conn = ringtest.SeedLinkConn(self.server.port)
        self.addCleanup(conn.sock.close)
        conn.hello()

        conn.sock.sendall(b"STATION XX_TE")  # no line terminator

        start = time.time()
        data = conn.sock.recv(16)
        elapsed = time.time() - start

        self.assertEqual(data, b"")
        self.assertLess(elapsed, 8)
        self.assertIn("Timeout for incomplete command reception",
                       self.server.log_text())

    def test_slowloris_seedlink_trickle(self):
        # Bytes keep arriving but a line terminator never does; the
        # incomplete-command clock is not reset by continued bytes.
        conn = ringtest.SeedLinkConn(self.server.port)
        self.addCleanup(conn.sock.close)
        conn.hello()

        conn.sock.sendall(b"STATION ")
        start = time.time()
        failed = False
        try:
            while time.time() - start < 8:
                time.sleep(0.3)
                conn.sock.sendall(b"X")
            data = conn.sock.recv(16)
            failed = data == b""
        except (BrokenPipeError, ConnectionResetError):
            failed = True

        elapsed = time.time() - start
        self.assertTrue(failed, "server did not disconnect a trickling SeedLink client")
        self.assertLess(elapsed, 8)
        self.assertIn("Timeout for incomplete command reception",
                       self.server.log_text())

    def test_datalink_write_payload_does_not_arm_stale_timer(self):
        # A WRITE header and its miniSEED payload sent in separate segments
        # force the server's blocking payload read to call recv(), which
        # previously left the incomplete-command clock armed even after the
        # WRITE fully completed, disconnecting an otherwise idle writer.
        prefix = unique("PAYLOAD")
        streamid = f"{prefix}/RAW"
        writer = ringtest.DataLinkConn(self.server.port)
        self.addCleanup(writer.close)

        payload = ringtest.make_ms2()
        now_us = int(time.time() * 1_000_000)
        header = f"WRITE {streamid} {now_us} {now_us + 1000} A {len(payload)}"
        hbytes = header.encode("ascii")

        writer.sock.sendall(b"DL" + bytes([len(hbytes)]) + hbytes)
        time.sleep(0.2)
        writer.sock.sendall(payload)

        resp_header, _ = writer.recv()
        self.assertTrue(resp_header.startswith("OK"), resp_header)
        first_pid = int(resp_header.split()[1])

        # Idle past the network I/O timeout; the connection should remain
        # open since the WRITE fully completed.
        time.sleep(5)

        last_pid = writer.write(streamid, ringtest.make_ms2())
        self.assertIsNotNone(last_pid)
        self.assertGreater(last_pid, first_pid)
        self.assertNotIn("Timeout for incomplete command reception",
                          self.server.log_text())

    def test_proxyv2_header_rejected(self):
        sock = self._raw_conn()
        sock.sendall(b"\r\n\r")

        data = sock.recv(16)
        self.assertEqual(data, b"")
        self.assertIn("not configured for PROXYv2", self.server.log_text())

    def test_seedlink_junk_consecutive_errors(self):
        sock = self._raw_conn()
        sock.settimeout(10)

        eof = False
        for _ in range(30):
            try:
                sock.sendall(b"NOTACOMMAND\r\n")
            except (BrokenPipeError, ConnectionResetError):
                eof = True
                break
            try:
                data = sock.recv(256)
            except (ConnectionResetError, TimeoutError):
                eof = True
                break
            if data == b"":
                eof = True
                break

        self.assertTrue(eof, "server did not disconnect after repeated junk commands")
        self.assertIn("Too many consecutive errors", self.server.log_text())

    def test_websocket_oversize_frame_length(self):
        ws = ringtest.WebSocketConn(self.server.port, "/datalink",
                                     subprotocol="DataLink1.1")
        self.addCleanup(ws.close)

        frame = bytes([0x82, 0x80 | 127]) + struct.pack(">Q", 1 << 30) + os.urandom(4)
        ws.sock.sendall(frame)

        # The server sends a WebSocket close frame before dropping the TCP
        # connection; drain until EOF rather than expecting an immediate one.
        ws.sock.settimeout(10)
        eof = False
        for _ in range(10):
            data = ws.sock.recv(4096)
            if data == b"":
                eof = True
                break
        self.assertTrue(eof, "server did not close the connection")
        self.assertIn("exceeds receive buffer size", self.server.log_text())

    def test_stalled_reader_does_not_wedge_server(self):
        prefix = unique("STALL")
        streamid = f"{prefix}/RAW"

        # A stalled reader eventually fails a send with a timeout, which the
        # server also logs as a lower-level ring-packet send error; these
        # are the expected consequence of this test, not a real problem.
        self.server.ignore_log_patterns.append(r"SendRingPacket\(\): Error sending packet")
        self.server.ignore_log_patterns.append(r"Error sending packet to client")

        reader_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        reader_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        reader_sock.connect(("127.0.0.1", self.server.port))
        reader = ringtest.DataLinkConn(0, sock=reader_sock)
        self.addCleanup(reader.close)

        writer = ringtest.DataLinkConn(self.server.port)
        self.addCleanup(writer.close)

        first_pid = writer.write(streamid, ringtest.make_ms2())

        header = reader.match(f"^{prefix}")
        self.assertTrue(header.startswith("OK"), header)
        header = reader.position_set(str(first_pid))
        self.assertTrue(header.startswith("OK"), header)
        reader.stream()

        # Write until the stalled reader's kernel buffers fill and the
        # server's send poll times out; buffer capacity varies widely by
        # platform.  Each acked write also proves the server is not wedged
        # while the stalled reader's thread is blocked in its send poll.
        deadline = time.time() + 60
        while "Timeout sending data" not in self.server.log_text():
            self.assertLess(time.time(), deadline,
                            "server never timed out sending to the stalled reader")
            for _ in range(250):
                writer.write(streamid, b"x" * 400)

        # The writer can still write and get acked: the server is not wedged.
        last_pid = writer.write(streamid, ringtest.make_ms2())
        self.assertIsNotNone(last_pid)

        # A brand-new reader can still read the latest packet.
        fresh = ringtest.DataLinkConn(self.server.port)
        self.addCleanup(fresh.close)
        header, payload = fresh.read(last_pid)
        self.assertTrue(header.startswith("PACKET"), header)

        # The stalled reader itself should have been disconnected by now for
        # failing to drain its socket; drain to confirm EOF/reset.
        reader_sock.settimeout(10)
        stalled_disconnected = False
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                chunk = reader_sock.recv(65536)
            except TimeoutError:
                break  # Still connected, just no data: not a disconnect
            except OSError:
                stalled_disconnected = True
                break
            if chunk == b"":
                stalled_disconnected = True
                break

        self.assertTrue(stalled_disconnected,
                         "stalled reader was never disconnected")
        self.assertIn("Timeout sending data", self.server.log_text())


class LimitTestCase(unittest.TestCase):
    """Connection-count limits, enforced at accept time."""

    def _check_rejected_and_others_alive(self, server, conns):
        """Open one more connection past the limit, expect it rejected.

        Retries once to absorb a race with the readiness-probe connection's
        server-side teardown, then confirms the pre-existing connections
        are still functioning normally.
        """
        for attempt in range(2):
            extra = socket.create_connection(("127.0.0.1", server.port), timeout=10)
            extra.settimeout(3)
            try:
                data = extra.recv(16)
            except (ConnectionResetError, TimeoutError):
                data = b""
            extra.close()
            if data == b"":
                break
            time.sleep(0.5)
        self.assertEqual(data, b"")

        for conn in conns:
            conn.send("ID ringtest.py")
            header, _ = conn.recv()
            self.assertIn("DataLink", header)

    def test_max_clients_per_ip(self):
        server = ringtest.Server(
            protocols="DataLink",
            env={"RS_MAX_CLIENTS_PER_IP": "3", "RS_WRITE_IP": "192.0.2.1"}).start()
        try:
            # The server's connection-count watchdog reaps closed threads
            # on a ~1s cadence, so give the readiness-probe connection's
            # slot time to be reclaimed before consuming the budget.
            time.sleep(1.5)
            conns = [ringtest.DataLinkConn(server.port, send_id=False)
                     for _ in range(3)]
            time.sleep(0.3)

            self._check_rejected_and_others_alive(server, conns)

            for conn in conns:
                conn.close()

            self.assertIn("Too many connections from", server.log_text())
        finally:
            server.stop()

    def test_max_clients_global(self):
        server = ringtest.Server(
            protocols="DataLink",
            env={"RS_MAX_CLIENTS": "3", "RS_WRITE_IP": "192.0.2.1"}).start()
        try:
            time.sleep(1.5)
            conns = [ringtest.DataLinkConn(server.port, send_id=False)
                     for _ in range(3)]
            time.sleep(0.3)

            self._check_rejected_and_others_alive(server, conns)

            for conn in conns:
                conn.close()

            self.assertIn("Maximum number of clients exceeded", server.log_text())
        finally:
            server.stop()


class IdleTimeoutTestCase(unittest.TestCase):
    """Idle and non-communicating client watchdogs."""

    def test_idle_identified_client_closed(self):
        server = ringtest.Server(
            protocols="DataLink", env={"RS_CLIENT_TIMEOUT": "2"}).start()
        try:
            conn = ringtest.DataLinkConn(server.port)

            conn.sock.settimeout(10)
            start = time.time()
            data = conn.sock.recv(16)
            elapsed = time.time() - start

            self.assertEqual(data, b"")
            self.assertLess(elapsed, 7)
            self.assertIn("Closing idle client connection", server.log_text())
            conn.close()
        finally:
            server.stop()

    def test_never_communicating_client_closed(self):
        server = ringtest.Server(protocols="DataLink").start()
        try:
            sock = socket.create_connection(("127.0.0.1", server.port), timeout=20)
            sock.settimeout(20)

            start = time.time()
            data = sock.recv(16)
            elapsed = time.time() - start

            self.assertEqual(data, b"")
            self.assertGreater(elapsed, 8)
            self.assertLess(elapsed, 16)
            self.assertIn("Non-communicating client timeout", server.log_text())
            sock.close()
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main()
