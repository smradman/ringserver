"""Authentication and permission tests for ringserver.

Covers the external auth-program integration (DataLink AUTH USERPASS/JWT,
SeedLink v4 AUTH), the RS_AUTH_REQUIRED_FOR_STREAMS gate on DataLink STREAM
and SeedLink ring configuration, and allowed_streams/forbidden_streams
filtering returned by the auth program.
"""

import socket
import sys
import time
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ringtest

# Keyed on AUTH_USERNAME/AUTH_PASSWORD/AUTH_JWTOKEN, exercises the range of
# auth-program outcomes: success with/without write, stream filtering,
# outright failure, a non-zero exit, garbage stdout, and a hang.
AUTH_HELPER_SCRIPT = '''\
import json
import os
import sys
import time

username = os.environ.get("AUTH_USERNAME", "")
password = os.environ.get("AUTH_PASSWORD", "")
jwtoken = os.environ.get("AUTH_JWTOKEN", "")

if jwtoken == "good.jwt.token":
    print(json.dumps({"authenticated": True, "write_permission": True, "username": "jwtuser"}))
elif username == "alice" and password == "sesame":
    print(json.dumps({"authenticated": True, "write_permission": True, "username": "alice"}))
elif username == "bob" and password == "sesame":
    print(json.dumps({"authenticated": True, "username": "bob"}))
elif username == "carol" and password == "sesame":
    print(json.dumps({"authenticated": True, "username": "carol",
                       "allowed_streams": ["XX_ALLOW"]}))
elif username == "dave" and password == "sesame":
    print(json.dumps({"authenticated": True, "username": "dave",
                       "forbidden_streams": ["XX_SECRET"]}))
elif username == "erin" and password == "sesame":
    sys.exit(1)
elif username == "frank" and password == "sesame":
    print("this is not json")
elif username == "grace" and password == "sesame":
    time.sleep(30)
else:
    print(json.dumps({"authenticated": False}))
'''


def unique(label):
    """Return a short, collision-free stream ID prefix."""
    return f"{label}{uuid.uuid4().hex[:8].upper()}"


def _write_auth_helper(tmp_path):
    """Write the auth helper script into a server's temp dir; return its path."""
    script_path = tmp_path / "auth_helper.py"
    script_path.write_text(AUTH_HELPER_SCRIPT)
    return script_path


class DataLinkAuthTestCase(unittest.TestCase):
    """DataLink AUTH command: USERPASS/JWT credentials, resulting
    permissions, argument errors, and auth-program failure modes."""

    @classmethod
    def setUpClass(cls):
        server = ringtest.Server(protocols="DataLink")
        script_path = _write_auth_helper(server.tmp_path)
        # No implicit write permission for localhost, so the only way to
        # get WRITE_PERMISSION in this class is through authentication.
        server.env_overlay = {
            "RS_AUTH_COMMAND": f"{sys.executable} {script_path}",
            "RS_AUTH_TIMEOUT": "2",
            "RS_WRITE_IP": "192.0.2.1",
        }
        cls.server = server.start()
        # Deliberately triggered by the failure-mode and wrong-password
        # tests below; not real problems.
        cls.server.ignore_log_patterns += [
            r"Error performing authentication",
            r"Error executing auth program",
            r"Error parsing permission JSON",
            r"Authentication failed, not allowed to connect",
        ]

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _conn(self, **kwargs):
        """Open a DataLinkConn to the shared server, closed on test end."""
        conn = ringtest.DataLinkConn(self.server.port, **kwargs)
        self.addCleanup(conn.close)
        return conn

    def _auth_userpass(self, conn, username, password):
        payload = f"{username}\r{password}".encode("ascii")
        conn.send(f"AUTH USERPASS {len(payload)}", payload)
        return conn.recv()

    def _auth_jwt(self, conn, token):
        payload = token.encode("ascii")
        conn.send(f"AUTH JWT {len(payload)}", payload)
        return conn.recv()

    # -- capability advertisement -----------------------------------------

    def test_id_advertises_auth(self):
        conn = self._conn()
        self.assertIn(" AUTH", conn.id_response)
        self.assertNotIn(" WRITE", conn.id_response)

    # -- USERPASS -----------------------------------------------------------

    def test_userpass_grants_write(self):
        conn = self._conn()
        header, payload = self._auth_userpass(conn, "alice", "sesame")
        self.assertTrue(header.startswith("OK"), header)
        self.assertIn(b"Authentication successful", payload)

        conn.send("ID ringtest.py")
        header, _ = conn.recv()
        self.assertIn(" WRITE", header)

        streamid = f"{unique('AUTHWR')}/RAW"
        record = ringtest.make_ms2()
        pid = conn.write(streamid, record)
        header, data = conn.read(pid)
        self.assertTrue(header.startswith("PACKET"), header)
        self.assertEqual(data, record)

    def test_userpass_wrong_password_disconnects(self):
        conn = self._conn()
        start = time.monotonic()
        header, payload = self._auth_userpass(conn, "alice", "wrongpass")
        elapsed = time.monotonic() - start

        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"Authentication failed", payload)
        # The denial reply is delayed to slow brute-forcing attempts.
        self.assertGreaterEqual(elapsed, 1.5)
        self.assertEqual(conn.sock.recv(16), b"")

    def test_write_without_auth_refused(self):
        conn = self._conn()
        streamid = f"{unique('NOAUTH')}/RAW"
        payload = ringtest.make_ms2()
        now_us = int(time.time() * 1_000_000)

        conn.send(f"WRITE {streamid} {now_us} {now_us + 1000} A {len(payload)}", payload)
        header, resp = conn.recv()
        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"Write permission not granted", resp)
        self.assertEqual(conn.sock.recv(16), b"")

    def test_authenticated_without_write_refused(self):
        conn = self._conn()
        header, _ = self._auth_userpass(conn, "bob", "sesame")
        self.assertTrue(header.startswith("OK"), header)

        streamid = f"{unique('BOBWR')}/RAW"
        payload = ringtest.make_ms2()
        now_us = int(time.time() * 1_000_000)

        conn.send(f"WRITE {streamid} {now_us} {now_us + 1000} A {len(payload)}", payload)
        header, resp = conn.recv()
        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"Write permission not granted", resp)
        self.assertEqual(conn.sock.recv(16), b"")

    # -- JWT ------------------------------------------------------------

    def test_jwt_success(self):
        conn = self._conn()
        header, payload = self._auth_jwt(conn, "good.jwt.token")
        self.assertTrue(header.startswith("OK"), header)
        self.assertIn(b"Authentication successful", payload)

        conn.send("ID ringtest.py")
        header, _ = conn.recv()
        self.assertIn(" WRITE", header)

    def test_jwt_failure(self):
        conn = self._conn()
        header, payload = self._auth_jwt(conn, "bad.jwt.token")
        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"Authentication failed", payload)
        self.assertEqual(conn.sock.recv(16), b"")

    # -- argument errors --------------------------------------------------

    def test_auth_argument_errors(self):
        conn = self._conn()

        # Wrong argc: sub-command given but no size argument.
        conn.send("AUTH USERPASS")
        header, resp = conn.recv()
        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"AUTH requires 2 arguments", resp)

        # Non-numeric size argument.
        conn.send("AUTH USERPASS notanumber")
        header, resp = conn.recv()
        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"AUTH size argument is invalid", resp)

        # Size argument over the 4095-byte credential limit.
        conn.send("AUTH USERPASS 5000")
        header, resp = conn.recv()
        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"AUTH credentials are too large", resp)

        # Unsupported sub-command; the payload is still read.
        conn.send("AUTH NOPE 4", b"data")
        header, resp = conn.recv()
        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"Unsupported AUTH type", resp)

        # USERPASS payload missing the USER\rPASS separator.
        conn.send("AUTH USERPASS 8", b"userpass")
        header, resp = conn.recv()
        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"requires payload of USER", resp)

        # The connection is still usable after all of the above.
        header, _ = self._auth_userpass(conn, "alice", "sesame")
        self.assertTrue(header.startswith("OK"), header)

    # -- auth program failure modes -----------------------------------------

    def test_auth_program_exit_error(self):
        conn = self._conn()
        header, resp = self._auth_userpass(conn, "erin", "sesame")
        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"Error performing authentication", resp)

        # An auth-program failure is an operational error, not a denial:
        # the connection stays open and can still authenticate normally.
        header, _ = self._auth_userpass(conn, "alice", "sesame")
        self.assertTrue(header.startswith("OK"), header)

    def test_auth_program_garbage_output(self):
        conn = self._conn()
        header, resp = self._auth_userpass(conn, "frank", "sesame")
        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"Error performing authentication", resp)

        # The connection stays open and can still authenticate normally.
        header, _ = self._auth_userpass(conn, "alice", "sesame")
        self.assertTrue(header.startswith("OK"), header)

    def test_auth_program_timeout(self):
        conn = self._conn()
        start = time.time()
        header, resp = self._auth_userpass(conn, "grace", "sesame")
        elapsed = time.time() - start

        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"Error performing authentication", resp)
        self.assertGreater(elapsed, 1.5)
        self.assertLess(elapsed, 8)

        # The connection stays open; confirm it without invoking the
        # auth helper again.
        conn.send("ID ringtest.py")
        header, _ = conn.recv()
        self.assertTrue(header.startswith("ID"), header)

    def test_program_errors_eventually_disconnect(self):
        conn = self._conn()
        for _ in range(20):
            header, resp = self._auth_userpass(conn, "erin", "sesame")
            self.assertTrue(header.startswith("ERROR"), header)
            self.assertIn(b"Error performing authentication", resp)

        # Auth-program failures still count toward the consecutive-error
        # disconnect limit.
        self.assertEqual(conn.sock.recv(16), b"")


class WriteIPPreservationTestCase(unittest.TestCase):
    """Regression: an auth-program operational failure must not wipe out
    write permission already granted by RS_WRITE_IP."""

    @classmethod
    def setUpClass(cls):
        server = ringtest.Server(protocols="DataLink")
        script_path = _write_auth_helper(server.tmp_path)
        server.env_overlay = {
            "RS_AUTH_COMMAND": f"{sys.executable} {script_path}",
            "RS_AUTH_TIMEOUT": "2",
            "RS_WRITE_IP": "127.0.0.1",
        }
        cls.server = server.start()
        # Deliberately triggered by the auth-program-failure test below.
        cls.server.ignore_log_patterns += [
            r"Error performing authentication",
            r"Error executing auth program",
        ]

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _conn(self, **kwargs):
        """Open a DataLinkConn to the shared server, closed on test end."""
        conn = ringtest.DataLinkConn(self.server.port, **kwargs)
        self.addCleanup(conn.close)
        return conn

    def _auth_userpass(self, conn, username, password):
        payload = f"{username}\r{password}".encode("ascii")
        conn.send(f"AUTH USERPASS {len(payload)}", payload)
        return conn.recv()

    def test_write_ip_survives_auth_program_error(self):
        conn = self._conn()

        streamid = f"{unique('IPWR')}/RAW"
        record = ringtest.make_ms2()
        pid = conn.write(streamid, record)
        header, data = conn.read(pid)
        self.assertTrue(header.startswith("PACKET"), header)
        self.assertEqual(data, record)

        header, resp = self._auth_userpass(conn, "erin", "sesame")
        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"Error performing authentication", resp)

        # Write permission granted by RS_WRITE_IP must still be intact.
        record = ringtest.make_ms2()
        pid = conn.write(streamid, record)
        header, data = conn.read(pid)
        self.assertTrue(header.startswith("PACKET"), header)
        self.assertEqual(data, record)


class StreamAuthGateTestCase(unittest.TestCase):
    """RS_AUTH_REQUIRED_FOR_STREAMS gating of DataLink STREAM and SeedLink
    ring configuration, across DataLink, SeedLink v3, and SeedLink v4."""

    BHZ_STREAMID = "FDSN:XX_TEST_00_B_H_Z/MSEED"

    @classmethod
    def setUpClass(cls):
        server = ringtest.Server(protocols="DataLink SeedLink")
        script_path = _write_auth_helper(server.tmp_path)
        server.env_overlay = {
            "RS_AUTH_COMMAND": f"{sys.executable} {script_path}",
            "RS_AUTH_REQUIRED_FOR_STREAMS": "1",
        }
        cls.server = server.start()
        # Deliberately triggered by the v4 AUTH argument-error test below.
        cls.server.ignore_log_patterns += [
            r"Error parsing AUTH: no sub-command",
            r"Error parsing AUTH USERPASS",
            r"Error parsing AUTH JWT",
        ]

        # WRITE is not gated, so seed the backlog over plain DataLink.
        dl = ringtest.DataLinkConn(cls.server.port)
        cls.records = []
        for i in range(4):
            record = ringtest.make_ms2(chan="BHZ", seq=i)
            pktid = dl.write(cls.BHZ_STREAMID, record)
            cls.records.append((pktid, record))
        dl.close()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _dlconn(self, **kwargs):
        """Open a DataLinkConn to the shared server, closed on test end."""
        conn = ringtest.DataLinkConn(self.server.port, **kwargs)
        self.addCleanup(conn.close)
        return conn

    def _slconn(self, **kwargs):
        """Open a SeedLinkConn to the shared server, closed on test end."""
        conn = ringtest.SeedLinkConn(self.server.port, **kwargs)
        self.addCleanup(conn.close)
        return conn

    # -- DataLink -----------------------------------------------------------

    def test_datalink_stream_requires_auth(self):
        conn = self._dlconn()
        header = conn.match(".*")
        self.assertTrue(header.startswith("OK"), header)

        conn.stream()
        header, resp = conn.recv()
        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"Authentication required for streaming", resp)
        self.assertEqual(conn.sock.recv(16), b"")

    def test_datalink_read_requires_auth(self):
        conn = self._dlconn()
        pktid, _ = self.records[0]
        conn.send(f"READ {pktid}")
        header, resp = conn.recv()
        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"Authentication required", resp)
        self.assertEqual(conn.sock.recv(16), b"")

    def test_datalink_read_after_auth(self):
        conn = self._dlconn()
        payload = b"alice\rsesame"
        conn.send(f"AUTH USERPASS {len(payload)}", payload)
        header, _ = conn.recv()
        self.assertTrue(header.startswith("OK"), header)

        pktid, record = self.records[0]
        header, data = conn.read(pktid)
        self.assertTrue(header.startswith("PACKET"), header)
        self.assertEqual(data, record)

    def test_datalink_stream_after_auth(self):
        conn = self._dlconn()
        payload = b"alice\rsesame"
        conn.send(f"AUTH USERPASS {len(payload)}", payload)
        header, _ = conn.recv()
        self.assertTrue(header.startswith("OK"), header)

        first_pktid = self.records[0][0]
        header = conn.position_set(str(first_pktid))
        self.assertTrue(header.startswith("OK"), header)

        conn.stream()
        header, _ = conn.recv()
        self.assertTrue(header.startswith("PACKET"), header)
        conn.endstream()

    # -- SeedLink -------------------------------------------------------

    def test_seedlink_v4_stream_requires_auth(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z"), "OK")
        conn.sendline("END")

        reply = conn.recvline()
        self.assertEqual(reply, "ERROR AUTH Authentication required for streaming")

        conn.sock.settimeout(3)
        self.assertEqual(conn.sock.recv(16), b"")

    def test_seedlink_v4_stream_after_auth(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")
        self.assertEqual(conn.cmd("AUTH USERPASS alice sesame"), "OK")
        self.assertEqual(conn.cmd("STATION XX_TEST"), "OK")
        self.assertEqual(conn.cmd("SELECT 00_B_H_Z"), "OK")

        start_pktid, expected = self.records[0][0], self.records
        self.assertEqual(conn.cmd(f"DATA {start_pktid}"), "OK")
        conn.sendline("END")

        prev_pktid = None
        for pktid, record in expected:
            frame = conn.recv_v4()
            self.assertEqual(frame["kind"], "data")
            self.assertEqual(frame["staid"], "XX_TEST")
            self.assertEqual(frame["pktid"], pktid)
            self.assertEqual(frame["payload"], record)
            if prev_pktid is not None:
                self.assertGreater(frame["pktid"], prev_pktid)
            prev_pktid = frame["pktid"]

        conn.sock.settimeout(2)
        with self.assertRaises(socket.timeout):
            conn.recv_v4()

    def test_seedlink_v4_auth_failure_disconnects(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")

        reply = conn.cmd("AUTH USERPASS alice wrongpass")
        self.assertTrue(reply.startswith("ERROR AUTH"), reply)

        conn.sock.settimeout(3)
        self.assertEqual(conn.sock.recv(16), b"")

    def test_seedlink_v3_cannot_stream(self):
        # SeedLink v3 has no AUTH command, so a fully negotiated v3 session
        # gets the same refusal as an unauthenticated v4 client.
        conn = self._slconn()
        self.assertEqual(conn.cmd("STATION TEST XX"), "OK")
        self.assertEqual(conn.cmd("SELECT 00BHZ"), "OK")
        conn.sendline("END")

        reply = conn.recvline()
        self.assertEqual(reply, "ERROR")

        conn.sock.settimeout(5)
        self.assertEqual(conn.sock.recv(16), b"")

    def test_seedlink_v4_auth_errors_then_success(self):
        conn = self._slconn()
        self.assertEqual(conn.cmd("SLPROTO 4.0"), "OK")

        self.assertEqual(conn.cmd("AUTH"),
                          "ERROR ARGUMENTS AUTH requires a sub-command (USERPASS or JWT)")
        self.assertEqual(conn.cmd("AUTH USERPASS onlyuser"),
                          "ERROR ARGUMENTS AUTH USERPASS requires 2 arguments")
        self.assertEqual(conn.cmd("AUTH JWT"),
                          "ERROR ARGUMENTS AUTH JWT requires 1 argument")
        self.assertTrue(conn.cmd("AUTH NOPE x").startswith("ERROR UNSUPPORTED"))

        self.assertEqual(conn.cmd("AUTH USERPASS alice sesame"), "OK")


class StreamFilterTestCase(unittest.TestCase):
    """allowed_streams / forbidden_streams from the auth program, applied
    as ring-reader filters."""

    ALLOW_STREAMID = "FDSN:XX_ALLOW_00_B_H_Z/MSEED"
    SECRET_STREAMID = "FDSN:XX_SECRET_00_B_H_Z/MSEED"

    @classmethod
    def setUpClass(cls):
        server = ringtest.Server(protocols="DataLink")
        script_path = _write_auth_helper(server.tmp_path)
        server.env_overlay = {
            "RS_AUTH_COMMAND": f"{sys.executable} {script_path}",
        }
        cls.server = server.start()

        # Interleaved backlog for two stations, written without auth.
        dl = ringtest.DataLinkConn(cls.server.port)

        cls.allow_pkts = []
        cls.secret_pkts = []
        for i in range(2):
            allow_record = ringtest.make_ms2(sta="ALLOW", chan="BHZ", seq=i)
            cls.allow_pkts.append((dl.write(cls.ALLOW_STREAMID, allow_record), allow_record))
            secret_record = ringtest.make_ms2(sta="SECRET", chan="BHZ", seq=i + 10)
            cls.secret_pkts.append((dl.write(cls.SECRET_STREAMID, secret_record), secret_record))
        dl.close()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _conn(self, **kwargs):
        """Open a DataLinkConn to the shared server, closed on test end."""
        conn = ringtest.DataLinkConn(self.server.port, **kwargs)
        self.addCleanup(conn.close)
        return conn

    def _auth_userpass(self, conn, username, password):
        payload = f"{username}\r{password}".encode("ascii")
        conn.send(f"AUTH USERPASS {len(payload)}", payload)
        return conn.recv()

    def test_allowed_streams_filter(self):
        conn = self._conn()
        header, _ = self._auth_userpass(conn, "carol", "sesame")
        self.assertTrue(header.startswith("OK"), header)

        header = conn.position_set("EARLIEST")
        self.assertTrue(header.startswith("OK"), header)
        conn.stream()

        received = []
        for _ in range(2):
            header, _ = conn.recv()
            self.assertTrue(header.startswith("PACKET"), header)
            received.append(header.split()[1])

        self.assertEqual(received, [self.ALLOW_STREAMID, self.ALLOW_STREAMID])

        conn.sock.settimeout(1.5)
        with self.assertRaises(socket.timeout):
            conn.recv()

    def test_forbidden_streams_filter(self):
        conn = self._conn()
        header, _ = self._auth_userpass(conn, "dave", "sesame")
        self.assertTrue(header.startswith("OK"), header)

        header = conn.position_set("EARLIEST")
        self.assertTrue(header.startswith("OK"), header)
        conn.stream()

        received = []
        for _ in range(2):
            header, _ = conn.recv()
            self.assertTrue(header.startswith("PACKET"), header)
            received.append(header.split()[1])

        self.assertEqual(received, [self.ALLOW_STREAMID, self.ALLOW_STREAMID])

        conn.sock.settimeout(1.5)
        with self.assertRaises(socket.timeout):
            conn.recv()

    def test_read_allowed_streams_filter(self):
        conn = self._conn()
        header, _ = self._auth_userpass(conn, "carol", "sesame")
        self.assertTrue(header.startswith("OK"), header)

        pktid, record = self.allow_pkts[0]
        header, data = conn.read(pktid)
        self.assertTrue(header.startswith("PACKET"), header)
        self.assertEqual(data, record)

        secret_pktid = self.secret_pkts[0][0]
        # READ of a filtered packet is indistinguishable from a missing one.
        conn.send(f"READ {secret_pktid}")
        header, resp = conn.recv()
        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"not found", resp)

    def test_read_forbidden_streams_filter(self):
        conn = self._conn()
        header, _ = self._auth_userpass(conn, "dave", "sesame")
        self.assertTrue(header.startswith("OK"), header)

        pktid, record = self.allow_pkts[0]
        header, data = conn.read(pktid)
        self.assertTrue(header.startswith("PACKET"), header)
        self.assertEqual(data, record)

        secret_pktid = self.secret_pkts[0][0]
        # READ of a filtered packet is indistinguishable from a missing one.
        conn.send(f"READ {secret_pktid}")
        header, resp = conn.recv()
        self.assertTrue(header.startswith("ERROR"), header)
        self.assertIn(b"not found", resp)


if __name__ == "__main__":
    unittest.main()
