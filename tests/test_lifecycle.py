"""Server lifecycle and configuration tests for ringserver.

Exercises process start/stop, ring persistence across restarts, ring
geometry changes on restart, ring packet size rounding, the INFO
response cache TTL, JSON usage logs, TLS-wrapped DataLink, and the
miniSEED directory scanner. Each test owns its server configuration
and any ring/log/scan directories it needs.
"""

import glob
import json
import os
import re
import signal
import socket
import ssl
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ringtest


class LifecycleTestCase(unittest.TestCase):

    def test_clean_shutdown(self):
        server = ringtest.Server().start()

        dl = ringtest.DataLinkConn(server.port)
        dl.write("LIFECYCLE/RAW", ringtest.make_ms2(seq=1))
        dl.close()

        # The log file lives in the server's tempdir, which stop() removes
        # once its checks pass, so capture the termination message before
        # calling stop() rather than after.
        server.proc.send_signal(signal.SIGTERM)
        server.proc.wait(timeout=10)
        self.assertIn("Received termination signal", server.log_text())

        server.stop()

    def test_ring_persistence(self):
        with tempfile.TemporaryDirectory(prefix="ringtest-persist-") as ring_dir:
            payloads = [ringtest.make_ms2(seq=i, nsamples=10) for i in range(1, 6)]
            pktids = []

            server = ringtest.Server(volatile=False, ring_dir=ring_dir,
                                      ring_size="1M", pkt_size=512).start()
            dl = ringtest.DataLinkConn(server.port)
            for i, payload in enumerate(payloads, start=1):
                pktids.append(dl.write(f"PERSIST_{i}/RAW", payload))
            dl.close()
            server.stop()

            # Second server, identical ring geometry, same directory: the
            # existing ring packet buffer file should be recovered as-is.
            server2 = ringtest.Server(volatile=False, ring_dir=ring_dir,
                                       ring_size="1M", pkt_size=512).start()
            dl2 = ringtest.DataLinkConn(server2.port)
            for pktid, payload in zip(pktids, payloads):
                header, body = dl2.read(pktid)
                self.assertTrue(header.startswith("PACKET"), header)
                self.assertEqual(body, payload)
            dl2.close()
            server2.stop()

    def test_ring_reinit_on_pktsize_change(self):
        # Growing MaxPacketSize on restart is rebuildable: the ring is
        # recreated but existing packets are migrated forward, so it does
        # not exercise the "old packets gone" behavior below. Shrinking it
        # is not rebuildable, so verify that direction instead: the ring is
        # reset and old contents are discarded.
        with tempfile.TemporaryDirectory(prefix="ringtest-reinit-") as ring_dir:
            server = ringtest.Server(volatile=False, ring_dir=ring_dir,
                                      ring_size="1M", pkt_size=600).start()
            dl = ringtest.DataLinkConn(server.port)
            old_pktid = dl.write("REINIT/RAW", ringtest.make_ms2(seq=1))
            dl.close()
            server.stop()

            server2 = ringtest.Server(volatile=False, ring_dir=ring_dir,
                                       ring_size="1M", pkt_size=500).start()
            log_text = server2.log_text()
            self.assertIn("Packet size change", log_text)
            self.assertIn("Resetting ring packet buffer", log_text)

            dl2 = ringtest.DataLinkConn(server2.port)
            header, payload = dl2.read(old_pktid)
            self.assertTrue(header.startswith("ERROR"), header)
            self.assertIn("not found", payload.decode("ascii"))
            dl2.close()
            server2.stop()

    def test_max_packet_size_rounding(self):
        server = ringtest.Server(pkt_size=500).start()
        dl = ringtest.DataLinkConn(server.port)

        match = re.search(r"PACKETSIZE:(\d+)", dl.id_response)
        self.assertIsNotNone(match, dl.id_response)
        reported = int(match.group(1))

        # MaxPacketSize is rounded up internally so ring packet slots stay
        # 8-byte aligned; verify the invariant rather than a hard-coded
        # constant, since the exact ring packet header size is an
        # implementation detail.
        self.assertGreaterEqual(reported, 500)
        self.assertEqual((reported + 112) % 8, 0)

        pktid = dl.write("ROUND/RAW", b"x" * reported)
        self.assertIsNotNone(pktid)

        with self.assertRaises(RuntimeError) as ctx:
            dl.write("ROUND/RAW", b"x" * (reported + 1))
        self.assertIn("too large", str(ctx.exception))

        dl.close()
        server.stop()

    def test_info_cache_ttl(self):
        # TTL=5: a second /streamids fetch immediately after adding a new
        # stream should still return the cached (stale) document.
        server_a = ringtest.Server(env={"RS_INFO_CACHE_TTL": "5"}).start()
        try:
            dl = ringtest.DataLinkConn(server_a.port)
            dl.write("CACHE_A/RAW", ringtest.make_ms2(seq=1))

            status, _, body = ringtest.http_get(server_a.port, "/streamids")
            self.assertEqual(status, 200)
            self.assertIn("CACHE_A", body.decode())

            dl.write("CACHE_B/RAW", ringtest.make_ms2(seq=2))
            status, _, body = ringtest.http_get(server_a.port, "/streamids")
            self.assertEqual(status, 200)
            self.assertNotIn("CACHE_B", body.decode())

            dl.close()
        finally:
            server_a.stop()

        # TTL=0 (rig default): no caching, the new stream shows up right away.
        server_b = ringtest.Server().start()
        try:
            dl = ringtest.DataLinkConn(server_b.port)
            dl.write("CACHE_A/RAW", ringtest.make_ms2(seq=1))
            ringtest.http_get(server_b.port, "/streamids")

            dl.write("CACHE_B/RAW", ringtest.make_ms2(seq=2))
            status, _, body = ringtest.http_get(server_b.port, "/streamids")
            self.assertEqual(status, 200)
            self.assertIn("CACHE_B", body.decode())

            dl.close()
        finally:
            server_b.stop()

    def test_usage_logs(self):
        streamid = "FDSN:XX_TEST_00_B_H_Z/MSEED"

        with tempfile.TemporaryDirectory(prefix="ringtest-usage-") as logdir:
            server = ringtest.Server(
                protocols="DataLink SeedLink",
                extra_args=["-U", str(logdir), "-Uj"]).start()
            try:
                # Subscribe over SeedLink first: STATION/DATA/END negotiates
                # a live position at the next packet, so records written
                # afterwards arrive as streamed data (classic protocol has
                # no historical "give me everything" request without a
                # known sequence number or start time).
                sl = ringtest.SeedLinkConn(server.port)
                self.assertTrue(sl.cmd("STATION TEST XX").startswith("OK"))
                self.assertTrue(sl.cmd("DATA").startswith("OK"))
                sl.sendline("END")

                # END has no reply (it just starts the data flow), so give
                # the server a brief moment to reach its "next packet"
                # position before writing the records it should stream.
                time.sleep(0.2)

                dl = ringtest.DataLinkConn(server.port)
                for seq in range(1, 6):
                    dl.write(streamid, ringtest.make_ms2(chan="BHZ", seq=seq))
                dl.close()

                received = 0
                for _ in range(5):
                    frame = sl.recv_v3()
                    self.assertEqual(frame["kind"], "data")
                    received += 1
                sl.close()
            finally:
                server.stop()

            rx_files = glob.glob(os.path.join(logdir, "rxlog-*.jsonl"))
            tx_files = glob.glob(os.path.join(logdir, "txlog-*.jsonl"))
            access_files = glob.glob(os.path.join(logdir, "accesslog-*.jsonl"))
            self.assertTrue(rx_files, "no rxlog file found")
            self.assertTrue(tx_files, "no txlog file found")
            self.assertTrue(access_files, "no accesslog file found")

            def load_lines(paths):
                lines = []
                for path in paths:
                    with open(path) as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                lines.append(json.loads(line))
                return lines

            rx_records = load_lines(rx_files)
            tx_records = load_lines(tx_files)
            access_records = load_lines(access_files)

            rx_hit = None
            for rec in rx_records:
                if rec.get("transfer_direction") == "RX":
                    for stream in rec.get("streams", []):
                        if stream.get("stream_id") == streamid and stream.get("bytes", 0) > 0:
                            rx_hit = (rec, stream)
                            break
                if rx_hit:
                    break
            self.assertIsNotNone(rx_hit, f"no RX record for {streamid} in {rx_records}")

            tx_hit = None
            for rec in tx_records:
                if rec.get("transfer_direction") == "TX":
                    for stream in rec.get("streams", []):
                        if stream.get("stream_id") == streamid and stream.get("bytes", 0) > 0:
                            tx_hit = (rec, stream)
                            break
                if tx_hit:
                    break
            self.assertIsNotNone(tx_hit, f"no TX record for {streamid} in {tx_records}")

            events = {rec.get("event") for rec in access_records}
            self.assertIn("connect", events)
            self.assertIn("disconnect", events)

    def test_tls_datalink(self):
        server = ringtest.Server(
            protocols="DataLink",
            listen_flags="TLS",
            env={
                "RS_TLS_CERT_FILE": str(ringtest.DATA_DIR / "test-cert.pem"),
                "RS_TLS_KEY_FILE": str(ringtest.DATA_DIR / "test-key.pem"),
            }).start()

        # The readiness probe in Server.start() is a plain TCP connect/close,
        # which aborts before any TLS handshake and logs a benign error.
        server.ignore_log_patterns.append(r"Error negotiating TLS")

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        raw_sock = socket.create_connection(("127.0.0.1", server.port), timeout=10)
        tls_sock = ctx.wrap_socket(raw_sock)

        dl = ringtest.DataLinkConn(0, sock=tls_sock)
        self.assertIn("DataLink", dl.id_response)

        payload = ringtest.make_ms2(seq=1)
        pktid = dl.write("TLS_STREAM/RAW", payload)
        header, body = dl.read(pktid)
        self.assertTrue(header.startswith("PACKET"), header)
        self.assertEqual(body, payload)

        dl.close()
        server.stop()

    def test_mseedscan(self):
        with tempfile.TemporaryDirectory(prefix="ringtest-scan-") as scandir:
            server = ringtest.Server(
                protocols="DataLink SeedLink HTTP",
                extra_args=["-MSSCAN", str(scandir)]).start()
            try:
                records = b"".join(
                    ringtest.make_ms2(chan="BHZ", seq=seq) for seq in (1, 2, 3))

                tmp_path = os.path.join(scandir, ".tmp")
                final_path = os.path.join(scandir, "test.mseed")
                with open(tmp_path, "wb") as f:
                    f.write(records)
                os.rename(tmp_path, final_path)

                expected_id = None
                deadline = time.time() + 20
                while time.time() < deadline and expected_id is None:
                    status, _, body = ringtest.http_get(server.port, "/streamids")
                    if status == 200:
                        for line in body.decode().splitlines():
                            if "XX_TEST" in line:
                                expected_id = line.strip()
                                break
                    if expected_id is None:
                        time.sleep(0.5)

                if expected_id is None:
                    self.fail("mseedscan did not surface a stream for the "
                              "scanned file within 20s; server log:\n"
                              + server.log_text())

                # The reply's packet ID is the earliest packet in the ring;
                # READ it directly to verify the first scanned record.
                dl = ringtest.DataLinkConn(server.port)
                match_header = dl.match(f"^{re.escape(expected_id)}$")
                self.assertTrue(match_header.startswith("OK"), match_header)
                pos_header = dl.position_set("EARLIEST")
                self.assertTrue(pos_header.startswith("OK"), pos_header)
                earliest_pktid = int(pos_header.split()[1])

                header, payload = dl.read(earliest_pktid)
                self.assertTrue(header.startswith("PACKET"), header)
                self.assertEqual(len(payload), 512)
                self.assertEqual(payload, records[:512])
                dl.close()
            finally:
                server.stop()


if __name__ == "__main__":
    unittest.main()
