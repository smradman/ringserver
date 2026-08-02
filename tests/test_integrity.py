"""Data-integrity and concurrency stress tests for the ring buffer.

These tests guard the ring-buffer seqlock: a reader must never receive a
torn packet (header from one write mixed with payload from another) while
a writer is concurrently overwriting slots, including while the ring
wraps and a slow reader gets lapped.

Payload convention: each 400-byte payload is built from a "SEQ%08d|"
marker repeated to fill the length, so a delivered payload is
self-describing -- the expected bytes can be regenerated from the
sequence number embedded in the payload itself and compared byte-exact
against what was actually received.
"""
import socket
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ringtest

STREAMID = "XX_TEST/RAW"
PAYLOAD_LEN = 400


def make_payload(seq):
    """Build a self-describing 400-byte payload for sequence `seq`."""
    base = f"SEQ{seq:08d}|".encode()
    return (base * (PAYLOAD_LEN // len(base) + 1))[:PAYLOAD_LEN]


class IntegrityTests(unittest.TestCase):
    """Ring-buffer read/write integrity under ordinary and stress conditions."""

    def setUp(self):
        self.server = ringtest.Server(protocols="DataLink", ring_size="1M",
                                       pkt_size=512)
        self.server.start()

    def tearDown(self):
        self.server.stop()

    def test_write_readback_ordered(self):
        n = 200
        writer = ringtest.DataLinkConn(self.server.port)
        for seq in range(n):
            pktid = writer.write(STREAMID, make_payload(seq))
            self.assertIsNotNone(pktid, f"seq {seq} not acked")

        reader = ringtest.DataLinkConn(self.server.port)
        header = reader.position_set("EARLIEST")
        self.assertTrue(header.startswith("OK"), header)
        reader.stream()

        # POSITION SET EARLIEST positions AT the earliest packet; streaming
        # resumes with the packet AFTER it, so the first delivered seq is 1
        # and the count is n - 1.
        expected_count = n - 1
        got = 0
        last_seq = None
        while got < expected_count:
            header, payload = reader.recv()
            self.assertTrue(header.startswith("PACKET"), header)
            parts = header.split()
            self.assertEqual(parts[1], STREAMID)
            seq = int(payload[3:11])
            self.assertEqual(payload, make_payload(seq),
                              f"torn/corrupt payload at seq {seq}")
            if last_seq is None:
                self.assertEqual(seq, 1, "unexpected first delivered seq")
            else:
                self.assertEqual(seq, last_seq + 1, "sequence gap")
            last_seq = seq
            got += 1

        reader.endstream()
        reader.close()
        writer.close()

    def test_concurrent_write_stream(self):
        n = 200
        writer = ringtest.DataLinkConn(self.server.port)
        reader = ringtest.DataLinkConn(self.server.port)

        # Seed the ring with one packet before positioning: positioning
        # LATEST against a genuinely empty ring only resolves to a real
        # packet once the server notices data, which races the writer
        # thread's first write. Seeding first makes positioning
        # deterministic.
        self.assertIsNotNone(writer.write(STREAMID, make_payload(-1)))
        header = reader.position_set("LATEST")
        self.assertTrue(header.startswith("OK"), header)
        reader.stream()

        write_failures = []

        def do_write():
            try:
                for seq in range(n):
                    pktid = writer.write(STREAMID, make_payload(seq))
                    if pktid is None:
                        write_failures.append(f"seq {seq} not acked")
                        return
            except Exception as exc:
                write_failures.append(f"write exception: {exc!r}")

        writer_thread = threading.Thread(target=do_write)
        writer_thread.start()

        got = 0
        last_seq = None
        while got < n:
            header, payload = reader.recv()
            self.assertTrue(header.startswith("PACKET"), header)
            seq = int(payload[3:11])
            self.assertEqual(payload, make_payload(seq),
                              f"torn/corrupt payload at seq {seq}")
            if last_seq is None:
                self.assertEqual(seq, 0, "unexpected first delivered seq")
            else:
                self.assertEqual(seq, last_seq + 1, "sequence gap")
            last_seq = seq
            got += 1

        writer_thread.join(timeout=30)
        self.assertFalse(writer_thread.is_alive(), "writer thread did not finish")
        self.assertEqual(write_failures, [])

        reader.endstream()
        reader.close()
        writer.close()

    def test_ring_wrap_integrity(self):
        # A 1M ring at pkt_size 512 holds ~1600 packets, so 5000 writes
        # wrap the ring roughly 3 times while the reader streams.
        n_wrap = 5000
        writer = ringtest.DataLinkConn(self.server.port)
        reader = ringtest.DataLinkConn(self.server.port)

        # Seed the ring with one packet before positioning: positioning
        # EARLIEST against a genuinely empty ring only resolves to a real
        # packet once the server notices data, which races the writer
        # thread's first write. Seeding first makes positioning
        # deterministic.
        self.assertIsNotNone(writer.write(STREAMID, make_payload(-1)))
        header = reader.position_set("EARLIEST")
        self.assertTrue(header.startswith("OK"), header)
        reader.stream()

        write_failures = []
        writer_done = threading.Event()

        def do_write():
            try:
                for seq in range(n_wrap):
                    pktid = writer.write(STREAMID, make_payload(seq))
                    if pktid is None:
                        write_failures.append(f"seq {seq} not acked")
                        return
            except Exception as exc:
                write_failures.append(f"write exception: {exc!r}")
            finally:
                writer_done.set()

        writer_thread = threading.Thread(target=do_write)
        writer_thread.start()

        # The reader may be lapped by the faster writer -- sequence gaps
        # are legal and it may end up with an arbitrary intact subset.
        # What must never happen is a torn payload or a size mismatch.
        reader.sock.settimeout(3)
        got = 0
        last_seq = None
        deadline = time.time() + 90
        while time.time() < deadline:
            try:
                header, payload = reader.recv()
            except socket.timeout:
                if writer_done.is_set():
                    break
                continue
            self.assertTrue(header.startswith("PACKET"), header)
            parts = header.split()
            size = int(parts[6])
            self.assertEqual(size, len(payload),
                              "header size field does not match payload length")
            self.assertTrue(payload.startswith(b"SEQ"),
                             f"corrupt payload start: {payload[:20]!r}")
            seq = int(payload[3:11])
            self.assertEqual(payload, make_payload(seq),
                              f"torn/corrupt payload at seq {seq}")
            if last_seq is not None:
                self.assertGreater(seq, last_seq, "sequence not increasing")
            last_seq = seq
            got += 1

        writer_thread.join(timeout=30)
        self.assertFalse(writer_thread.is_alive(), "writer thread did not finish")
        self.assertEqual(write_failures, [])
        self.assertGreater(got, 0, "reader received no packets during wrap")

        # Liveness: a lapped reader must still receive fresh packets intact.
        reader.sock.settimeout(10)
        liveness_seq = n_wrap
        pktid = writer.write(STREAMID, make_payload(liveness_seq))
        self.assertIsNotNone(pktid, "liveness write not acked")
        header, payload = reader.recv()
        self.assertTrue(header.startswith("PACKET"), header)
        self.assertEqual(payload, make_payload(liveness_seq))

        reader.endstream()
        reader.close()

        # A fresh connection positioned at EARLIEST must see every
        # surviving packet in the ring, each one byte-exact and in order.
        subset_reader = ringtest.DataLinkConn(self.server.port)
        header = subset_reader.position_set("EARLIEST")
        self.assertTrue(header.startswith("OK"), header)
        subset_reader.stream()
        subset_reader.sock.settimeout(3)

        subset_count = 0
        last_seq = None
        while True:
            try:
                header, payload = subset_reader.recv()
            except socket.timeout:
                break
            self.assertTrue(header.startswith("PACKET"), header)
            seq = int(payload[3:11])
            self.assertEqual(payload, make_payload(seq),
                              f"torn/corrupt payload at seq {seq}")
            if last_seq is not None:
                self.assertGreater(seq, last_seq, "sequence not increasing")
            last_seq = seq
            subset_count += 1

        self.assertGreater(subset_count, 0,
                            "no surviving packets found in ring after wrap")

        subset_reader.endstream()
        subset_reader.close()
        writer.close()

    def test_monotonic_pktids(self):
        n = 500
        writer = ringtest.DataLinkConn(self.server.port)

        last_pktid = None
        last_payload = None
        for seq in range(n):
            payload = make_payload(seq)
            pktid = writer.write(STREAMID, payload)
            self.assertIsNotNone(pktid, f"seq {seq} not acked")
            if last_pktid is not None:
                self.assertGreater(pktid, last_pktid,
                                    f"pktid did not increase at seq {seq}")
            last_pktid = pktid
            last_payload = payload

        header, payload = writer.read(last_pktid)
        self.assertTrue(header.startswith("PACKET"), header)
        self.assertEqual(payload, last_payload)

        writer.close()


if __name__ == "__main__":
    unittest.main()
