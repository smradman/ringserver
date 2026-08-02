"""Shared test rig for the ringserver end-to-end test suite.

This module provides the building blocks used by the individual test
cases: a helper to build a valid miniSEED 2 record, a context manager
that launches and supervises a ringserver process, and small protocol
client classes for DataLink, SeedLink, HTTP and WebSocket.  Python 3
standard library only -- no test cases live here.
"""

import base64
import hashlib
import http.client
import os
import re
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SERVER_BIN = REPO_ROOT / "ringserver"
DATA_DIR = Path(__file__).resolve().parent / "data"

WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def free_port():
    """Return an available TCP port on 127.0.0.1."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make_ms2(net="XX", sta="TEST", loc="00", chan="BHZ", seq=1,
             starttime=None, nsamples=100):
    """Build a 512-byte, big-endian miniSEED 2 data record.

    The record has a valid fixed section header and a Blockette 1000
    (data-only SEED encoding, i.e. 16-bit integers) followed by
    deterministic sample data derived from `seq`.
    """
    if starttime is None:
        starttime = time.time()
    nsamples = min(nsamples, 224)

    record = bytearray(512)

    record[0:6] = b"%06d" % (seq % 1000000)
    record[6:7] = b"D"
    record[7:8] = b" "
    record[8:13] = sta.ljust(5)[:5].encode("ascii")
    record[13:15] = loc.ljust(2)[:2].encode("ascii")
    record[15:18] = chan.ljust(3)[:3].encode("ascii")
    record[18:20] = net.ljust(2)[:2].encode("ascii")

    gm = time.gmtime(starttime)
    frac_seconds = starttime - int(starttime)
    fract = int(round(frac_seconds * 10000))
    struct.pack_into(">HHBBBBH", record, 20,
                      gm.tm_year, gm.tm_yday, gm.tm_hour, gm.tm_min,
                      gm.tm_sec, 0, fract)

    struct.pack_into(">H", record, 30, nsamples)
    struct.pack_into(">h", record, 32, 20)
    struct.pack_into(">h", record, 34, 1)

    record[36] = 0  # activity flags
    record[37] = 0  # io flags
    record[38] = 0  # quality flags
    record[39] = 1  # number of blockettes

    struct.pack_into(">i", record, 40, 0)
    struct.pack_into(">H", record, 44, 64)
    struct.pack_into(">H", record, 46, 48)

    struct.pack_into(">HHBBBB", record, 48, 1000, 0, 1, 1, 9, 0)

    for i in range(nsamples):
        sample = (seq * 100 + i) % 32000
        struct.pack_into(">h", record, 64 + i * 2, sample)

    return bytes(record)


_CRC32C_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0x82F63B78 if _c & 1 else _c >> 1
    _CRC32C_TABLE.append(_c)


def crc32c(data, crc=0):
    """CRC-32C (Castagnoli), as used by miniSEED 3."""
    crc ^= 0xFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ _CRC32C_TABLE[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFFFFFF


def make_ms3(net="XX", sta="TEST", loc="00", chan="BHZ", seq=1,
             starttime=None, nsamples=100):
    """Build a little-endian miniSEED 3 data record (40-byte fixed header
    + FDSN Source ID + 16-bit integer payload) with a valid CRC-32C.
    Record length is 40 + len(sid) + 2*nsamples (261 bytes for defaults).
    """
    if starttime is None:
        starttime = time.time()

    sid = "FDSN:%s_%s_%s_%s" % (net, sta, loc, "_".join(chan))
    sid_bytes = sid.encode("ascii")

    payload = b"".join(
        struct.pack("<h", (seq * 100 + i) % 32000) for i in range(nsamples))

    gm = time.gmtime(starttime)
    nsec = min(int(round((starttime - int(starttime)) * 1e9)), 999_999_999)

    header = struct.pack(
        "<2sBBIHHBBBBdIIBBHI",
        b"MS", 3,            # record indicator, format version
        0,                   # flags
        nsec,                # nanosecond
        gm.tm_year, gm.tm_yday, gm.tm_hour, gm.tm_min, gm.tm_sec,
        1,                   # data encoding: 16-bit integers
        20.0,                # sample rate (Hz)
        nsamples,            # number of samples
        0,                   # CRC placeholder (computed over zeroed field)
        1,                   # publication version
        len(sid_bytes),      # length of identifier
        0,                   # length of extra headers
        len(payload))        # length of data payload

    record = bytearray(header + sid_bytes + payload)
    struct.pack_into("<I", record, 28, crc32c(record))
    return bytes(record)


class Server:
    """Manages a ringserver subprocess for the duration of a test.

    Usable as a context manager: entering calls `start()`, exiting
    calls `stop()`.
    """

    def __init__(self, protocols="DataLink SeedLink HTTP", port=None,
                 volatile=True, ring_dir=None, ring_size="1M", pkt_size=512,
                 env=None, extra_args=None, server_id=None, listen_flags="",
                 check_log_errors=True):
        self.protocols = protocols
        self.port = port if port is not None else free_port()
        self.volatile = volatile
        self.ring_size = ring_size
        self.pkt_size = pkt_size
        self.env_overlay = env
        self.extra_args = extra_args or []
        self.server_id = server_id
        self.listen_flags = listen_flags
        self.check_log_errors = check_log_errors
        self.ignore_log_patterns = []

        self._tmpdir = tempfile.TemporaryDirectory(prefix="ringtest-")
        self.tmp_path = Path(self._tmpdir.name)
        self.ring_dir = Path(ring_dir) if ring_dir else self.tmp_path / "ring"
        self.logfile = self.tmp_path / "server.log"

        self.proc = None

    def _build_env(self):
        env = dict(os.environ)
        env["RS_RESOLVE_HOSTNAMES"] = "0"
        env["RS_INFO_CACHE_TTL"] = "0"
        if self.env_overlay:
            for key, value in self.env_overlay.items():
                if value is None:
                    env.pop(key, None)
                else:
                    env[key] = value
        return env

    def _build_argv(self):
        listen = f"{self.port} {self.protocols}"
        if self.listen_flags:
            listen += " " + self.listen_flags

        argv = [str(SERVER_BIN), "-Rp", str(self.pkt_size), "-L", listen, "-vv"]

        if self.volatile:
            argv.append("-VOLATILE")
        else:
            self.ring_dir.mkdir(parents=True, exist_ok=True)
            argv += ["-Rd", str(self.ring_dir)]

        argv += ["-Rs", str(self.ring_size)]

        if self.server_id:
            argv += ["-I", self.server_id]

        argv += list(self.extra_args)

        return argv

    def start(self):
        """Launch the server and wait until it accepts connections."""
        argv = self._build_argv()
        env = self._build_env()

        with open(self.logfile, "wb") as log:
            self.proc = subprocess.Popen(
                argv, stdout=log, stderr=subprocess.STDOUT, env=env)

        deadline = time.time() + 10
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"server exited early (code {self.proc.returncode}):\n"
                    f"{self.log_text()}")
            try:
                sock = socket.create_connection(("127.0.0.1", self.port), 0.25)
                sock.close()
                return self
            except OSError:
                time.sleep(0.05)

        self.proc.kill()
        raise RuntimeError(f"server did not start listening in time:\n"
                            f"{self.log_text()}")

    def log_text(self):
        """Return the captured stdout+stderr log contents."""
        try:
            return self.logfile.read_text(errors="replace")
        except OSError:
            return ""

    def stop(self, expect_exit=0):
        """Terminate the server and verify a clean exit.

        Sends SIGTERM, waits up to 10 seconds, and asserts the process
        exit code matches `expect_exit`.  If `check_log_errors` is set,
        also scans the log for error lines (lines matching any pattern
        in `ignore_log_patterns` are excluded).
        """
        try:
            if self.proc is not None and self.proc.poll() is None:
                self.proc.send_signal(signal.SIGTERM)
                try:
                    self.proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=10)
                    raise RuntimeError(
                        f"server did not exit after SIGTERM, killed:\n"
                        f"{self.log_text()}")

            if self.proc is not None:
                returncode = self.proc.returncode
                if returncode != expect_exit:
                    raise AssertionError(
                        f"server exited with code {returncode}, "
                        f"expected {expect_exit}:\n{self.log_text()}")

            if self.check_log_errors:
                log_text = self.log_text()
                bad_lines = []
                for line in log_text.splitlines():
                    if "Error" not in line and "error:" not in line:
                        continue
                    if any(re.search(pat, line)
                           for pat in self.ignore_log_patterns):
                        continue
                    bad_lines.append(line)
                if bad_lines:
                    raise AssertionError(
                        "server log contains error lines:\n" +
                        "\n".join(bad_lines))
        finally:
            self._tmpdir.cleanup()

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            try:
                self.stop()
            except Exception:
                pass
            return False
        self.stop()
        return False


def _recvall(recv_func, n):
    """Read exactly n bytes using a recv(bufsize)-style callable."""
    data = b""
    while len(data) < n:
        chunk = recv_func(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed while reading data")
        data += chunk
    return data


class DataLinkConn:
    """A DataLink protocol client connection."""

    def __init__(self, port, host="127.0.0.1", timeout=10, sock=None,
                 send_id=True):
        if sock is not None:
            self.sock = sock
        else:
            self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)

        self.id_response = None
        if send_id:
            self.send("ID ringtest.py")
            header, _ = self.recv()
            self.id_response = header

    def send(self, header, payload=b""):
        """Send one DataLink message: preheader + header + payload."""
        hbytes = header.encode("ascii")
        if len(hbytes) > 255:
            raise ValueError("DataLink header too long")
        self.sock.sendall(b"DL" + bytes([len(hbytes)]) + hbytes + payload)

    def recv(self):
        """Receive one DataLink message, returning (header, payload)."""
        preheader = _recvall(self.sock.recv, 3)
        if preheader[0:2] != b"DL":
            raise RuntimeError(f"bad DataLink preheader: {preheader!r}")
        hlen = preheader[2]
        header = _recvall(self.sock.recv, hlen).decode("ascii") if hlen else ""
        parts = header.split()

        size = 0
        if parts and parts[0] == "PACKET":
            size = int(parts[6])
        elif parts and parts[0] in ("OK", "ERROR"):
            size = int(parts[2])
        elif parts and parts[0] == "INFO":
            size = int(parts[2])

        payload = _recvall(self.sock.recv, size) if size else b""
        return header, payload

    def write(self, streamid, payload, flags="A", datastart=None, dataend=None):
        """Send a WRITE request; return the pktid if acked, else None."""
        now_us = int(time.time() * 1_000_000)
        if datastart is None:
            datastart = now_us
        if dataend is None:
            dataend = now_us + 1000

        self.send(f"WRITE {streamid} {datastart} {dataend} {flags} {len(payload)}",
                  payload)

        if "A" not in flags:
            return None

        header, resp = self.recv()
        if not header.startswith("OK"):
            raise RuntimeError(f"WRITE failed: {header} {resp!r}")
        return int(header.split()[1])

    def position_set(self, what):
        """Send POSITION SET <EARLIEST|LATEST|pktid>; return the reply header."""
        self.send(f"POSITION SET {what}")
        header, _ = self.recv()
        return header

    def position_after(self, time_us):
        """Send POSITION AFTER <time_us>; return the reply header."""
        self.send(f"POSITION AFTER {time_us}")
        header, _ = self.recv()
        return header

    def match(self, pattern=None):
        """Send MATCH <pattern>, or bare MATCH to clear; return the reply header."""
        if pattern is None:
            self.send("MATCH")
        else:
            data = pattern.encode("ascii")
            self.send(f"MATCH {len(data)}", data)
        header, _ = self.recv()
        return header

    def reject(self, pattern=None):
        """Send REJECT <pattern>, or bare REJECT to clear; return the reply header."""
        if pattern is None:
            self.send("REJECT")
        else:
            data = pattern.encode("ascii")
            self.send(f"REJECT {len(data)}", data)
        header, _ = self.recv()
        return header

    def read(self, pktid):
        """Send READ <pktid>; return the raw (header, payload) reply."""
        self.send(f"READ {pktid}")
        return self.recv()

    def stream(self):
        """Send STREAM; no reply is expected until packets/ENDSTREAM arrive."""
        self.send("STREAM")

    def endstream(self):
        """Send ENDSTREAM and discard packets until the ENDSTREAM reply."""
        self.send("ENDSTREAM")
        while True:
            header, _ = self.recv()
            if header.startswith("ENDSTREAM"):
                return header

    def info(self, itype, match=None):
        """Send INFO <itype>; return (header, parsed XML root element)."""
        cmd = f"INFO {itype}"
        if match is not None:
            cmd += f" {match}"
        self.send(cmd)
        header, payload = self.recv()
        root = ET.fromstring(payload.decode("utf-8"))
        return header, root

    def close(self):
        self.sock.close()


class SeedLinkConn:
    """A SeedLink protocol client connection (v3 and v4 framing)."""

    def __init__(self, port, host="127.0.0.1", timeout=10, sock=None):
        if sock is not None:
            self.sock = sock
        else:
            self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self._buf = b""

    def _recv_exact(self, n):
        while len(self._buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("connection closed while reading data")
            self._buf += chunk
        data = self._buf[:n]
        self._buf = self._buf[n:]
        return data

    def sendline(self, line):
        """Send one SeedLink command line, terminated with \\r\\n."""
        self.sock.sendall(line.encode("ascii") + b"\r\n")

    def recvline(self):
        """Read one \\r\\n-terminated line, returning it stripped."""
        while b"\r\n" not in self._buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("connection closed while reading a line")
            self._buf += chunk
        line, self._buf = self._buf.split(b"\r\n", 1)
        return line.decode("ascii", errors="replace")

    def cmd(self, line):
        """Send a command line and return its single-line reply."""
        self.sendline(line)
        return self.recvline()

    def hello(self):
        """Send HELLO; return the (id_line, description_line) reply pair."""
        self.sendline("HELLO")
        return self.recvline(), self.recvline()

    def recv_v3(self):
        """Read one v3 frame: data record, INFO chunk, or stream end."""
        prefix = self._recv_exact(3)
        if prefix == b"END":
            return {"kind": "end", "seq": None, "record": None}

        rest = self._recv_exact(5)
        header = prefix + rest

        if header[0:2] == b"SL" and header[2:3] != b"I":
            seq = int(header[2:8], 16)
            record = self._recv_exact(512)
            return {"kind": "data", "seq": seq, "record": record}
        elif header == b"SLINFO *":
            record = self._recv_exact(512)
            return {"kind": "info", "seq": None, "record": record}
        elif header == b"SLINFO  ":
            record = self._recv_exact(512)
            return {"kind": "info_end", "seq": None, "record": record}
        else:
            raise RuntimeError(f"unrecognized SeedLink v3 header: {header!r}")

    def recv_v4(self):
        """Read one v4 frame: data/INFO packet, or stream end."""
        prefix = self._recv_exact(2)
        if prefix == b"EN":
            self._recv_exact(1)  # consume the trailing "D" of "END"
            return {"kind": "end", "format": None, "subformat": None,
                    "pktid": None, "staid": None, "payload": None}
        if prefix != b"SE":
            raise RuntimeError(f"unrecognized SeedLink v4 header: {prefix!r}")

        fixed = self._recv_exact(15)
        fmt = chr(fixed[0])
        subfmt = chr(fixed[1])
        payloadlen = struct.unpack("<I", fixed[2:6])[0]
        pktid = struct.unpack("<Q", fixed[6:14])[0]
        staidlen = fixed[14]

        staid = self._recv_exact(staidlen).decode("ascii") if staidlen else ""
        payload = self._recv_exact(payloadlen) if payloadlen else b""

        kind = "data" if subfmt == "D" else "info"
        return {"kind": kind, "format": fmt, "subformat": subfmt,
                "pktid": pktid, "staid": staid, "payload": payload}

    def collect_info_v3(self):
        """Read v3 INFO records until termination; return parsed XML root."""
        chunks = []
        while True:
            frame = self.recv_v3()
            if frame["kind"] not in ("info", "info_end"):
                raise RuntimeError(f"unexpected frame while collecting INFO: {frame['kind']}")

            record = frame["record"]
            nsamples = struct.unpack(">H", record[30:32])[0]
            if nsamples:
                chunks.append(record[56:56 + nsamples])
            else:
                chunks.append(record[56:].rstrip(b"\x00 "))

            if frame["kind"] == "info_end":
                break

        xml_text = b"".join(chunks).decode("utf-8")
        return ET.fromstring(xml_text)

    def close(self):
        self.sock.close()


def tls_client_context():
    """An SSL client context that accepts the self-signed test certificate."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def http_get(port, path, headers=None, method="GET", host="127.0.0.1", tls=False):
    """Issue an HTTP request; return (status, headers_dict, body_bytes)."""
    if tls:
        conn = http.client.HTTPSConnection(host, port, timeout=10, context=tls_client_context())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=10)
    req_headers = {"Accept-Encoding": "identity"}
    if headers:
        req_headers.update(headers)
    try:
        conn.request(method, path, headers=req_headers)
        resp = conn.getresponse()
        body = resp.read()
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, resp_headers, body
    finally:
        conn.close()


class WebSocketConn:
    """A minimal WebSocket client, usable as the `sock` for DataLink/SeedLink."""

    def __init__(self, port, path, subprotocol=None, host="127.0.0.1",
                 timeout=10, version="13", expect_status=101, tls=False):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            self.sock = tls_client_context().wrap_socket(
                self.sock, server_hostname=host)
        self.sock.settimeout(timeout)
        self._buf = b""
        self._frame_buf = b""

        key = base64.b64encode(os.urandom(16)).decode("ascii")
        req = (f"GET {path} HTTP/1.1\r\n"
               f"Host: {host}:{port}\r\n"
               f"Upgrade: websocket\r\n"
               f"Connection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\n"
               f"Sec-WebSocket-Version: {version}\r\n")
        if subprotocol:
            req += f"Sec-WebSocket-Protocol: {subprotocol}\r\n"
        req += "\r\n"
        self.sock.sendall(req.encode("ascii"))

        header_data = b""
        while b"\r\n\r\n" not in header_data:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("connection closed during WebSocket handshake")
            header_data += chunk
        head, _, rest = header_data.partition(b"\r\n\r\n")
        self._buf = rest

        lines = head.decode("ascii", errors="replace").split("\r\n")
        status_line = lines[0]
        self.status = int(status_line.split()[1])
        self.headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                self.headers[k.strip().lower()] = v.strip()

        if self.status != expect_status:
            raise RuntimeError(
                f"WebSocket handshake failed: status {self.status}, "
                f"expected {expect_status}")

        if self.status == 101:
            accept = self.headers.get("sec-websocket-accept", "")
            digest = hashlib.sha1((key + WEBSOCKET_GUID).encode("ascii")).digest()
            expected = base64.b64encode(digest).decode("ascii")
            if accept != expected:
                raise RuntimeError(
                    f"Sec-WebSocket-Accept mismatch: got {accept!r}, "
                    f"expected {expected!r}")

    def _sock_recv_exact(self, n):
        while len(self._buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("connection closed while reading a frame")
            self._buf += chunk
        data = self._buf[:n]
        self._buf = self._buf[n:]
        return data

    def send_bytes(self, data):
        """Send `data` as a single masked binary WebSocket frame."""
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))

        length = len(data)
        frame = bytearray()
        frame.append(0x80 | 0x02)  # FIN + binary opcode

        if length < 126:
            frame.append(0x80 | length)
        elif length < 65536:
            frame.append(0x80 | 126)
            frame += struct.pack(">H", length)
        else:
            frame.append(0x80 | 127)
            frame += struct.pack(">Q", length)

        frame += mask
        frame += masked
        self.sock.sendall(bytes(frame))

    def _read_frame(self):
        """Read one server frame, unmask if needed, and dispatch control frames."""
        head = self._sock_recv_exact(2)
        opcode = head[0] & 0x0F
        masked = bool(head[1] & 0x80)
        length = head[1] & 0x7F

        if length == 126:
            length = struct.unpack(">H", self._sock_recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._sock_recv_exact(8))[0]

        mask_key = self._sock_recv_exact(4) if masked else None
        payload = self._sock_recv_exact(length) if length else b""
        if mask_key:
            payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

        return opcode, payload

    def _buffer_frame(self):
        """Read server frames until application data is buffered.

        Replies to pings; returns False when a close frame is received.
        """
        while True:
            opcode, payload = self._read_frame()
            if opcode == 0x9:  # ping -> reply pong
                self._send_control(0xA, payload)
                continue
            if opcode == 0x8:  # close
                return False
            if opcode in (0x0, 0x1, 0x2):  # continuation, text, binary
                self._frame_buf += payload
                return True

    def recv_bytes(self, n):
        """Return exactly n bytes of application data from server frames."""
        while len(self._frame_buf) < n:
            if not self._buffer_frame():
                return self._frame_buf if self._frame_buf else b""

        data = self._frame_buf[:n]
        self._frame_buf = self._frame_buf[n:]
        return data

    def _send_control(self, opcode, payload=b""):
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        frame = bytearray([0x80 | opcode, 0x80 | len(payload)])
        frame += mask
        frame += masked
        self.sock.sendall(bytes(frame))

    def close(self):
        try:
            self._send_control(0x8)
        except OSError:
            pass
        self.sock.close()

    # socket-like interface so DataLinkConn/SeedLinkConn can wrap this
    def sendall(self, data):
        self.send_bytes(data)

    def recv(self, n):
        # Socket semantics: return between 1 and n buffered bytes, or
        # empty bytes once the peer has closed.
        if not self._frame_buf:
            if not self._buffer_frame():
                return b""
        data = self._frame_buf[:n]
        self._frame_buf = self._frame_buf[n:]
        return data

    def settimeout(self, t):
        self.sock.settimeout(t)
