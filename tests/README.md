# ringserver test suite

End-to-end tests that run the compiled `ringserver` binary and exercise it
over TCP using the DataLink, SeedLink, and HTTP protocols.

## Running

From the repository root:

    make test

or directly (requires the binary to be built):

    python3 -m unittest discover -s tests -v

A single module:

    python3 -m unittest tests.test_datalink -v
    python3 tests/test_datalink.py -v

Requirements: Python 3 (standard library only).

## Layout

- `ringtest.py` — shared rig: server launcher, DataLink/SeedLink/HTTP/WebSocket
  clients, and a miniSEED 2 record builder. No test cases.
- `test_datalink.py` — DataLink protocol: handshake, WRITE/READ, positioning,
  MATCH/REJECT, streaming, INFO, error responses.
- `test_seedlink.py` — SeedLink v3 and v4: negotiation, streaming, framing,
  INFO documents.
- `test_auth.py` — authentication: DataLink AUTH (USERPASS/JWT), permissions,
  the auth-required-for-streaming gate, and allowed/forbidden stream filters.
- `test_http.py` — HTTP endpoints, gzip, access control, WebSocket transport.
- `test_integrity.py` — data-integrity stress: concurrent write/stream,
  ring-wrap torn-read detection, lapped-reader liveness.
- `test_lifecycle.py` — startup/shutdown, ring persistence and reinitialization,
  usage logs, TLS, miniSEED scanning.
- `test_abuse.py` — misbehaving clients: slow-loris stalls, silent connections,
  junk input, stalled readers, and connection limits.
- `test_transports.py` — TLS/wss transport matrix: DataLink, SeedLink v3/v4,
  HTTPS, and WebSocket-over-TLS.
- `data/` — long-lived self-signed certificate for the TLS tests.

## Conventions

Each test class starts its own server on a free port, by default with a
volatile (in-memory) ring, hostname resolution disabled, and the INFO cache
disabled for determinism. Servers log to a per-instance temporary directory;
the log is checked for error lines at shutdown and included in failure
messages. Nothing is written inside the repository.
