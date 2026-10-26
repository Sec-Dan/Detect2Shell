"""The out-of-band canary listener.

Inert by construction: the HTTP handler always answers one fixed string and the
raw TCP catcher only notes that a connection happened, so a callback proves a
lookup fired but can never become the second stage of an exploit.
"""

import secrets
import socket
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional

_INERT_BODY = b"detect2shell canary. This endpoint only records that it was reached.\n"


@dataclass
class CanaryHit:
    token: str
    kind: str          # "http" or "tcp"
    peer_ip: str
    at: float
    detail: str = ""   # request path for http hits, first bytes (hex) for tcp hits


class _CanaryHandler(BaseHTTPRequestHandler):
    server_version = "Detect2Shell-canary/0.1"

    def _record(self) -> None:
        path = self.path
        segments = [p for p in path.split("?", 1)[0].split("/") if p]
        token = ""
        if len(segments) >= 2 and segments[0] == "c":
            token = segments[1]
        elif segments:
            token = segments[-1]
        self.server.record_hit(
            CanaryHit(
                token=token,
                kind="http",
                peer_ip=self.client_address[0],
                at=time.time(),
                detail=path,
            )
        )

    def _respond(self, head: bool = False) -> None:
        try:
            self._record()
        except Exception:
            pass
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(_INERT_BODY)))
        self.end_headers()
        if not head:
            self.wfile.write(_INERT_BODY)

    def do_GET(self):
        self._respond()

    def do_POST(self):
        self._respond()

    def do_HEAD(self):
        self._respond(head=True)

    def log_message(self, *args):
        # Silent; hits surface through the findings, not stderr.
        return


class _HttpCanaryServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr):
        super().__init__(addr, _CanaryHandler)
        self._hits: Dict[str, CanaryHit] = {}
        self._lock = threading.Lock()

    def record_hit(self, hit: CanaryHit) -> None:
        with self._lock:
            if hit.token and hit.token not in self._hits:
                self._hits[hit.token] = hit

    def hit_for(self, token: str) -> Optional[CanaryHit]:
        with self._lock:
            return self._hits.get(token)


class _RawPort:
    """A dedicated socket that notices the JNDI callback on its port; attribution
    is by port, so no LDAP/RMI parsing is needed."""

    def __init__(self, bind_host: str, token: str = ""):
        self.token = token
        self._token_bytes = token.encode("ascii", "ignore")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind_host, 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(8)
        self.hit: Optional[CanaryHit] = None
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @staticmethod
    def _looks_like_jndi(data: bytes) -> bool:
        # LDAP opens with 0x30 (BER SEQUENCE), RMI with "JRMI"; a bare connect or
        # an HTTP/TLS probe opens otherwise, so neither is mistaken for a callback.
        return bool(data) and (data[0] == 0x30 or data[:4] == b"JRMI")

    def _serve(self) -> None:
        self.sock.settimeout(0.5)
        while not self._stop:
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(1.0)
                data = b""
                deadline = time.monotonic() + 1.0
                while len(data) < 1024 and time.monotonic() < deadline:
                    try:
                        chunk = conn.recv(256)
                    except Exception:
                        break
                    if not chunk:
                        break
                    data += chunk
                    if self._token_bytes and self._token_bytes in data:
                        break
                # Record only JNDI-shaped traffic or our token, so a stray connect is never a hit.
                if self.hit is None and (self._looks_like_jndi(data) or (self._token_bytes and self._token_bytes in data)):
                    self.hit = CanaryHit(
                        token=self.token,
                        kind="tcp",
                        peer_ip=addr[0],
                        at=time.time(),
                        detail=data[:32].hex(),
                    )
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    def stop(self) -> None:
        self._stop = True
        try:
            self.sock.close()
        except Exception:
            pass


class CanaryListener:
    """Facade over the HTTP server and the per-token raw catchers. `advertise_host`
    is what targets reach us on (embedded in callback URLs); `bind_host` is where
    we listen locally.
    """

    def __init__(self, advertise_host, http_port=0, bind_host="0.0.0.0", enabled=True):
        self.advertise_host = advertise_host
        self.bind_host = bind_host
        self.enabled = enabled
        self.http_port = http_port
        self._http: Optional[_HttpCanaryServer] = None
        self._http_thread: Optional[threading.Thread] = None
        self._raw: Dict[str, _RawPort] = {}
        self._lock = threading.Lock()

    def start(self) -> None:
        if not self.enabled:
            return
        self._http = _HttpCanaryServer((self.bind_host, self.http_port))
        self.http_port = self._http.server_address[1]
        self._http_thread = threading.Thread(target=self._http.serve_forever, daemon=True)
        self._http_thread.start()

    # --- HTTP-scheme canaries (token carried in the request path) ---
    def new_http_token(self) -> str:
        return secrets.token_hex(8)

    def http_callback_url(self, token: str) -> str:
        return "http://{}:{}/c/{}".format(self.advertise_host, self.http_port, token)

    def http_hit(self, token: str) -> Optional[CanaryHit]:
        return self._http.hit_for(token) if self._http else None

    # --- Raw TCP canaries (attribution by dedicated port) ---
    def new_raw_endpoint(self):
        """Returns (token, host, port); a JNDI-shaped connection to host:port proves the lookup ran."""
        token = secrets.token_hex(8)
        raw = _RawPort(self.bind_host, token)
        with self._lock:
            self._raw[token] = raw
        return token, self.advertise_host, raw.port

    def raw_hit(self, token: str) -> Optional[CanaryHit]:
        raw = self._raw.get(token)
        return raw.hit if raw else None

    def release_raw(self, token: str) -> None:
        """Free a raw catcher's socket, thread and port once its check is done, so
        a long CIDR run does not exhaust file descriptors. A callback after release
        is dropped; a recycled port could misattribute a very late callback, which
        the token check makes rare."""
        with self._lock:
            raw = self._raw.pop(token, None)
        if raw is not None:
            raw.stop()

    # --- blocking waits, for checks that probe and then listen for a beat ---
    def wait_http(self, token: str, timeout: float = 6.0, interval: float = 0.3) -> Optional[CanaryHit]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            hit = self.http_hit(token)
            if hit:
                return hit
            time.sleep(interval)
        return self.http_hit(token)

    def wait_raw(self, token: str, timeout: float = 6.0, interval: float = 0.3) -> Optional[CanaryHit]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            hit = self.raw_hit(token)
            if hit:
                return hit
            time.sleep(interval)
        return self.raw_hit(token)

    def stop(self) -> None:
        if self._http:
            try:
                self._http.shutdown()
            except Exception:
                pass
            try:
                self._http.server_close()
            except Exception:
                pass
        for raw in list(self._raw.values()):
            raw.stop()
