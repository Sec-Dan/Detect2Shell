"""A thin HTTP client on urllib: every request carries the honest User-Agent, and
the client never raises - errors fold into a `Response`.
"""

import http.client
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, Optional

from .. import REPO_URL, __version__


def build_user_agent(scanner_ip: str) -> str:
    """The fingerprint on every request; `authorised-scan` marks it as sanctioned."""
    return "Detect2Shell/{} (+{}; scanner-ip={}; authorised-scan)".format(
        __version__, REPO_URL, scanner_ip
    )


@dataclass
class Response:
    url: str
    status: Optional[int]
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    elapsed: float = 0.0
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def header(self, name: str, default=None):
        return self.headers.get(name.lower(), default)


def _lower_headers(message) -> Dict[str, str]:
    # Fold repeated header lines (e.g. several Set-Cookie) instead of last-wins.
    out: Dict[str, str] = {}
    try:
        for key, value in message.items():
            lower = key.lower()
            out[lower] = out[lower] + ", " + value if lower in out else value
    except Exception:
        pass
    return out


class HttpClient:
    def __init__(
        self,
        user_agent: str,
        timeout: float = 10.0,
        verify_tls: bool = False,
        rate: float = 0.0,
        max_body: int = 2_000_000,
        extra_headers: Optional[Dict[str, str]] = None,
    ):
        self.user_agent = user_agent
        self.timeout = timeout
        self.max_body = max_body
        self.extra_headers = dict(extra_headers or {})
        self._min_interval = (1.0 / rate) if rate and rate > 0 else 0.0
        self._lock = threading.Lock()
        self._last = 0.0

        if verify_tls:
            ctx = ssl.create_default_context()
        else:
            # Targets routinely have self-signed/mismatched certs; opt back in with --verify-tls.
            ctx = ssl._create_unverified_context()
        self._ssl_ctx = ctx
        # Talk to targets directly; the empty ProxyHandler blocks an ambient proxy.
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ctx),
        )

    def _throttle(self) -> None:
        if self._min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()

    def request(self, method, url, headers=None, data=None, timeout=None) -> Response:
        self._throttle()
        hdrs = {}
        hdrs.update(self.extra_headers)
        if headers:
            hdrs.update(headers)
        # Honest User-Agent is non-negotiable: strip any caller variant, set ours last.
        for key in [k for k in hdrs if k.lower() == "user-agent"]:
            del hdrs[key]
        hdrs["User-Agent"] = self.user_agent
        req = urllib.request.Request(url, data=data, method=method.upper(), headers=hdrs)
        start = time.monotonic()
        try:
            with self._opener.open(req, timeout=timeout or self.timeout) as resp:
                body = resp.read(self.max_body)
                return Response(
                    url=resp.geturl(),
                    status=resp.getcode(),
                    headers=_lower_headers(resp.headers),
                    body=body,
                    elapsed=time.monotonic() - start,
                )
        except urllib.error.HTTPError as exc:
            body = b""
            try:
                body = exc.read(self.max_body)
            except Exception:
                pass
            return Response(
                url=url,
                status=exc.code,
                headers=_lower_headers(exc.headers),
                body=body,
                elapsed=time.monotonic() - start,
            )
        except Exception as exc:
            return Response(
                url=url,
                status=None,
                elapsed=time.monotonic() - start,
                error="{}: {}".format(type(exc).__name__, exc),
            )

    def get(self, url, headers=None, timeout=None) -> Response:
        return self.request("GET", url, headers=headers, timeout=timeout)

    def head(self, url, headers=None, timeout=None) -> Response:
        return self.request("HEAD", url, headers=headers, timeout=timeout)

    def post(self, url, data=None, headers=None, timeout=None) -> Response:
        return self.request("POST", url, headers=headers, data=data, timeout=timeout)

    def request_raw_headers(self, method, url, headers=None, data=None, timeout=None) -> Response:
        """Send a request preserving exact header-name case. urllib's opener
        title-cases header names, which Spring Cloud Function's case-sensitive
        routing-expression lookup then misses; http.client sends them verbatim.
        """
        self._throttle()
        start = time.monotonic()
        conn = None
        try:
            # Parse inside the try so a malformed URL folds into a Response.
            parts = urllib.parse.urlsplit(url)
            host = parts.hostname or ""
            port = parts.port or (443 if parts.scheme == "https" else 80)
            path = parts.path or "/"
            if parts.query:
                path = path + "?" + parts.query
            hdrs = {}
            hdrs.update(self.extra_headers)
            if headers:
                hdrs.update(headers)
            for key in [k for k in hdrs if k.lower() == "user-agent"]:
                del hdrs[key]
            hdrs["User-Agent"] = self.user_agent

            if parts.scheme == "https":
                conn = http.client.HTTPSConnection(host, port, timeout=timeout or self.timeout, context=self._ssl_ctx)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout or self.timeout)
            conn.request(method.upper(), path, body=data, headers=hdrs)
            resp = conn.getresponse()
            body = resp.read(self.max_body)
            return Response(
                url=url,
                status=resp.status,
                headers=_lower_headers(resp.headers),
                body=body,
                elapsed=time.monotonic() - start,
            )
        except Exception as exc:
            return Response(
                url=url,
                status=None,
                elapsed=time.monotonic() - start,
                error="{}: {}".format(type(exc).__name__, exc),
            )
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
