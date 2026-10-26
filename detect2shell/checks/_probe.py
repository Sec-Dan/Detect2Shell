"""Shared injection and correlation machinery for the Java interpolation cluster
(Log4Shell, Spring4Shell, Text4Shell). The User-Agent is never injected - it
stays honest so the target's owner can see who is knocking.
"""

from typing import Callable, List, Optional
from urllib.parse import quote

from ..core.http import Response
from ..core.models import Confidence, Finding, Tier

INJECTABLE_HEADERS = [
    "Referer",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Api-Version",
    "X-Request-Id",
    "True-Client-IP",
    "X-Client-IP",
    "X-Real-IP",
    "X-Originating-IP",
    "Cf-Connecting-IP",
    "Forwarded",
    "Origin",
]

INJECTABLE_PARAMS = ["q", "search", "id", "action", "name", "query"]

# Product-specific endpoints the generic root-path surface would never reach; a
# target not running the product just 404s.
KNOWN_SINKS = [
    ("/solr/admin/cores", "action"),   # Apache Solr admin API (a confirmed Log4Shell sink)
]


def inject_requests(ctx, target, value, in_headers=True, in_params=True, in_path=True, in_sinks=True) -> List[Response]:
    """Place `value` into a spread of likely-evaluated inputs (headers, params,
    path, and the known product sinks), one request each; return every response."""
    responses: List[Response] = []
    base = target.url("/")
    if in_headers:
        for header in INJECTABLE_HEADERS:
            responses.append(ctx.client.get(base, headers={header: value}))
    if in_params:
        sep = "&" if "?" in base else "?"
        for param in INJECTABLE_PARAMS:
            responses.append(ctx.client.get("{}{}{}={}".format(base, sep, param, quote(value, safe=""))))
    if in_path:
        responses.append(ctx.client.get(target.url("/" + quote(value, safe=""))))
    if in_sinks:
        for path, param in KNOWN_SINKS:
            responses.append(ctx.client.get("{}?{}={}".format(target.url(path), param, quote(value, safe=""))))
    return responses


def any_contains(responses: List[Response], needles: List[str]) -> bool:
    lowered = [n.lower() for n in needles]
    for resp in responses:
        hay = resp.text.lower()
        if any(n in hay for n in lowered):
            return True
    return False


def differential_signatures(ctx, target, real_value, control_value, signatures, baseline_text="") -> List[str]:
    """Signatures the real payload drew out that a benign same-shape control (and
    the baseline) did not, so an endpoint that errors on any odd input, or a WAF
    block page, is not mistaken for the vulnerability firing."""
    real = inject_requests(ctx, target, real_value)
    control = inject_requests(ctx, target, control_value)
    control_blob = (baseline_text or "").lower() + " " + " ".join(r.text.lower() for r in control)
    out = []
    for sig in signatures:
        s = sig.lower()
        if s in control_blob:
            continue
        if any(s in r.text.lower() for r in real):
            out.append(sig)
    return out


def oob_confirm(check, target, ctx, build_value: Callable, kind: str, tier: Tier, summary: str) -> Optional[Finding]:
    """Benign out-of-band confirmation. `build_value(primary, secondary, token)`
    builds the ${...} string (host/port for a raw canary, callback URL for HTTP).
    A callback proves the lookup fired; the canary serves nothing."""
    listener = ctx.listener
    if listener is None:
        return None

    if kind == "raw":
        token, host, port = listener.new_raw_endpoint()
        value = build_value(host, port, token)
    else:
        token = listener.new_http_token()
        value = build_value(listener.http_callback_url(token), None, token)

    try:
        inject_requests(ctx, target, value)
        hit = listener.wait_raw(token) if kind == "raw" else listener.wait_http(token)
    finally:
        # Free the raw catcher's socket now; the HTTP canary is shared.
        if kind == "raw":
            listener.release_raw(token)

    if hit:
        return check.finding(
            target,
            Confidence.CONFIRMED,
            tier,
            summary,
            ["out-of-band {} callback from {} (token {})".format(hit.kind, hit.peer_ip, token)],
        )
    return None
