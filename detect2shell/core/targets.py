"""Parse user input into `Target`s: full URLs, bare hosts, host:port, CIDR ranges.
A bare host with no scheme expands to both https and http; pin it with a scheme or port.
"""

import ipaddress
from typing import Iterable, List, Optional
from urllib.parse import urlsplit

from .models import Target

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _mk(scheme: str, host: str, port: Optional[int]) -> Target:
    return Target(scheme=scheme, host=host, port=port or _DEFAULT_PORTS[scheme])


def _expand_bare_host(host: str, port: Optional[int] = None) -> List[Target]:
    if port == 80:
        return [_mk("http", host, 80)]
    if port == 443:
        return [_mk("https", host, 443)]
    if port is not None:
        return [_mk("https", host, port), _mk("http", host, port)]
    return [_mk("https", host, 443), _mk("http", host, 80)]


def parse_one(item: str) -> List[Target]:
    item = item.strip()
    if not item or item.startswith("#"):
        return []

    # CIDR range (but not a URL that merely contains a slash).
    if "/" in item and "://" not in item:
        try:
            net = ipaddress.ip_network(item, strict=False)
            out: List[Target] = []
            hosts = net.hosts() if net.num_addresses > 1 else [net.network_address]
            for addr in hosts:
                out.extend(_expand_bare_host(str(addr)))
            return out
        except ValueError:
            pass  # not a network, fall through

    # Full URL. urlsplit/.port raise ValueError on a malformed URL; skip it, don't abort the run.
    if "://" in item:
        try:
            parts = urlsplit(item)
            scheme = parts.scheme.lower()
            if scheme not in _DEFAULT_PORTS or not parts.hostname:
                return []
            return [_mk(scheme, parts.hostname, parts.port or _DEFAULT_PORTS[scheme])]
        except ValueError:
            return []

    # host or host:port (IPv6 needs an explicit scheme). isascii() rejects Unicode
    # digits int() would choke on; the range check stops a nonsensical port.
    host, port = item, None
    if item.count(":") == 1:
        left, _, right = item.partition(":")
        if right.isascii() and right.isdigit() and 1 <= int(right) <= 65535:
            host, port = left, int(right)
    return _expand_bare_host(host, port)


def parse_targets(items: Iterable[str]) -> List[Target]:
    seen = set()
    out: List[Target] = []
    for item in items:
        for target in parse_one(item):
            key = (target.scheme, target.host, target.port)
            if key not in seen:
                seen.add(key)
                out.append(target)
    return out
