"""Work out which IP targets see us from, for the User-Agent. Best-effort: if we
cannot find out, we say so rather than guess.
"""

import ipaddress
import socket
import urllib.request

from .. import REPO_URL, __version__

# Small, boring services that echo back the caller's public address.
_ECHO_SERVICES = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def public_ip(timeout: float = 4.0):
    """Ask an external echo service for our egress address; None on failure."""
    # This call is discovering the scanner IP, so it cannot carry it in its own UA;
    # requests to actual targets carry the full tag.
    user_agent = "Detect2Shell/{} (+{}; resolving-scanner-ip)".format(__version__, REPO_URL)
    for url in _ECHO_SERVICES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": user_agent})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                value = resp.read().decode("utf-8", "replace").strip()
            if _is_ip(value):
                return value
        except Exception:
            continue
    return None


def local_ip():
    """The address the OS routes outbound traffic from (private behind NAT)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        finally:
            sock.close()
    except Exception:
        return None


def resolve_scanner_ip(override=None, allow_network=True):
    """Advertise the scanner's source address: override, else public IP, else local
    route address, else "unknown"."""
    if override:
        return override
    if allow_network:
        found = public_ip()
        if found:
            return found
    return local_ip() or "unknown"
