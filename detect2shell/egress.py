"""Host-side egress canary: can this box actually reach out?

A box can be vulnerable on paper and still be low-risk because nothing it runs
can call home - egress filtering, segmentation, or a genuine air gap sits in the
way. That is not visible from a version check, so this asks it directly: from the
host, try to reach a destination *you* control over DNS, HTTP(S) and raw TCP, and
report which channels get out.

It only makes outbound connections to destinations you pass on the command line;
it never picks a destination on its own, and it carries no exploit. Point it at
the built-in canary listener (detect2shell's --confirm listener, or any endpoint
you own) and the far side records the hit, so you get both ends of the proof.
"""

import argparse
import socket
import sys
import time
import urllib.error
import urllib.request

from . import REPO_URL, __version__
from .core import report as report_mod

_UA = "Detect2Shell-egress/{} (+{})".format(__version__, REPO_URL)
# No ambient-proxy handler: we are testing the host's own egress, not a proxy's.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def check_dns(name, timeout=5.0):
    start = time.monotonic()
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(name, None)
        addrs = sorted({info[4][0] for info in infos})
        return "resolved", "{} -> {}".format(name, ", ".join(addrs)), time.monotonic() - start
    except socket.gaierror as exc:
        return "failed", "{}: {}".format(name, exc), time.monotonic() - start
    except Exception as exc:
        return "error", "{}: {}".format(name, exc), time.monotonic() - start
    finally:
        socket.setdefaulttimeout(None)


def check_tcp(host, port, timeout=5.0):
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open", "{}:{} accepted a connection".format(host, port), time.monotonic() - start
    except socket.timeout:
        return "timeout", "{}:{} did not answer in {:.0f}s".format(host, port, timeout), time.monotonic() - start
    except ConnectionRefusedError:
        return "refused", "{}:{} refused the connection".format(host, port), time.monotonic() - start
    except OSError as exc:
        return "blocked", "{}:{}: {}".format(host, port, exc), time.monotonic() - start


def check_http(url, timeout=5.0):
    start = time.monotonic()
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": _UA})
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            # Any HTTP response means the request left the host and came back.
            return "reached", "{} returned HTTP {}".format(url, resp.getcode()), time.monotonic() - start
    except urllib.error.HTTPError as exc:
        # A 4xx/5xx still proves egress reached the server.
        return "reached", "{} returned HTTP {}".format(url, exc.code), time.monotonic() - start
    except urllib.error.URLError as exc:
        return "blocked", "{}: {}".format(url, exc.reason), time.monotonic() - start
    except Exception as exc:
        return "error", "{}: {}".format(url, exc), time.monotonic() - start


# Outcomes that mean traffic left the host.
_GOT_OUT = {"resolved", "open", "reached"}


def _split_hostport(value):
    """Parse HOST:PORT; supports bare IPv6 in brackets, e.g. [::1]:443."""
    if value.startswith("["):
        host, _, port = value[1:].partition("]")
        port = port.lstrip(":")
    else:
        host, _, port = value.rpartition(":")
    if not host or not port:
        raise ValueError("expected HOST:PORT, got {!r}".format(value))
    return host, int(port)


def run(argv=None):
    parser = argparse.ArgumentParser(
        prog="detect2shell --egress-check",
        description="Host-side egress canary: test whether this box can reach a destination you control "
                    "over DNS, HTTP(S) and raw TCP. Only contacts destinations you pass explicitly.",
    )
    parser.add_argument("--egress-url", action="append", dest="urls", metavar="URL", default=[],
                        help="HTTP(S) URL to GET (repeatable); use a /c/<token> path on your canary to attribute the hit")
    parser.add_argument("--egress-tcp", action="append", dest="tcps", metavar="HOST:PORT", default=[],
                        help="raw TCP destination to connect to (repeatable)")
    parser.add_argument("--egress-dns", action="append", dest="names", metavar="NAME", default=[],
                        help="hostname to resolve (repeatable); a unique name under a domain you control tests DNS egress")
    parser.add_argument("--timeout", type=float, default=5.0, help="per-channel timeout in seconds")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    args = parser.parse_args(argv)

    if not (args.urls or args.tcps or args.names):
        parser.error("give at least one destination you control: --egress-url, --egress-tcp or --egress-dns")

    palette = report_mod.Palette(report_mod.color_enabled(args.no_color, stream=sys.stdout))
    print(palette.paint("Detect2Shell egress canary", "1;36"))
    print(palette.dim("tests whether this host can reach destinations you control - no exploit, no auto-chosen targets"))
    print()

    results = []
    for name in args.names:
        results.append(("DNS ", name) + check_dns(name, args.timeout))
    for spec in args.tcps:
        try:
            host, port = _split_hostport(spec)
        except ValueError as exc:
            results.append(("TCP ", spec, "error", str(exc), 0.0))
            continue
        results.append(("TCP ", spec) + check_tcp(host, port, args.timeout))
    for url in args.urls:
        results.append(("HTTP", url) + check_http(url, args.timeout))

    got_out = False
    for channel, dest, outcome, detail, elapsed in results:
        out = outcome in _GOT_OUT
        got_out = got_out or out
        color = "1;31" if out else "32"
        mark = "OUT " if out else "----"
        print("  {} {} {}".format(palette.paint(mark, color), palette.paint(channel, "1"),
                                   palette.paint(outcome.upper(), color)))
        print(palette.dim("        {}  ({:.0f} ms)".format(detail, elapsed * 1000)))
    print()

    if got_out:
        print(palette.paint(
            "At least one channel left the host. A vulnerable service here could call home - "
            "treat egress as open on those channels.", "1;31"))
        print(palette.dim(
            "Check the far side (your canary/listener) to confirm the traffic actually arrived, "
            "not just that the socket opened."))
    else:
        print(palette.paint(
            "No channel reached its destination. Egress to the destinations tested is blocked - "
            "a real plus for a vulnerable-but-segmented host.", "32"))
        print(palette.dim("This covers only the destinations and channels you tested; it is not a blanket air-gap proof."))
    print()
    print(palette.dim("source + method: {}".format(REPO_URL)))

    return 1 if got_out else 0


if __name__ == "__main__":
    sys.exit(run())
