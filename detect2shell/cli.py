"""Command-line entrypoint: splash, consent, scan, report."""

import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import List

from . import AUTHOR, MIN_PYTHON, PROJECT_NAME, REPO_URL, __version__
from .checks import base as checks_base
from .core import auth, netinfo
from .core import report as report_mod
from .core import targets as targets_mod
from .core.http import HttpClient, build_user_agent
from .core.listener import CanaryListener
from .core.models import Tier
from .core.runner import run_scan


def _err(msg: str = "") -> None:
    sys.stderr.write(msg + "\n")


def load_splash() -> str:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "art", "splash.txt")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except Exception:
        return PROJECT_NAME + "\n"


def print_banner(palette) -> None:
    splash = load_splash()
    sys.stderr.write(palette.paint(splash, "1;36") if palette.enabled else splash)
    _err(palette.dim("  {} v{}  -  authorised *2Shell / *4Shell exposure scanner".format(PROJECT_NAME, __version__)))
    _err(palette.dim("  by {}  -  {}".format(AUTHOR, REPO_URL)))
    _err("")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detect2shell",
        description="Authorised exposure scanner for the *2Shell / *4Shell remote code execution family.",
        epilog="Use only against systems you own or are explicitly authorised to test.",
    )
    parser.add_argument("targets", nargs="*", help="URL, host, host:port or CIDR range")
    parser.add_argument("-f", "--file", help="read targets from a file, one per line")
    parser.add_argument("--only", help="comma-separated check keys to run (see --list-checks)")
    parser.add_argument("--exclude", help="comma-separated check keys to skip")
    parser.add_argument("--list-checks", action="store_true", help="list available checks and exit")

    group = parser.add_argument_group("detection tiers")
    group.add_argument("--confirm", action="store_true",
                       help="tier 2: benign out-of-band canary; nothing executes on the target")
    group.add_argument("--prove", action="store_true",
                       help="tier 3: send the real trigger only to prove the path fires, then stop (never opens a shell)")
    group.add_argument("--allow-disruptive", action="store_true",
                       help="permit prove-tier checks that may crash a target worker/process")

    group = parser.add_argument_group("authorisation")
    group.add_argument("--i-am-authorised", action="store_true",
                       help="assert, non-interactively, that you are permitted to scan these targets")
    group.add_argument("--scope", help="file of allowed host / CIDR / *.wildcard patterns; others are skipped")

    group = parser.add_argument_group("out-of-band listener")
    group.add_argument("--listener-host", help="address targets can reach this scanner on (default: detected scanner IP)")
    group.add_argument("--listener-port", type=int, default=0, help="port for the built-in HTTP canary (default: ephemeral)")
    group.add_argument("--no-listener", action="store_true", help="do not start the built-in canary listener")

    group = parser.add_argument_group("http")
    group.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds")
    group.add_argument("--rate", type=float, default=0.0, help="max requests/second per run (0 = unthrottled)")
    group.add_argument("--concurrency", type=int, default=10, help="number of concurrent workers")
    group.add_argument("--verify-tls", action="store_true", help="verify TLS certificates (off by default)")
    group.add_argument("--scanner-ip", help="override the IP advertised in the User-Agent")
    group.add_argument("--no-ip-lookup", action="store_true", help="skip the outbound lookup used to find the scanner IP")

    group = parser.add_argument_group("output")
    group.add_argument("--json", dest="json_path", help="write the full result set as JSON to this path")
    group.add_argument("--no-color", action="store_true", help="disable coloured output")
    group.add_argument("--no-banner", action="store_true", help="suppress the splash banner")
    group.add_argument("--show-clean", action="store_true", help="also show checks that found nothing")
    group.add_argument("-v", "--verbose", action="store_true", help="show references and extra detail")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return parser


def _read_target_file(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip() and not line.startswith("#")]


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    # Survive a non-UTF-8 console and enable ANSI on legacy Windows terminals.
    if os.name == "nt":
        os.system("")
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except Exception:
            pass

    # Colour per stream: diagnostics/banner to stderr, report/summary to stdout.
    palette = report_mod.Palette(report_mod.color_enabled(args.no_color, stream=sys.stderr))
    out_palette = report_mod.Palette(report_mod.color_enabled(args.no_color, stream=sys.stdout))

    if not args.no_banner:
        print_banner(palette)

    if sys.version_info < MIN_PYTHON:
        _err(palette.paint(
            "warning: Python {}.{}+ recommended; you are on {}.{}".format(
                MIN_PYTHON[0], MIN_PYTHON[1], sys.version_info[0], sys.version_info[1]
            ), "33"))

    if args.list_checks:
        for check in checks_base.all_checks():
            print("{:<14} {:<22} {}".format(check.key, check.name, ", ".join(check.cves)))
        return 0

    # --- collect targets ---
    raw = list(args.targets)
    if args.file:
        try:
            raw += _read_target_file(args.file)
        except (OSError, UnicodeDecodeError) as exc:
            _err("cannot read target file: {}".format(exc))
            return 2
    if not raw:
        _err("no targets given. See --help.")
        return 2

    target_list = targets_mod.parse_targets(raw)
    if not target_list:
        _err("no valid targets parsed from input.")
        return 2

    # --- consent, every run, before anything touches the network ---
    sys.stderr.write(auth.DISCLAIMER + "\n")
    is_tty = bool(getattr(sys.stdin, "isatty", lambda: False)()) and bool(getattr(sys.stderr, "isatty", lambda: False)())
    try:
        authorisation = auth.resolve(args, is_tty)
    except auth.NotAuthorised as exc:
        _err(palette.paint(str(exc), "1;31"))
        return 3
    except (OSError, UnicodeDecodeError) as exc:
        _err("cannot read scope file: {}".format(exc))
        return 2
    if not authorisation.authorised:
        _err(palette.paint("authorisation not confirmed; aborting.", "1;31"))
        return 3

    # A --scope that resolves to nothing must not fall open to "scan everything";
    # an absent --scope is different and still means no restriction.
    if args.scope and not authorisation.scope:
        _err(palette.paint("scope file '{}' has no patterns; refusing to scan without a scope.".format(args.scope), "1;31"))
        return 2

    allowed, rejected = auth.filter_in_scope(target_list, authorisation.scope)
    for target in rejected:
        _err(palette.dim("out of scope, skipping: {}".format(target.base_url)))
    target_list = allowed
    if not target_list:
        _err("no targets remain after the scope filter.")
        return 2

    # --- identity / client ---
    scanner_ip = netinfo.resolve_scanner_ip(override=args.scanner_ip, allow_network=not args.no_ip_lookup)
    user_agent = build_user_agent(scanner_ip)
    client = HttpClient(user_agent, timeout=args.timeout, verify_tls=args.verify_tls, rate=args.rate)

    # --- reachability pre-check (concurrent, so a dead CIDR does not stall) ---
    def _reach(target):
        return target, client.get(target.url("/"))
    reachable = []
    workers = max(1, min(args.concurrency, len(target_list)))
    # pool.map preserves order, so the skip notices stay deterministic.
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for target, probe in pool.map(_reach, target_list):
            if probe.ok:
                reachable.append(target)
            else:
                _err(palette.dim("unreachable, skipping: {} ({})".format(target.base_url, probe.error or "no response")))
    target_list = reachable
    if not target_list:
        _err("no reachable targets.")
        return 2

    # --- out-of-band listener (only needed from tier 2 up) ---
    listener = None
    if authorisation.max_tier >= Tier.CONFIRM and not args.no_listener:
        advertise = args.listener_host or scanner_ip
        listener = CanaryListener(advertise_host=advertise, http_port=args.listener_port)
        try:
            listener.start()
        except Exception as exc:
            _err(palette.paint("listener failed to start ({}); out-of-band checks disabled".format(exc), "33"))
            listener = None
        if listener and advertise in (None, "unknown"):
            _err(palette.paint(
                "warning: scanner IP is unknown; pass --listener-host so targets can call back", "33"))

    # --- checks ---
    only = args.only.split(",") if args.only else None
    exclude = args.exclude.split(",") if args.exclude else None
    checks = checks_base.select(only=only, exclude=exclude)
    if not checks:
        _err("no checks selected.")
        if listener:
            listener.stop()
        return 2

    ctx = checks_base.CheckContext(
        client=client,
        listener=listener,
        max_tier=authorisation.max_tier,
        allow_disruptive=authorisation.allow_disruptive,
        verbose=args.verbose,
    )

    _err(palette.dim("targets: {}   checks: {}   tier: {}   scanner-ip: {}".format(
        len(target_list), len(checks), authorisation.max_tier.name.lower(), scanner_ip)))
    _err(palette.dim("user-agent: {}".format(user_agent)))
    if listener:
        _err(palette.dim("canary: http://{}:{}/  (advertising {})".format(
            listener.bind_host, listener.http_port, listener.advertise_host)))
    _err("")

    try:
        findings = run_scan(target_list, checks, ctx, concurrency=args.concurrency)
    finally:
        if listener:
            listener.stop()

    print(report_mod.render(findings, out_palette, show_clean=args.show_clean, verbose=args.verbose))
    print()
    print(report_mod.summary_line(findings, out_palette, target_count=len(target_list), check_count=len(checks)))

    json_failed = False
    if args.json_path:
        meta = {
            "scanner_ip": scanner_ip,
            "user_agent": user_agent,
            "tier": authorisation.max_tier.name.lower(),
            "allow_disruptive": authorisation.allow_disruptive,
            "targets": [t.base_url for t in target_list],
            "checks": [c.key for c in checks],
        }
        try:
            report_mod.write_json(args.json_path, findings, meta)
            _err(palette.dim("wrote JSON report to {}".format(args.json_path)))
        except OSError as exc:
            _err(palette.paint("could not write JSON report: {}".format(exc), "1;31"))
            json_failed = True

    code = report_mod.exit_code(findings)
    if json_failed and code == 0:
        # A report-write failure must not mask a positive finding (exit 1); only
        # promote an otherwise-clean run to the error code.
        code = 2
    return code
