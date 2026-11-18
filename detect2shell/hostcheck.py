"""Host-side Java4Shell companion: answer "is this box actually exploitable?"

The remote scanner can only see that a service is reachable and that its build
is in range. Whether CVE-2026-114938 can really fire depends on three things
that are not visible over the wire: the exact JDK build, whether the HotSpot
Base64 intrinsic is enabled, and whether the JVM is driving the AVX-512 decode
path at all. All three are answerable locally, with no exploit - you just ask
the JVM. Run this on the host next to the running service.

It is read-only: it launches the target `java` binary with `-version` and
`-XX:+PrintFlagsFinal -version` (both of which only print and exit) and parses
the output. It never touches the network and never drives the vulnerability.
"""

import argparse
import re
import shutil
import subprocess
import sys
import textwrap

from . import REPO_URL, __version__
from .checks.java4shell import _jdk_status, _parse_jdk
from .core import report as report_mod

# UseAVX levels: 3 is the AVX-512 tier, which is the decode path the overflow
# lives in. At 2 or below HotSpot does not take the AVX-512 intrinsic, so the
# vulnerable code is not reached even on an affected build - this is exactly
# what the `-XX:UseAVX=2` mitigation leans on.
_AVX512_LEVEL = 3

_FLAG_RE = re.compile(r"^\s*\S+\s+(\w+)\s*(?::?=)\s*(\S+)", re.M)


def _run_java(java_bin, extra_args, timeout=15):
    """Run the JVM with print-and-exit flags; return combined output or None."""
    try:
        proc = subprocess.run(
            [java_bin] + list(extra_args),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout.decode("utf-8", "replace")


def _version_line(text):
    """The quoted version from `java -version` output, e.g. 21.0.5 or 1.8.0_511."""
    m = re.search(r'version "([^"]+)"', text or "")
    return m.group(1) if m else None


def _vendor(text):
    for line in (text or "").splitlines():
        if "Runtime Environment" in line:
            return line.strip()
    return (text or "").strip().splitlines()[0] if text else None


def _flags(text):
    """Map every `<type> Name = value` line from PrintFlagsFinal to its value."""
    return {name: value for name, value in _FLAG_RE.findall(text or "")}


class HostVerdict:
    EXPLOITABLE = "EXPLOITABLE"
    MITIGATED = "MITIGATED"
    NOT_EXPLOITABLE = "NOT EXPLOITABLE"
    UNKNOWN = "UNKNOWN"


def assess(java_bin):
    """Inspect one JVM and return (verdict, version_string, [reasons])."""
    reasons = []
    ver_text = _run_java(java_bin, ["-version"])
    if ver_text is None:
        return HostVerdict.UNKNOWN, None, ["could not run '{}' -version".format(java_bin)]

    vstr = _version_line(ver_text)
    version = _parse_jdk(vstr)
    vendor = _vendor(ver_text)
    if vendor:
        reasons.append(vendor)

    if version is None:
        return HostVerdict.UNKNOWN, vstr, reasons + ["could not parse a JDK version from -version output"]

    status = _jdk_status(version)
    shown = vstr or ".".join(str(p) for p in version)

    # The Oracle 8u511b33-perf build is the one pre-17 build that carries the
    # intrinsic; a normal 1.8/8 string does not identify it, so flag rather than clear.
    if version[0] < 17 and "perf" in (ver_text or "").lower():
        return HostVerdict.UNKNOWN, shown, reasons + [
            "pre-17 'perf' build - the Oracle 8u511b33-perf line is affected; confirm the exact build"]

    if status == "unaffected":
        return HostVerdict.NOT_EXPLOITABLE, shown, reasons + [
            "JDK {} is outside the affected range".format(shown)]
    if status == "fixed":
        return HostVerdict.NOT_EXPLOITABLE, shown, reasons + [
            "JDK {} carries the fix (verify a vendor backport did not keep the version string)".format(shown)]
    if status == "unknown":
        reasons.append("JDK {} is on a line with no fix data - treat the build as in-range".format(shown))
    else:
        reasons.append("JDK {} is within the affected range".format(shown))

    # Build is in range (or unknown-but-in-range): the flags decide whether the
    # vulnerable decode path is actually live on this CPU with these options.
    flag_text = _run_java(java_bin, ["-XX:+PrintFlagsFinal", "-version"])
    flags = _flags(flag_text)
    intrinsic = flags.get("UseBASE64Intrinsics")
    use_avx = flags.get("UseAVX")

    if intrinsic is None and use_avx is None:
        return HostVerdict.UNKNOWN, shown, reasons + [
            "could not read UseBASE64Intrinsics / UseAVX from this JVM - confirm the flags manually"]

    if intrinsic == "false":
        return HostVerdict.MITIGATED, shown, reasons + [
            "UseBASE64Intrinsics is off - the vulnerable intrinsic is not compiled in"]

    try:
        avx_level = int(use_avx) if use_avx is not None else None
    except ValueError:
        avx_level = None

    if avx_level is not None and avx_level < _AVX512_LEVEL:
        return HostVerdict.NOT_EXPLOITABLE, shown, reasons + [
            "UseAVX={} - below the AVX-512 level ({}), so the AVX-512 Base64 path is not taken "
            "(this is the -XX:UseAVX=2 mitigation)".format(avx_level, _AVX512_LEVEL)]

    if intrinsic == "true" and avx_level is not None and avx_level >= _AVX512_LEVEL:
        return HostVerdict.EXPLOITABLE, shown, reasons + [
            "UseBASE64Intrinsics=true and UseAVX={} (AVX-512) - the vulnerable decode path is live "
            "on this JVM and CPU".format(avx_level)]

    # In range with the intrinsic on but the AVX level unreadable: cannot clear it.
    return HostVerdict.UNKNOWN, shown, reasons + [
        "build in range and the intrinsic is not disabled, but UseAVX could not be read - "
        "confirm the JVM is not forced below AVX-512"]


_VERDICT_COLOR = {
    HostVerdict.EXPLOITABLE: "1;31",
    HostVerdict.MITIGATED: "33",
    HostVerdict.NOT_EXPLOITABLE: "32",
    HostVerdict.UNKNOWN: "35",
}
_REMEDIATION = (
    "Upgrade to a patched JDK (Oracle 17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1 or your vendor's "
    "fixed build) and restart the JVM. As a stopgap, start it with -XX:-UseBASE64Intrinsics "
    "(or -XX:UseAVX=2 on x86-64).")


def run(argv=None):
    parser = argparse.ArgumentParser(
        prog="detect2shell --host-check",
        description="Local Java4Shell (CVE-2026-114938) exploitability check - asks the JVM directly. "
                    "Read-only: it only runs 'java -version' style print-and-exit commands.",
    )
    parser.add_argument("--java", action="append", dest="javas", metavar="PATH",
                        help="a java binary to check (repeatable); default: 'java' on PATH")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    args = parser.parse_args(argv)

    palette = report_mod.Palette(report_mod.color_enabled(args.no_color, stream=sys.stdout))
    binaries = args.javas or ["java"]

    print(palette.paint("Detect2Shell host-check - Java4Shell / CVE-2026-114938", "1;36"))
    print(palette.dim("asks each JVM for its build, UseBASE64Intrinsics and UseAVX - no network, no exploit"))
    print()

    worst = HostVerdict.NOT_EXPLOITABLE
    rank = {HostVerdict.NOT_EXPLOITABLE: 0, HostVerdict.MITIGATED: 1,
            HostVerdict.UNKNOWN: 2, HostVerdict.EXPLOITABLE: 3}
    any_exploitable = False

    for java_bin in binaries:
        resolved = shutil.which(java_bin) or java_bin
        verdict, version, reasons = assess(resolved)
        if rank[verdict] > rank[worst]:
            worst = verdict
        if verdict == HostVerdict.EXPLOITABLE:
            any_exploitable = True

        label = palette.paint(verdict, _VERDICT_COLOR[verdict])
        head = "  {}  {}".format(label, resolved)
        if version:
            head += palette.dim("  (JDK {})".format(version))
        print(head)
        for reason in reasons:
            print(palette.dim("      - " + reason))
        print()

    if worst in (HostVerdict.EXPLOITABLE, HostVerdict.UNKNOWN):
        print(palette.paint("remediation:", "1"))
        for line in textwrap.wrap(_REMEDIATION, 96):
            print("  " + line)
        print()

    print(palette.dim("note: check every JVM that serves untrusted input; a host can run several, "
                      "each with its own build and flags."))
    print(palette.dim("source + method: {}".format(REPO_URL)))

    return 1 if any_exploitable else 0


if __name__ == "__main__":
    sys.exit(run())
