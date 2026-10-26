"""Render findings for humans, and as JSON for pipelines."""

import json
import os
import shutil
import sys
import textwrap
import time
from typing import Dict, List, Optional

from .. import __version__
from .models import Confidence, Finding, Severity, Tier

_RESET = "\033[0m"

_SEV_COLOR = {
    Severity.CRITICAL: "1;31",
    Severity.HIGH: "31",
    Severity.MEDIUM: "33",
    Severity.LOW: "36",
    Severity.INFO: "2",
}

_CONF_COLOR = {
    Confidence.CONFIRMED: "1;31",
    Confidence.LIKELY: "33",
    Confidence.POSSIBLE: "36",
    Confidence.NOT_DETECTED: "32",
    Confidence.ERROR: "35",
}

_CONF_MARK = {
    Confidence.CONFIRMED: "●",
    Confidence.LIKELY: "◆",
    Confidence.POSSIBLE: "○",
    Confidence.NOT_DETECTED: "·",
    Confidence.ERROR: "✗",
}

# Tag colour per active tier (prove loudest); passive carries no tag.
_TIER_TAG_COLOR = {
    Tier.CONFIRM: "36",
    Tier.PROVE: "1;35",
}


class Palette:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def paint(self, text: str, code: str) -> str:
        if not self.enabled or not code:
            return text
        return "\033[{}m{}{}".format(code, text, _RESET)

    def sev(self, severity: Severity) -> str:
        return self.paint(severity.value.upper(), _SEV_COLOR[severity])

    def conf(self, confidence: Confidence) -> str:
        label = confidence.value.replace("_", " ").upper()
        return self.paint(label, _CONF_COLOR[confidence])

    def dim(self, text: str) -> str:
        return self.paint(text, "2")


def color_enabled(no_color_flag: bool, stream=sys.stdout) -> bool:
    if no_color_flag or os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _group_by_target(findings: List[Finding]) -> "Dict[str, List[Finding]]":
    grouped: Dict[str, List[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.target, []).append(finding)
    for items in grouped.values():
        # Worst first; check key as a stable tiebreaker for deterministic order.
        items.sort(key=lambda f: (-f.confidence.rank, -f.severity.rank, f.check))
    return grouped


def _cell(palette: Palette, text: str, code: str, width: int) -> str:
    """Pad to `width` by visible text, then colour, so columns align with colour on or off."""
    pad = max(0, width - len(text))
    return palette.paint(text, code) + (" " * pad)


def _term_width() -> int:
    try:
        cols = shutil.get_terminal_size((80, 24)).columns
    except Exception:
        cols = 80
    return max(60, min(cols, 100))


def _wrap(text: str, width: int, indent: int, bullet: str = "") -> List[str]:
    """Word-wrap `text` with a hanging indent under its label."""
    first = " " * indent + bullet
    cont = " " * (indent + len(bullet))
    return textwrap.fill(
        text or "",
        width=max(40, width),
        initial_indent=first,
        subsequent_indent=cont,
        break_long_words=False,
        break_on_hyphens=False,
    ).split("\n")


def _render_finding(finding: Finding, palette: Palette, width: int, verbose: bool) -> List[str]:
    out: List[str] = [""]
    mark = palette.paint(_CONF_MARK[finding.confidence], _CONF_COLOR[finding.confidence])
    conf = _cell(palette, finding.confidence.value.replace("_", " ").upper(), _CONF_COLOR[finding.confidence], 12)
    check = _cell(palette, finding.check, "1;37", 13)
    sev = palette.paint(finding.severity.value.upper(), _SEV_COLOR[finding.severity])
    out.append("  {}  {} {} {}".format(mark, conf, check, sev).rstrip())

    if finding.cves:
        for ln in _wrap(", ".join(finding.cves), width, 5):
            out.append(palette.dim(ln))
    tag_code = _TIER_TAG_COLOR.get(finding.tier)
    if tag_code:
        out.append("     " + palette.paint("probed: " + finding.tier.name.lower(), tag_code))

    if finding.summary:
        out.append("")
        out.extend(_wrap(finding.summary, width, 5))

    if finding.note:
        out.append("")
        out.append("     " + palette.paint("not remotely confirmed", "33"))
        out.extend(_wrap(finding.note, width, 7))

    if finding.evidence:
        out.append("")
        out.append("     " + palette.dim("evidence"))
        for item in finding.evidence:
            out.extend(_wrap(item, width, 7, "· "))

    if finding.confidence.is_positive and finding.remediation:
        out.append("")
        out.append("     " + palette.dim("fix"))
        out.extend(_wrap(finding.remediation, width, 7))

    if verbose and finding.references:
        out.append("")
        out.append("     " + palette.dim("refs"))
        for ref in finding.references:
            for ln in _wrap(ref, width, 7, "· "):
                out.append(palette.dim(ln))
    return out


def render(findings: List[Finding], palette: Palette, show_clean: bool = False, verbose: bool = False) -> str:
    width = _term_width()
    grouped = _group_by_target(findings)
    lines: List[str] = []
    for target in sorted(grouped):
        items = grouped[target]
        shown = items if show_clean else [
            f for f in items if f.confidence.is_positive or f.confidence == Confidence.ERROR
        ]
        lines.append("")
        lines.append("{} {}".format(palette.paint("▸", "1;37"), palette.paint(target, "1;37")))
        if not shown:
            lines.append("     " + palette.dim("no exposure detected on the surface checked"))
            continue
        for finding in shown:
            lines.extend(_render_finding(finding, palette, width, verbose))
    return "\n".join(lines)


def summary_line(findings: List[Finding], palette: Palette, target_count: int, check_count: int) -> str:
    counts = {c: 0 for c in Confidence}
    for finding in findings:
        counts[finding.confidence] += 1
    parts = [
        palette.paint("{} confirmed".format(counts[Confidence.CONFIRMED]), _CONF_COLOR[Confidence.CONFIRMED]),
        palette.paint("{} likely".format(counts[Confidence.LIKELY]), _CONF_COLOR[Confidence.LIKELY]),
        palette.paint("{} possible".format(counts[Confidence.POSSIBLE]), _CONF_COLOR[Confidence.POSSIBLE]),
    ]
    tail = palette.dim("{} target{} · {} checks · {} errors".format(
        target_count, "" if target_count == 1 else "s", check_count, counts[Confidence.ERROR]))
    rule = palette.dim("─" * _term_width())
    caveat = palette.dim(textwrap.fill(
        "A clean result is not proof of safety: Detect2Shell probes a limited "
        "surface at the tiers you ran and can miss real exposure. Confirm "
        "component versions host-side before relying on a clean result.",
        width=_term_width(),
        break_long_words=False,
        break_on_hyphens=False,
    ))
    summary = rule + "\n" + "Summary:  " + "   ".join(parts) + "    " + tail
    return summary + "\n" + caveat


def build_report(findings: List[Finding], meta: Dict) -> Dict:
    # Deterministic order so the JSON is stable across concurrent runs.
    ordered = sorted(
        findings,
        key=lambda f: (f.target, -f.confidence.rank, -f.severity.rank, f.check),
    )
    return {
        "tool": "detect2shell",
        "version": __version__,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "meta": meta,
        "findings": [f.to_dict() for f in ordered],
    }


def write_json(path: str, findings: List[Finding], meta: Dict) -> None:
    report = build_report(findings, meta)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=False)
        handle.write("\n")


def exit_code(findings: List[Finding]) -> int:
    """0 = nothing found, 1 = something exposed, 2 = only errors."""
    has_positive = any(f.confidence.is_positive for f in findings)
    has_error = any(f.confidence == Confidence.ERROR for f in findings)
    if has_positive:
        return 1
    if has_error:
        return 2
    return 0
