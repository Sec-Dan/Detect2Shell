"""The Check contract and the registry of detectors.

A check overrides passive/confirm/prove and sets a few class attributes; `run`
walks the tiers, honours the consent gate, turns exceptions into ERROR findings,
and returns a single best result.
"""

from dataclasses import dataclass
from typing import List, Optional

from ..core.http import HttpClient, Response
from ..core.listener import CanaryListener
from ..core.models import Confidence, Finding, Severity, Target, Tier

_REGISTRY = {}


@dataclass
class CheckContext:
    client: HttpClient
    listener: Optional[CanaryListener] = None
    max_tier: Tier = Tier.PASSIVE
    allow_disruptive: bool = False
    verbose: bool = False

    def tier_allows(self, tier: Tier) -> bool:
        return int(self.max_tier) >= int(tier)

    def prove_allowed(self, check: "Check") -> bool:
        if not self.tier_allows(Tier.PROVE):
            return False
        if check.disruptive and not self.allow_disruptive:
            return False
        return True

    def get(self, target: Target, path: str = "/", **kwargs) -> Response:
        return self.client.get(target.url(path), **kwargs)


class Check:
    # --- identity / metadata, filled in by each subclass ---
    key: str = ""
    name: str = ""
    component: str = ""
    cves: List[str] = []
    aliases: List[str] = []
    references: List[str] = []
    severity: Severity = Severity.CRITICAL
    affected: str = ""
    remediation: str = ""

    # --- capability flags ---
    supports_confirm: bool = False
    supports_prove: bool = False
    disruptive: bool = False
    # Advisory appended when a deeper tier ran but could not strengthen a weak finding.
    probe_note: str = "Deeper tiers ran and added no remote proof."

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if getattr(cls, "key", ""):
            _REGISTRY[cls.key] = cls

    # --- helpers for building results ---
    def finding(self, target, confidence, tier, summary, evidence=None) -> Finding:
        return Finding(
            check=self.key,
            name=self.name,
            target=str(target),
            confidence=confidence,
            severity=self.severity,
            tier=tier,
            cves=list(self.cves),
            summary=summary,
            evidence=list(evidence or []),
            remediation=self.remediation,
            references=list(self.references),
        )

    def not_detected(self, target) -> Finding:
        return self.finding(target, Confidence.NOT_DETECTED, Tier.PASSIVE, "no indication of exposure")

    # --- tiers; override the ones that apply ---
    def passive(self, target: Target, ctx: CheckContext) -> Optional[Finding]:
        return None

    def confirm(self, target: Target, ctx: CheckContext) -> Optional[Finding]:
        return None

    def prove(self, target: Target, ctx: CheckContext) -> Optional[Finding]:
        return None

    # --- orchestration ---
    def run(self, target: Target, ctx: CheckContext) -> Finding:
        best = self._safe(self.passive, target, ctx, Tier.PASSIVE, "passive probe failed", None)

        ran_confirm = ran_prove = False
        if ctx.tier_allows(Tier.CONFIRM) and self.supports_confirm and ctx.listener is not None:
            ran_confirm = True
            best = self._safe(self.confirm, target, ctx, Tier.CONFIRM, "confirm probe failed", best)
        if self.supports_prove and ctx.prove_allowed(self):
            ran_prove = True
            best = self._safe(self.prove, target, ctx, Tier.PROVE, "prove probe failed", best)

        if best is None:
            best = self.not_detected(target)

        # Store the deepest tier we actually ran as the finding's tier, so the
        # reporter can show a probed: tag and a deeper run never looks passive.
        verdict_tier = best.tier
        attempted = Tier.PROVE if ran_prove else (Tier.CONFIRM if ran_confirm else Tier.PASSIVE)
        best.tier = Tier(max(int(best.tier), int(attempted)))

        # If a deeper tier ran but could not strengthen a weak reading, attach the
        # advisory note (the reporter shows it as its own block).
        if (best.confidence in (Confidence.POSSIBLE, Confidence.LIKELY)
                and int(attempted) > int(verdict_tier) and self.probe_note):
            best.note = self.probe_note

        return best

    @staticmethod
    def _tag(tier: Tier, line: str) -> str:
        label = {Tier.PASSIVE: "passive", Tier.CONFIRM: "confirm", Tier.PROVE: "prove"}.get(tier, "")
        if not label or line.lower().startswith(label + ":"):
            return line
        return "{}: {}".format(label, line)

    def _safe(self, method, target, ctx, tier, err_summary, best) -> Optional[Finding]:
        try:
            result = method(target, ctx)
        except Exception as exc:
            result = self.finding(
                target, Confidence.ERROR, tier, err_summary,
                ["{}: {}".format(type(exc).__name__, exc)],
            )
        if result is None:
            return best
        # Label each piece of evidence with the tier that produced it.
        result.evidence = [self._tag(tier, line) for line in result.evidence]
        return result if best is None else best.merge(result)


def all_checks() -> List[Check]:
    # Lazy import so the registry populates without a circular import.
    import detect2shell.checks  # noqa: F401
    return [cls() for _, cls in sorted(_REGISTRY.items())]


def select(only=None, exclude=None) -> List[Check]:
    checks = all_checks()
    if only:
        wanted = {k.strip().lower() for k in only}
        checks = [c for c in checks if c.key in wanted]
    if exclude:
        drop = {k.strip().lower() for k in exclude}
        checks = [c for c in checks if c.key not in drop]
    return checks
