"""Shared data types every check and the reporter agree on."""

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order[self]


class Confidence(enum.Enum):
    """How sure we are, worst to best. NOT_DETECTED and ERROR are first-class (not
    None) so a run distinguishes "looked, found nothing" from "could not look"."""

    ERROR = "error"
    NOT_DETECTED = "not_detected"
    POSSIBLE = "possible"      # the vulnerable component looks present, version unknown
    LIKELY = "likely"          # a version in the known-vulnerable range was observed
    CONFIRMED = "confirmed"    # a tier-2/3 probe proved the vulnerable path is live

    @property
    def rank(self) -> int:
        order = {
            Confidence.ERROR: -1,
            Confidence.NOT_DETECTED: 0,
            Confidence.POSSIBLE: 1,
            Confidence.LIKELY: 2,
            Confidence.CONFIRMED: 3,
        }
        return order[self]

    @property
    def is_positive(self) -> bool:
        return self.rank >= Confidence.POSSIBLE.rank


class Tier(enum.IntEnum):
    """Escalating levels of intrusiveness. Each is gated separately."""

    PASSIVE = 1   # read-only fingerprinting
    CONFIRM = 2   # benign out-of-band canary; nothing executes on the target
    PROVE = 3     # sends the real trigger to prove reachability, then aborts


@dataclass
class Finding:
    check: str
    name: str
    target: str
    confidence: Confidence
    severity: Severity
    tier: Tier
    cves: List[str] = field(default_factory=list)
    summary: str = ""
    evidence: List[str] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    note: str = ""   # advisory set when a deeper tier ran but could not confirm the finding

    def merge(self, other: "Finding") -> "Finding":
        """Fold a deeper-tier result into this one, keeping the strongest
        confidence and the union of evidence."""
        best, weak = (self, other) if self.confidence.rank >= other.confidence.rank else (other, self)
        merged_evidence = list(self.evidence)
        for line in other.evidence:
            if line not in merged_evidence:
                merged_evidence.append(line)
        return Finding(
            check=best.check,
            name=best.name,
            target=best.target,
            confidence=best.confidence,
            severity=best.severity,
            tier=Tier(max(self.tier, other.tier)),
            cves=best.cves or weak.cves,
            summary=best.summary,
            evidence=merged_evidence,
            remediation=best.remediation or weak.remediation,
            references=best.references or weak.references,
            # The advisory note follows the strongest finding only.
            note=best.note,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check": self.check,
            "name": self.name,
            "target": self.target,
            "confidence": self.confidence.value,
            "severity": self.severity.value,
            "tier": int(self.tier),
            "cves": list(self.cves),
            "summary": self.summary,
            "evidence": list(self.evidence),
            "remediation": self.remediation,
            "references": list(self.references),
            "note": self.note,
        }


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int

    @property
    def netloc(self) -> str:
        host = "[{}]".format(self.host) if ":" in self.host else self.host
        default = {"http": 80, "https": 443}.get(self.scheme)
        if self.port == default:
            return host
        return "{}:{}".format(host, self.port)

    @property
    def base_url(self) -> str:
        return "{}://{}".format(self.scheme, self.netloc)

    def url(self, path: str = "/") -> str:
        if not path.startswith("/"):
            path = "/" + path
        return self.base_url + path

    def __str__(self) -> str:
        return self.base_url
