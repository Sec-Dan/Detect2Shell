"""Authorisation and the tiered consent gate: no network until the operator
confirms permission, and the deeper the probe the louder the consent demanded.
"""

import ipaddress
import sys
from dataclasses import dataclass, field
from typing import List, Optional

from .models import Target, Tier

DISCLAIMER = """\
Detect2Shell checks whether a service is exposed to the *2Shell / *4Shell family
of remote code execution bugs. It is for AUTHORISED testing only.

  * Only scan systems you own or have explicit, documented permission to test.
  * Every request is tagged with this tool's name and your scanner's IP so the
    owner can see the traffic for what it is.
  * Even the passive checks contact the target. Scanning without authorisation
    may be unlawful in your jurisdiction. You are responsible for your use.
  * Provided as-is, with no warranty. The authors accept no liability for any
    damage, disruption or legal consequence of its use or misuse.
  * Results are best-effort. A clean result is not proof of safety: the tool
    probes a limited surface and can miss real exposure. Check host-side before
    you trust a "not detected".

This tool is a detector. It proves exposure and stops; it never opens a shell.
"""

CONSENT_PHRASE = "I AM AUTHORISED"


@dataclass
class Authorisation:
    authorised: bool
    max_tier: Tier
    allow_disruptive: bool
    scope: List[str] = field(default_factory=list)


class NotAuthorised(Exception):
    """Raised when active scanning is requested without consent in a context
    where we cannot (or should not) ask interactively."""


def _match_scope(target: Target, pattern: str) -> bool:
    pattern = pattern.strip()
    if not pattern or pattern.startswith("#"):
        return False
    # CIDR / single address
    if "/" in pattern:
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            return ipaddress.ip_address(target.host) in net
        except ValueError:
            return False
    # Wildcard suffix, e.g. *.example.com
    if pattern.startswith("*."):
        return target.host.lower().endswith(pattern[1:].lower())
    # Exact host, or the same IP in a different form (::1 == 0:0:0:0:0:0:0:1);
    # else a case-insensitive name compare.
    try:
        return ipaddress.ip_address(target.host) == ipaddress.ip_address(pattern)
    except ValueError:
        return target.host.lower() == pattern.lower()


def load_scope(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip() and not line.startswith("#")]


def filter_in_scope(targets: List[Target], scope: List[str]):
    """Split targets into (allowed, rejected); an empty scope allows everything."""
    if not scope:
        return list(targets), []
    allowed, rejected = [], []
    for target in targets:
        if any(_match_scope(target, pat) for pat in scope):
            allowed.append(target)
        else:
            rejected.append(target)
    return allowed, rejected


def requested_tier(args) -> Tier:
    if getattr(args, "prove", False):
        return Tier.PROVE
    if getattr(args, "confirm", False):
        return Tier.CONFIRM
    return Tier.PASSIVE


def resolve(args, is_tty: bool) -> Authorisation:
    """Decide what the run is allowed to do. --i-am-authorised is non-interactive
    consent; on a TTY without it we ask once, elsewhere no flag means no scan.
    """
    tier = requested_tier(args)
    scope = []
    if getattr(args, "scope", None):
        scope = load_scope(args.scope)

    authorised = bool(getattr(args, "i_am_authorised", False))
    if not authorised:
        if is_tty:
            sys.stderr.write(
                "\nConfirm you have explicit authorisation to scan these targets.\n"
                'Type "{}" to continue: '.format(CONSENT_PHRASE)
            )
            sys.stderr.flush()
            try:
                answer = sys.stdin.readline().strip()
            except (EOFError, KeyboardInterrupt):
                answer = ""
            authorised = answer.upper() == CONSENT_PHRASE
        else:
            raise NotAuthorised(
                "authorisation required: pass --i-am-authorised to confirm you "
                "are permitted to scan these targets"
            )

    allow_disruptive = bool(getattr(args, "allow_disruptive", False))
    # Only ask the second, disruptive-risk question once the operator is authorised.
    if authorised and is_tty and tier >= Tier.PROVE and allow_disruptive and not getattr(args, "i_am_authorised", False):
        sys.stderr.write(
            "\n--allow-disruptive lets prove-tier checks crash a target worker.\n"
            'Type "{}" again to accept that risk: '.format(CONSENT_PHRASE)
        )
        sys.stderr.flush()
        try:
            answer = sys.stdin.readline().strip()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        allow_disruptive = answer.upper() == CONSENT_PHRASE

    return Authorisation(
        authorised=authorised,
        max_tier=tier if authorised else Tier.PASSIVE,
        allow_disruptive=allow_disruptive,
        scope=scope,
    )
