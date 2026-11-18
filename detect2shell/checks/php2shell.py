"""PHP2Shell - two PHP core request-lifecycle memory-safety bugs
(CVE-2026-109618 / CVE-2026-109619). Per the php.net advisories: 109618 is
state corruption when an out-of-memory bailout leaves request data
half-initialised, and 109619 is a use-after-free of request state that a later
request on the same worker reads (the session upload-progress path is one such
reader, not the bug itself). Recon only: the triggering condition makes a
patched build fail the same way (500, or a 502 when the worker is killed), so a
remote probe cannot tell patched from vulnerable. Defers to a host-side version
check.
"""

import re

from .base import Check
from ..core.models import Confidence, Severity, Tier

# First fixed release per branch.
_FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}


def _php_affected(version):
    branch = version[:2]
    if branch in _FIXED:
        return version < _FIXED[branch]
    # Branches older than 8.2 are EOL and broadly affected; 8.6+ is unknown here.
    return version < (8, 2, 0)


class PHP2Shell(Check):
    key = "php2shell"
    name = "PHP2Shell"
    component = "PHP core (request-lifecycle state handling)"
    cves = ["CVE-2026-109618", "CVE-2026-109619"]
    severity = Severity.CRITICAL
    affected = "PHP < 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (unofficial backports exist for 7.4 / 8.0 / 8.1)"
    remediation = ("Upgrade PHP to >= 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (or the vendor-backported "
                   "package) and restart every worker; no config-only fix is complete.")
    references = [
        "https://www.php.net/archive/2026.php#2026-10-21-5",
        "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
        "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
        "https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/",
    ]
    supports_confirm = False
    supports_prove = True
    disruptive = False
    probe_note = ("This is a memory-safety bug, and the input that triggers it also makes a *patched* PHP fail "
                  "(a 500, or a 502 when the worker is killed) - so there is no remote probe that tells patched "
                  "from vulnerable without driving the exploit, which this detector does not do. Take the "
                  "signatures above as \"could be vulnerable\" and confirm the installed PHP version host-side.")

    def passive(self, target, ctx):
        resp = ctx.get(target)
        if not resp.ok:
            return None
        banner = " ".join([resp.header("x-powered-by") or "", resp.header("server") or ""])
        match = re.search(r"php/(\d+)\.(\d+)\.(\d+)", banner, re.I)
        set_cookie = (resp.header("set-cookie") or "").lower()
        blob = resp.text[:4000].lower()
        php_present = bool(match) or "phpsessid" in set_cookie or any(
            m in blob for m in ("wordpress", "drupal", "laravel", "/wp-json", "x-pingback")
        )

        if match:
            version = tuple(int(g) for g in match.groups())
            vstr = "{}.{}.{}".format(*version)
            if _php_affected(version):
                return self.finding(
                    target, Confidence.LIKELY, Tier.PASSIVE,
                    "PHP {} banner is within the affected range - note distros backport the fix without bumping "
                    "the version string, so verify via the package changelog.".format(vstr),
                    ["version banner: PHP/{}".format(vstr)],
                )
            if version[:2] not in _FIXED:
                return self.finding(
                    target, Confidence.POSSIBLE, Tier.PASSIVE,
                    "PHP {} is on a branch this build has no fix data for - verify the patch level host-side.".format(vstr),
                    ["version banner: PHP/{}".format(vstr)],
                )
            return self.finding(
                target, Confidence.NOT_DETECTED, Tier.PASSIVE,
                "PHP {} banner is at or above the fixed release (still verify backports host-side).".format(vstr),
                ["version banner: PHP/{}".format(vstr)],
            )
        if php_present:
            tells = []
            if "phpsessid" in set_cookie:
                tells.append("PHPSESSID cookie")
            if any(m in blob for m in ("wordpress", "drupal", "laravel", "/wp-json", "x-pingback")):
                tells.append("PHP app markers")
            return self.finding(
                target, Confidence.POSSIBLE, Tier.PASSIVE,
                "PHP application detected but no version banner; patch level is not remotely visible. Confirm the PHP version host-side.",
                ["PHP tells: " + (", ".join(tells) or "generic")],
            )
        return self.not_detected(target)

    def prove(self, target, ctx):
        # Recon only: no safe remote proof of a memory-safety bug (see probe_note).
        return None
