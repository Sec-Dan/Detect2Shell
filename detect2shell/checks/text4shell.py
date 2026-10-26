"""Text4Shell - Apache Commons Text interpolation (CVE-2022-42889).

Confirms via the benign url lookup; never the script lookup, which is the RCE
primitive.
"""

from . import _probe
from .base import Check
from ..core.models import Confidence, Severity, Tier

_JAVA_TELLS = [
    "apache-coyote", "tomcat", "jetty", "wildfly", "jboss", "glassfish",
    "resin", "servlet", "jsessionid",
]


class Text4Shell(Check):
    key = "text4shell"
    name = "Text4Shell"
    component = "Apache Commons Text"
    cves = ["CVE-2022-42889"]
    severity = Severity.CRITICAL
    affected = "commons-text 1.5 - 1.9 (default script/dns/url lookups in createInterpolator)"
    remediation = "Upgrade Apache Commons Text to >= 1.10.0 (lookups disabled by default)."
    references = [
        "https://commons.apache.org/proper/commons-text/security.html",
        "https://nvd.nist.gov/vuln/detail/CVE-2022-42889",
    ]
    supports_confirm = True
    supports_prove = True
    disruptive = False

    def passive(self, target, ctx):
        resp = ctx.get(target)
        if not resp.ok:
            return None
        blob = " ".join([
            (resp.header("server") or ""),
            (resp.header("x-powered-by") or ""),
            (resp.header("set-cookie") or ""),
            resp.text[:2000],
        ]).lower()
        tells = sorted({t for t in _JAVA_TELLS if t in blob})
        leaks_class = "stringsubstitutor" in blob or "org.apache.commons.text" in blob
        if leaks_class:
            return self.finding(
                target, Confidence.POSSIBLE, Tier.PASSIVE,
                "Apache Commons Text is present (version not remotely visible; 1.10+ ships the same classes with the "
                "lookups disabled) - confirm the version host-side.",
                ["commons-text class name leaked in a response"],
            )
        if not tells:
            return self.not_detected(target)
        return self.finding(
            target, Confidence.POSSIBLE, Tier.PASSIVE,
            "Java web stack present; commons-text is transitive and not remotely version-fingerprintable. Confirm host-side (SBOM or dependency scan).",
            ["stack tells: " + ", ".join(tells)],
        )

    def confirm(self, target, ctx):
        # The url lookup fetches an HTTP URL, so we point it at the HTTP canary.
        return _probe.oob_confirm(
            self, target, ctx,
            build_value=lambda url, _unused, token: "${url:UTF-8:%s}" % url,
            kind="http",
            tier=Tier.CONFIRM,
            summary="Target fetched the canary URL via a commons-text url lookup - the interpolation path is live.",
        )

    def prove(self, target, ctx):
        value = "${url:UTF-8:http://d2s-detect.invalid/}"
        # Differential vs the inner URL with no ${url:...} wrapper, so an app that
        # fetches a URL from ?q= on its own is not misread as commons-text.
        control = "http://d2s-detect.invalid/"
        baseline = ctx.get(target)
        base_text = baseline.text.lower() if baseline.ok else ""
        # "error looking up url" is commons-text's own UrlStringLookup failure.
        signatures = ["error looking up url", "unknownhostexception", "malformedurlexception"]
        leaked = _probe.differential_signatures(ctx, target, value, control, signatures, base_text)
        if leaked:
            return self.finding(
                target, Confidence.LIKELY, Tier.PROVE,
                "A benign url lookup drew out an interpolation error that an identical URL without the lookup wrapper did not - commons-text lookups are enabled.",
                ["url-lookup error signature '{}' followed the payload but not the control".format(leaked[0])],
            )
        return None
