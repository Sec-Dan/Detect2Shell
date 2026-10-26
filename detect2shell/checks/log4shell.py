"""Log4Shell - the Apache Log4j2 JNDI lookup family."""

from . import _probe
from .base import Check
from ..core.models import Confidence, Severity, Tier

_JAVA_TELLS = [
    "apache-coyote", "tomcat", "jetty", "wildfly", "jboss", "glassfish",
    "resin", "servlet", "jsessionid", "whitelabel error page", "solr",
]


class Log4Shell(Check):
    key = "log4shell"
    name = "Log4Shell"
    component = "Apache Log4j2 (log4j-core)"
    cves = ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-44832"]
    severity = Severity.CRITICAL
    affected = "log4j-core < 2.17.1 (Java 8+), < 2.12.4 (Java 7), < 2.3.2 (Java 6)"
    remediation = ("Upgrade log4j-core to 2.17.1+ (2.12.4 on Java 7, 2.3.2 on Java 6); "
                   "where blocked, remove org/apache/logging/log4j/core/lookup/JndiLookup.class.")
    references = [
        "https://logging.apache.org/log4j/2.x/security.html",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
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
        if not tells:
            return self.not_detected(target)
        return self.finding(
            target, Confidence.POSSIBLE, Tier.PASSIVE,
            "Java web stack present; log4j-core cannot be version-fingerprinted remotely. Confirm host-side (SBOM or dependency scan).",
            ["stack tells: " + ", ".join(tells)],
        )

    def confirm(self, target, ctx):
        return _probe.oob_confirm(
            self, target, ctx,
            build_value=lambda host, port, token: "${jndi:ldap://%s:%s/%s}" % (host, port, token),
            kind="raw",
            tier=Tier.CONFIRM,
            summary="Target made an out-of-band JNDI lookup to the canary - the Log4j lookup path is live.",
        )

    def prove(self, target, ctx):
        # Unroutable lookup; read back only whether the app surfaced a JNDI error.
        marker = "d2s" + format(abs(hash((target.base_url, self.key))) & 0xFFFFFF, "x")
        value = "${jndi:ldap://localhost:1/%s}" % marker
        # Differential vs a benign same-shape control, so a directory search or
        # WAF error on ?q= is not misread as a live Log4j lookup.
        control = "jndi-ldap-d2s-%s" % marker
        baseline = ctx.get(target)
        base_text = baseline.text.lower() if baseline.ok else ""
        signatures = ["jndilookup", "javax.naming", "namingexception", "jndimanager", "error looking up jndi"]
        leaked = _probe.differential_signatures(ctx, target, value, control, signatures, base_text)
        if leaked:
            return self.finding(
                target, Confidence.LIKELY, Tier.PROVE,
                "A ${jndi:...} token drew out a JNDI lookup error that an identical-shape benign control did not - Log4j is evaluating lookups on reachable input.",
                ["JNDI/Naming error signature '{}' followed the payload but not the control".format(leaked[0])],
            )
        return None
