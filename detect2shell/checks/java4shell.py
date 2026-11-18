"""Java4Shell / Java2Shell - a heap overflow in HotSpot's AVX-512 Base64 decode
intrinsic (CVE-2026-114938), reachable wherever a JVM Base64-decodes untrusted
input on an AVX-512 VBMI CPU. Recon only: no safe remote proof.
"""

import json
import re

from .base import Check
from ..core.models import Confidence, Severity, Tier

_JAVA_TELLS = [
    "apache-coyote", "tomcat", "jetty", "wildfly", "jboss", "glassfish",
    "resin", "servlet", "jsessionid", "whitelabel error page",
]

# Products with a reported pre-auth path to the decoder. Each entry is a header
# name to look for, or a body/cookie substring.
_PRODUCT_HEADERS = {
    "x-jenkins": "Jenkins",
    "x-confluence-request-time": "Confluence",
    "x-arequestid": "Jira",
    "x-artifactory-id": "Artifactory",
}
_PRODUCT_MARKERS = {
    "keycloak": "Keycloak",
    "atlassian.xsrf.token": "Jira/Confluence",
    "pingfederate": "PingFederate",
    "jfrog": "Artifactory",
}

# Last vulnerable public release per feature line (the builds the CVE record
# names); builds above these carry the fix. The 17 line is affected from 17.0.6
# (Red Hat, oss-security). Standard Java 8 and 11 never had the vulnerable path;
# the Oracle 8u511b33-perf build did, but it does not leak a parseable version.
_LAST_VULNERABLE = {17: (17, 0, 21), 21: (21, 0, 13), 25: (25, 0, 5), 27: (27, 0, 1)}
_FIRST_VULNERABLE = {17: (17, 0, 6)}

# How many trigger-shaped requests the opt-in disruption probe sends. Kept
# modest: it is a "did it fall over" check, not a flood.
_DISRUPTION_BURST = 40


def _jdk_status(version):
    """'affected', 'fixed', 'unaffected' or 'unknown' for an (major, minor, patch) tuple."""
    major = version[0]
    if major < 17 or version < _FIRST_VULNERABLE.get(major, (0,)):
        return "unaffected"
    if major in _LAST_VULNERABLE:
        return "affected" if version <= _LAST_VULNERABLE[major] else "fixed"
    # Non-LTS lines (18-20, 22-24, 26) are EOL and carry the same intrinsic.
    return "affected" if major < 27 else "unknown"


def _parse_jdk(text):
    m = re.search(r"(?<![\w.])(\d+)(?:\.(\d+))?(?:\.(\d+))?", text or "")
    if not m:
        return None
    return tuple(int(g) if g else 0 for g in m.groups())


class Java4Shell(Check):
    key = "java4shell"
    name = "Java4Shell"
    component = "OpenJDK / HotSpot JVM (x86-64 AVX-512 Base64 intrinsic)"
    cves = ["CVE-2026-114938"]
    aliases = ["Java2Shell"]
    severity = Severity.CRITICAL
    affected = ("OpenJDK 17.0.6-17.0.21, 21 <= 21.0.13, 25 <= 25.0.5, 27 <= 27.0.1, Oracle 8u511b33-perf "
                "(and every downstream build: Temurin, Corretto, Zulu, Microsoft, Liberica, SapMachine, Red Hat, "
                "GraalVM) on x86-64 CPUs with AVX-512 VBMI; standard Java 8 and 11 are not affected")
    remediation = ("Upgrade the JDK to Oracle 17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1 or your vendor's "
                   "patched build and restart every JVM. Until then, start the JVM with "
                   "-XX:-UseBASE64Intrinsics (or -XX:UseAVX=2 on x86-64 only).")
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-114938",
        "https://www.oracle.com/security-alerts/cspunov2026.html",
        "https://access.redhat.com/security/cve/cve-2026-114938",
        "https://calif.io/java4shell/",
        "https://www.cisa.gov/news-events/alerts/2026/11/17/critical-java-vulnerability-requires-immediate-patching",
    ]
    supports_confirm = False
    supports_prove = True
    disruptive = False
    probe_note = ("This is a memory-safety bug in the JVM - confirming it would mean running the full exploit "
                  "chain to code execution, which this detector deliberately does not carry. Exposure also "
                  "depends on the host CPU (AVX-512 VBMI) and JVM flags, neither of which is remotely visible. "
                  "Take the signatures above as \"could be vulnerable\" and get the definitive yes/no on the box "
                  "itself: run 'detect2shell --host-check', which asks the JVM for its build, UseBASE64Intrinsics "
                  "and UseAVX and reports whether the vulnerable path is actually live.")

    def passive(self, target, ctx):
        resp = ctx.get(target)
        if not resp.ok:
            return None
        blob = " ".join([
            resp.header("server") or "",
            resp.header("x-powered-by") or "",
            resp.header("set-cookie") or "",
            resp.text[:4000],
        ]).lower()

        tells = sorted({t for t in _JAVA_TELLS if t in blob})
        products = {label for h, label in _PRODUCT_HEADERS.items() if h in resp.headers}
        products |= {label for m, label in _PRODUCT_MARKERS.items() if m in blob}

        version = self._jvm_version(target, ctx)
        if version:
            vstr = ".".join(str(p) for p in version)
            status = _jdk_status(version)
            evidence = ["JVM version leak: {}".format(vstr)]
            if status == "affected":
                return self.finding(
                    target, Confidence.LIKELY, Tier.PASSIVE,
                    "JVM {} is within the affected range. Exposure also needs an AVX-512 VBMI CPU, and some "
                    "vendors ship the fix without changing the version string - verify host-side.".format(vstr),
                    evidence,
                )
            if status == "unknown":
                return self.finding(
                    target, Confidence.POSSIBLE, Tier.PASSIVE,
                    "JVM {} is on a line this build has no fix data for - verify the build host-side.".format(vstr),
                    evidence,
                )
            return self.finding(
                target, Confidence.NOT_DETECTED, Tier.PASSIVE,
                "JVM {} is outside the affected range.".format(vstr), evidence,
            )

        if not tells and not products:
            return self.not_detected(target)
        evidence = []
        if products:
            evidence.append("products with a reported pre-auth decode path: " + ", ".join(sorted(products)))
        if tells:
            evidence.append("stack tells: " + ", ".join(tells))
        return self.finding(
            target, Confidence.POSSIBLE, Tier.PASSIVE,
            "Java service detected; the JDK build and host CPU are not remotely visible. Confirm the JDK "
            "version, CPU flags (avx512vbmi) and -XX options host-side.",
            evidence,
        )

    @staticmethod
    def _jvm_version(target, ctx):
        # Solr's system-info endpoint reports the running JVM when it is left open.
        resp = ctx.get(target, "/solr/admin/info/system?wt=json")
        if not resp.ok or resp.status != 200:
            return None
        try:
            jvm = json.loads(resp.text).get("jvm", {})
        except (ValueError, AttributeError):
            return None
        return _parse_jdk(str(jvm.get("version", "")))

    # A Basic-auth token shaped like the public trigger: a long Base64 string
    # ending in padding. It carries no memory-control content - it exists only
    # to see whether this input path is filtered at the edge or reaches the
    # application's Base64 decoder. Real credentials are far shorter.
    _TRIGGER_TOKEN = "A" * 128 + "="
    # Statuses a gateway/WAF returns when it refuses a request itself, rather
    # than the app's own 401 for a bad credential.
    _EDGE_BLOCK_STATUSES = {403, 406, 429, 451, 501, 406}

    def prove(self, target, ctx):
        # Two non-weaponised steps. The edge probe sends ONE trigger-shaped
        # request to see if a WAF shields the decode path (the common "is my WAF
        # catching this?" question). Only under --allow-disruptive does it then
        # send a bounded burst to see whether the service can be knocked over.
        # Neither step steers memory corruption or reads leaked bytes.
        if not self._has_basic_auth(target, ctx):
            return None  # no HTTP Basic-auth decode path to probe here
        verdict = self._edge_probe(target, ctx)
        if verdict is None:
            return None
        finding, reached = verdict
        if reached and ctx.allow_disruptive:
            disrupted = self._disruption_probe(target, ctx)
            if disrupted:
                return disrupted
            finding.evidence.append(
                "disruptive burst sent; the service stayed up - inconclusive (could be patched, "
                "mitigated by -XX flags, on a non-AVX-512 host, or simply not warmed/unlucky)")
        return finding

    @staticmethod
    def _has_basic_auth(target, ctx):
        """True when the server challenges HTTP Basic auth. That is the input
        path this probe exercises, and gating on it keeps the probe off the
        many servers that have no Base64-decoding auth surface at all."""
        resp = ctx.get(target)
        return "basic" in (resp.header("www-authenticate") or "").lower()

    def _edge_probe(self, target, ctx):
        """One trigger-shaped Basic-auth request vs a normal short one. Tells a
        WAF/edge block from the request reaching the application."""
        normal = ctx.client.get(target.url("/"), headers={"Authorization": "Basic YWRtaW46ZDJz"})
        trigger = ctx.client.get(target.url("/"), headers={"Authorization": "Basic " + self._TRIGGER_TOKEN})
        if trigger.status is None:
            return None
        # A gateway that passes a normal login but refuses the trigger shape is
        # filtering this input at the edge.
        blocked = (trigger.status in self._EDGE_BLOCK_STATUSES
                   and normal.status not in self._EDGE_BLOCK_STATUSES)
        if blocked:
            return (self.finding(
                target, Confidence.POSSIBLE, Tier.PROVE,
                "A trigger-shaped Basic-auth token was blocked at the edge ({}) while a normal login passed "
                "({}) - a WAF or gateway is shielding this input path. Note this covers only the path and "
                "input tested; the decoder is also reachable via JWTs, upload fields and other decoders.".format(
                    trigger.status, normal.status),
                ["edge blocked the trigger-shaped Authorization header (status {})".format(trigger.status)],
            ), False)
        # Otherwise the request reached the app (its own 401/200/404 for the token).
        return (self.finding(
            target, Confidence.POSSIBLE, Tier.PROVE,
            "A trigger-shaped Basic-auth token reached the application (status {}), so this input path feeds "
            "the Java Base64 decoder unfiltered. On a vulnerable JVM that path is exploitable; confirm the JDK "
            "build and -XX flags host-side.".format(trigger.status),
            ["trigger-shaped Authorization header reached the app (status {})".format(trigger.status)],
        ), True)

    def _disruption_probe(self, target, ctx):
        """A bounded burst of trigger-shaped requests, watching only for the
        service failing (reset / 5xx / no response). It never inspects response
        bytes for leaked memory and never drives the corruption further. A hit
        means the operator's opted-in disruption actually took the target down."""
        failures = 0
        for _ in range(_DISRUPTION_BURST):
            resp = ctx.client.get(target.url("/"), headers={"Authorization": "Basic " + self._TRIGGER_TOKEN})
            if resp.status is None or resp.status >= 500:
                failures += 1
        if failures == 0:
            return None
        return self.finding(
            target, Confidence.CONFIRMED, Tier.PROVE,
            "A disruptive burst of trigger-shaped requests made the service fail ({}/{} requests returned no "
            "response or a 5xx) - the vulnerable decode path is reachable and the service was disrupted. "
            "No memory was read and the exploit was not driven further.".format(failures, _DISRUPTION_BURST),
            ["{}/{} trigger-shaped requests drew a reset or 5xx under --allow-disruptive".format(
                failures, _DISRUPTION_BURST)],
        )
