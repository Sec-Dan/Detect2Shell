"""Spring4Shell - Spring Framework data binding (CVE-2022-22965) and Spring
Cloud Function SpEL (CVE-2022-22963).
"""

import re

from . import _probe
from .base import Check
from ..core.models import Confidence, Severity, Tier


class Spring4Shell(Check):
    key = "spring4shell"
    name = "Spring4Shell"
    component = "Spring Framework / Spring Cloud Function"
    cves = ["CVE-2022-22965", "CVE-2022-22963"]
    severity = Severity.CRITICAL
    affected = ("Spring Framework 5.3.0-5.3.17 / 5.2.0-5.2.19 (JDK 9+, WAR on Tomcat); "
                "Spring Cloud Function <= 3.1.6 and 3.2.0-3.2.2")
    remediation = ("Upgrade Spring Framework to >= 5.3.18 / 5.2.20 (Spring Boot >= 2.5.12 / 2.6.6); "
                   "Spring Cloud Function to >= 3.1.7 / 3.2.3.")
    references = [
        "https://spring.io/security/cve-2022-22965",
        "https://spring.io/security/cve-2022-22963",
    ]
    supports_confirm = True
    supports_prove = True
    disruptive = False

    def confirm(self, target, ctx):
        # CVE-2022-22963: a benign SpEL expression fetches the canary - a network
        # callback, never a command or shell.
        listener = ctx.listener
        if listener is None:
            return None
        token = listener.new_http_token()
        spel = "new java.net.URL('%s').openStream()" % listener.http_callback_url(token)
        # Case-sensitive header: urllib title-cases names and Spring would miss
        # it, so send verbatim via the case-preserving client.
        headers = {"spring.cloud.function.routing-expression": spel, "Content-Type": "text/plain"}
        ctx.client.request_raw_headers("POST", target.url("/functionRouter"), headers=headers, data=b"d2s")
        hit = listener.wait_http(token)
        if hit:
            return self.finding(
                target, Confidence.CONFIRMED, Tier.CONFIRM,
                "A benign SpEL expression in the routing-expression header made the target fetch the "
                "canary - Spring Cloud Function is evaluating attacker-controlled expressions "
                "(CVE-2022-22963). No command was run and no shell was taken.",
                ["out-of-band {} callback from {} (token {})".format(hit.kind, hit.peer_ip, token)],
            )
        return None

    def passive(self, target, ctx):
        resp = ctx.get(target)
        health = ctx.get(target, "/actuator/health")
        tells = []
        if resp.ok:
            body = resp.text[:4000].lower()
            if "whitelabel error page" in body or "this application has no explicit mapping for /error" in body:
                tells.append("spring boot whitelabel error page")
            if resp.header("x-application-context"):
                tells.append("x-application-context header")
            if '"timestamp"' in body and '"status"' in body and '"path"' in body:
                tells.append("spring default error json")
        if health.ok and '"status"' in health.text.lower() and '"up"' in health.text.lower():
            tells.append("/actuator/health up")
        if not tells:
            return self.not_detected(target)
        return self.finding(
            target, Confidence.POSSIBLE, Tier.PASSIVE,
            "Spring Boot application detected; patch level is not remotely visible. Confirm host-side (deployed version or dependency scan).",
            ["stack tells: " + ", ".join(sorted(set(tells)))],
        )

    def prove(self, target, ctx):
        evidence = []
        confidence = None

        # CVE-2022-22965: a malformed value on the class.module.classLoader.* path
        # 400s on a vulnerable binder. Differential against an accepted value, so
        # a WAF or blanket-400 app (which trips both) is ruled out.
        baseline = ctx.get(target)
        control = ctx.get(target, "/?class.module.classLoader.DefaultAssertionStatus=false")
        probe = ctx.get(target, "/?class.module.classLoader.DefaultAssertionStatus=d2s")
        if (probe.ok and probe.status == 400
                and baseline.status not in (400, None)
                and control.status != 400):
            evidence.append("class.module.classLoader binding returned 400 for a malformed value where the "
                            "same path with an accepted value did not - Spring's data binder is walking the class.* path")
            confidence = Confidence.LIKELY

        # CVE-2022-22963: a malformed SpEL at the functionRouter sink surfaces a
        # parser error where the app echoes it (the canary catches the rest).
        spel = ctx.client.request_raw_headers(
            "POST", target.url("/functionRouter"),
            headers={"spring.cloud.function.routing-expression": "T(d2s", "Content-Type": "text/plain"},
            data=b"d2s",
        )
        spel_body = spel.text.lower() if spel.ok else ""
        # EL\d{4}E is a SpEL message code; the bare "el1" substring hit page text.
        spel_hit = any(
            s in spel_body for s in
            ("spelparseexception", "spelevaluationexception", "org.springframework.expression")
        ) or bool(re.search(r"el\d{4}e", spel_body))
        if spel_hit:
            evidence.append("routing-expression header at /functionRouter produced a SpEL parser/evaluator error")
            confidence = Confidence.LIKELY

        if confidence is None:
            return None
        return self.finding(
            target, confidence, Tier.PROVE,
            "A Spring reachability differential fired without writing anything or running code - corroborate against the deployed version.",
            evidence,
        )
