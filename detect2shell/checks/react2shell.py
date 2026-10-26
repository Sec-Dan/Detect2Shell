"""React2Shell - unsafe deserialisation in React Server Components' Flight
protocol (CVE-2025-55182 / CVE-2025-66478), via Next.js App Router. No safe
out-of-band confirmation, so prove only reads the reply shape of one request.
"""

from .base import Check
from ..core.models import Confidence, Severity, Tier


class React2Shell(Check):
    key = "react2shell"
    name = "React2Shell"
    component = "React Server Components (Flight) / Next.js App Router"
    cves = ["CVE-2025-55182", "CVE-2025-66478"]
    severity = Severity.CRITICAL
    affected = ("react-server-dom-* 19.0.0 / 19.1.0 / 19.1.1 / 19.2.0; "
                "Next.js App Router 15.0.0-16.0.6 (see advisory for exact per-branch pins)")
    remediation = ("Upgrade RSC packages to 19.0.1 / 19.1.2 / 19.2.1 and Next.js to "
                   "15.0.5 / 15.1.9 / 15.2.6 / 15.3.6 / 15.4.8 / 15.5.7 / 16.0.7+ for your line.")
    references = [
        "https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components",
        "https://nextjs.org/blog/security-update-2025-12-11",
        "https://www.sysdig.com/blog/detecting-react2shell",
    ]
    supports_confirm = False
    supports_prove = True
    disruptive = True

    def passive(self, target, ctx):
        resp = ctx.get(target)
        if not resp.ok:
            return None
        rsc = ctx.client.get(target.url("/"), headers={"RSC": "1"})
        tells = []
        if "__next_f" in resp.text:
            tells.append("RSC Flight bootstrap (self.__next_f.push)")
        if resp.header("x-nextjs-cache") or resp.header("x-nextjs-matched-path"):
            tells.append("x-nextjs-* headers")
        if "next.js" in (resp.header("x-powered-by") or "").lower():
            tells.append("X-Powered-By: Next.js")
        if "text/x-component" in (rsc.header("content-type") or "").lower():
            tells.append("RSC text/x-component response")
        if not tells:
            return self.not_detected(target)
        return self.finding(
            target, Confidence.POSSIBLE, Tier.PASSIVE,
            "React Server Components / Next.js App Router detected; the version is not exposed in responses. "
            "Confirm host-side (npm ls next react-server-dom-webpack).",
            ["stack tells: " + ", ".join(tells)],
        )

    def prove(self, target, ctx):
        # One minimal, non-gadget Server-Action request; read only the reply shape.
        # A patched build answers the same, so this shows reachability, not
        # exploitability.
        headers = {
            "Next-Action": "0" * 40,
            "Content-Type": "text/plain;charset=UTF-8",
        }
        resp = ctx.client.post(target.url("/"), data=b"[]", headers=headers)
        if not resp.ok:
            return None
        ctype = (resp.header("content-type") or "").lower()
        # The dispatcher was reached if we got a Flight envelope or an
        # x-nextjs-action-not-found (Next.js 15.x) for our bogus action id.
        flight = "text/x-component" in ctype
        action_not_found = resp.header("x-nextjs-action-not-found") is not None
        if not (flight or action_not_found):
            return None
        evidence = []
        if action_not_found:
            evidence.append("Next-Action request reached the Server Action dispatcher (x-nextjs-action-not-found)")
        if flight:
            evidence.append("Server Action probe returned a Flight response (Content-Type: text/x-component)")
            if '"digest"' in resp.text[:400].lower():
                evidence.append("response body carried a Flight error envelope")
        return self.finding(
            target, Confidence.POSSIBLE, Tier.PROVE,
            "The RSC Flight / Server Action endpoint is reachable, but a patched build answers the same way, "
            "so confirm the deployed version host-side (npm ls next react-server-dom-webpack).",
            evidence,
        )
