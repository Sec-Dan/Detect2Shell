"""HTTP2Shell / Node2Shell / Python2Shell - an out-of-bounds write in Google's
Brotli decoder (CVE-2026-111497), wherever an HTTP stack inflates a
Content-Encoding: br request body. Recon only: no safe remote proof.
"""

from .base import Check
from ..core.models import Confidence, Severity, Tier

_STACK_TELLS = ["envoy", "istio", "express"]


class HTTP2Shell(Check):
    key = "http2shell"
    name = "HTTP2Shell"
    component = "Google Brotli decoder (Node.js / Bun / Python / Envoy / Istio / vendored copies)"
    cves = ["CVE-2026-111497"]
    aliases = ["Node2Shell", "Python2Shell", "Broccoli2Shell"]
    severity = Severity.CRITICAL
    affected = ("Brotli C 1.0.3-1.2.0; Node.js < 22.23.4 / 24.22.1 / 26.12.1; Bun <= 1.4.3; "
                "PyPI brotli 1.0.3-1.2.0 / brotlicffi <= 1.2.0.2; Envoy/Istio with the Brotli filter enabled")
    remediation = ("Upgrade the Brotli decoder everywhere it is embedded (Brotli 1.0.10 / 1.1.1 / 1.2.1; "
                   "Node 22.23.4 / 24.22.1 / 26.12.1; Bun 1.4.4; brotli 1.2.1 / brotlicffi 1.2.1.0; "
                   "Envoy/Istio patched lines) and rebuild vendored/static copies.")
    references = [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-111497",
        "https://github.com/envoyproxy/envoy/security/advisories/GHSA-3wvj-j6qm-62mr",
        "https://www.aikido.dev/blog/node2shell-nodejs-brotli-rce-cve-2026-111497",
    ]
    supports_confirm = False
    supports_prove = True
    disruptive = False
    probe_note = ("This is a memory-safety bug - confirming it would mean running the full exploit "
                  "chain to code execution, which this detector deliberately does not carry. Take the "
                  "signatures above as \"could be vulnerable\" and confirm the installed version host-side.")

    def passive(self, target, ctx):
        resp = ctx.get(target)
        if not resp.ok:
            return None
        server = (resp.header("server") or "").lower()
        powered = (resp.header("x-powered-by") or "").lower()
        tells = sorted({t for t in _STACK_TELLS if t in server or t in powered})
        if any(h.startswith("x-envoy") for h in resp.headers):
            tells.append("x-envoy-* headers")
        # Soft signal: advertising the Brotli encoder, not the vulnerable decoder
        # (see the README's known limits).
        br = ctx.client.get(target.url("/"), headers={"Accept-Encoding": "br"})
        if "br" in (br.header("content-encoding") or "").lower():
            tells.append("serves Content-Encoding: br")
        if not tells:
            return self.not_detected(target)
        return self.finding(
            target, Confidence.POSSIBLE, Tier.PASSIVE,
            "A Brotli-capable stack is present; the decoder version is not remotely visible. Confirm host-side (SBOM or package changelog).",
            ["stack tells: " + ", ".join(sorted(set(tells)))],
        )

    def prove(self, target, ctx):
        # Recon only: no safe remote proof of a memory-corruption bug (see probe_note).
        return None
