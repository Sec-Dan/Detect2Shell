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

    # The invalid-block-switch stream from Node's own regression test
    # (test/parallel/test-zlib-invalid-input.js). It is a version-check vector,
    # not the large crash input: a vulnerable decoder and a patched one reject
    # it with different error codes, and neither corrupts memory on this input.
    _BR_PROBE = bytes.fromhex("200010414141fcffff07002228f00b60f7f41f000000")
    _VULN_SIGNS = ["block_length_1", "errno -9", "code: -9"]
    _PATCHED_SIGNS = ["block_switch", "errno -17", "code: -17"]
    _DECODE_SIGNS = ["brotli", "decompress", "decompression failed", "content-encoding", "incorrect header"]
    _CANDIDATE_PATHS = ["/", "/api", "/api/data", "/upload", "/graphql", "/login"]

    def prove(self, target, ctx):
        # Non-disruptive: send the benign regression vector as a br request body
        # and read the reply. Shows whether the stack decodes br request bodies
        # (the reachable surface) and, where the app surfaces the decoder's
        # error name, tells a pre-patch error from the patched one. It never
        # sends the crash input and never reads response bytes for leaked memory.
        for path in self._CANDIDATE_PATHS:
            resp = ctx.client.post(
                target.url(path), data=self._BR_PROBE,
                headers={"Content-Encoding": "br", "Content-Type": "application/json"},
            )
            if resp.status is None:
                continue
            body = resp.text[:2000].lower()
            if any(s in body for s in self._VULN_SIGNS):
                return self.finding(
                    target, Confidence.LIKELY, Tier.PROVE,
                    "The Brotli decoder surfaced a pre-patch error for the regression vector at {} - the "
                    "decoder predates the fix. Confirm the exact build host-side.".format(path),
                    ["pre-patch Brotli error signature in the response to the br probe at {}".format(path)],
                )
            if any(s in body for s in self._PATCHED_SIGNS):
                return self.finding(
                    target, Confidence.NOT_DETECTED, Tier.PROVE,
                    "The Brotli decoder returned the patched error for the regression vector at {} - the "
                    "fix is present on this decode path.".format(path),
                    ["patched Brotli error signature in the response to the br probe at {}".format(path)],
                )
            if any(s in body for s in self._DECODE_SIGNS) or resp.status in (400, 415, 422, 500, 502):
                return self.finding(
                    target, Confidence.POSSIBLE, Tier.PROVE,
                    "The stack decodes br request bodies at {} (reachable surface) but did not surface the "
                    "decoder's version - confirm the Brotli build host-side.".format(path),
                    ["br request-body decoding reachable at {} (status {})".format(path, resp.status)],
                )
        return None
