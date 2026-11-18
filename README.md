# Detect2Shell

```
    ____       __            __ ___  _____ __         ____
   / __ \___  / /____  _____/ /|__ \/ ___// /_  ___  / / /
  / / / / _ \/ __/ _ \/ ___/ __/_/ /\__ \/ __ \/ _ \/ / /
 / /_/ /  __/ /_/  __/ /__/ /_/ __/___/ / / / /  __/ / /
/_____/\___/\__/\___/\___/\__/____/____/_/ /_/\___/_/_/
```

A command-line scanner that tells you whether a web service is exposed to the
`*2Shell` / `*4Shell` family of remote code execution bugs: Log4Shell,
Spring4Shell, Text4Shell, React2Shell, PHP2Shell, Java4Shell (also called
Java2Shell), and the Brotli bug that went by Node2Shell, then Python2Shell, then
HTTP2Shell.

They all share the "shell" nickname, so they are grouped here. What they do not
share is how you find them, which is most of what this tool is about.

Detect2Shell is a **detector**. It proves exposure and then stops. It never
opens a shell, never hands you a session, and never drops a file on the target.
That line is drawn in the code, not just in this README (see
[Safety by design](#safety-by-design)).

---

## Authorised use only

Run this only against systems you own or have explicit, written permission to
test. Even the passive checks send requests to the target, and in many places
scanning a service you do not control is a crime. Every request to a target
carries a User-Agent that names the tool and your scanner's own IP, so the owner
of whatever you touch can see the traffic for what it is:

```
User-Agent: Detect2Shell/0.2.0 (+https://github.com/Sec-Dan/Detect2Shell; scanner-ip=203.0.113.9; authorised-scan)
```

The tool will not scan until you confirm you are authorised, either by answering
the prompt or by passing `--i-am-authorised`. What you do with it is on you.

Detect2Shell is provided as-is under the MIT licence (see [LICENSE](LICENSE)),
with no warranty; the authors accept no liability for any damage, disruption or
legal consequence arising from its use or misuse. Its results are best-effort,
not a guarantee: a clean result is not proof of safety, because the tool probes
a limited surface and can miss real exposure. Confirm component versions
host-side before you rely on a "not detected".

---

## What it checks

| Check | CVE(s) | Component |
|---|---|---|
| `log4shell` | CVE-2021-44228 and the 45046 / 45105 / 44832 follow-ups | Apache Log4j2 (`log4j-core`) |
| `spring4shell` | CVE-2022-22965, CVE-2022-22963 | Spring Framework / Spring Cloud Function |
| `text4shell` | CVE-2022-42889 | Apache Commons Text |
| `react2shell` | CVE-2025-55182, CVE-2025-66478 | React Server Components / Next.js App Router |
| `php2shell` | CVE-2026-109618, CVE-2026-109619 | PHP core (session upload-progress handler) |
| `http2shell` | CVE-2026-111497 | Google Brotli decoder (Node.js, Bun, Python, Envoy/Istio, vendored copies) |
| `java4shell` | CVE-2026-114938 | OpenJDK / HotSpot JVM Base64 decoder on AVX-512 CPUs (every vendor's JDK 17, 21, 25, 27) |

Run `detect2shell --list-checks` for the current set.

## How the checks work: three tiers

Most of these bugs cannot be proven from the outside by reading a version
string. Versions are hidden, and distributions backport fixes without changing
the number. So Detect2Shell works in three tiers, and it tells you honestly
which one produced a result.

**Tier 1, passive (default).** Reads what the server already gives away:
response headers, cookies, HTML markers, how it handles `Accept-Encoding: br`.
This fingerprints the stack but rarely pins the version, so passive results are
reported as `possible` or `likely`, never `confirmed`.

**Tier 2, confirm (`--confirm`).** A benign out-of-band canary. The tool nudges
the target into making a lookup back to a listener it runs, using a one-off
token. If the callback arrives, the vulnerable path is live. The listener serves
nothing, so even a vulnerable target gets no code and no foothold. This is where
Log4Shell, Text4Shell and Spring4Shell's SpEL path earn a `confirmed`.

**Tier 3, prove (`--prove`).** Sends the real trigger, but only to answer one
question: did the vulnerable code path fire? The moment it would turn into
access, it stops. There is no shell, no returned command output, no persistence.

The memory-corruption bugs never get a *remote proof of exploitability*: a real
proof would mean driving the full exploit chain to code execution, which a
detector has no business carrying. What the prove tier does safely for them is
check **reachability** - is the vulnerable input path exposed, or shielded? -
and, for Java4Shell, the definitive yes/no comes from the
[host-side check](#host-side-exploitability-check) run on the box itself.

- `java4shell`: sends one trigger-shaped `Authorization: Basic` token (only
  where the server actually challenges Basic auth) and reports whether it was
  **blocked at the edge** by a WAF/gateway or **reached the application**. This
  is the "is my WAF catching this?" check. It carries no memory-control content.
- `http2shell`: sends the benign invalid-stream vector from Node's own Brotli
  regression test as a `Content-Encoding: br` body, and reports whether br
  request-body decoding is reachable - and, where the app surfaces the decoder's
  error, whether it is the pre-patch or the patched one.
- `php2shell`: stays recon-only. The input that triggers it makes a *patched*
  PHP fail the same way, so no remote probe can tell patched from vulnerable.

Some tier-3 probes can disrupt a target. For Java4Shell, `--allow-disruptive`
escalates the edge probe into a bounded burst of trigger-shaped requests that
watches only for the service failing (reset / 5xx) - a "did it fall over" check
the operator explicitly opts into for their own environment. It never reads
response bytes for leaked memory and never drives the corruption further; a
service that survives is reported as inconclusive, not safe. Disruptive probes
are off by default and refuse to run without `--allow-disruptive` and a second
explicit confirmation.

To exercise the edge probe against a WAF off-production, see [`lab/`](lab/): a
local target behind an open gateway and a WAF gateway, so you can watch the
probe tell "reached the app" from "blocked at the edge".

### Host-side exploitability check

For Java4Shell (CVE-2026-114938), whether a box is *actually* exploitable turns
on three things the network cannot show: the exact JDK build, whether the
HotSpot Base64 intrinsic is compiled in (`UseBASE64Intrinsics`), and whether the
JVM drives the AVX-512 decode path at all (`UseAVX` ≥ 3). All three are
answerable locally by asking the JVM, with no exploit. Run it on the host next
to the service:

```
detect2shell --host-check                       # the 'java' on PATH
detect2shell --host-check --java /path/to/java   # a specific JVM (repeatable)
```

It launches only print-and-exit commands (`java -version` and
`java -XX:+PrintFlagsFinal -version`), touches no network, and returns one of:

- **EXPLOITABLE** - affected build, intrinsic on, AVX-512 live: patch this JVM now.
- **MITIGATED** - affected build but `UseBASE64Intrinsics` is off.
- **NOT EXPLOITABLE** - out of the affected range, or `UseAVX` below the AVX-512
  level (the `-XX:UseAVX=2` stopgap), so the vulnerable path is never taken.
- **UNKNOWN** - the build or flags could not be read; it says what it saw.

A host can run several JVMs, each with its own build and flags, so check every
one that handles untrusted input. The exit code is 1 if any JVM is EXPLOITABLE.

### Egress canary

Being vulnerable is not the same as being reachable-and-exploitable in your
environment: egress filtering, segmentation or an air gap can mean a vulnerable
service still cannot call home. That is not visible from a version check, so ask
the host directly - from the box, try to reach a destination **you control** over
DNS, HTTP(S) and raw TCP, and see which channels get out:

```
detect2shell --egress-check \
    --egress-dns  probe.canary.example.com \
    --egress-tcp  canary.example.com:443 \
    --egress-url  http://canary.example.com/c/<token>
```

It only contacts the destinations you pass - it never chooses one itself - and
carries no exploit. Point the HTTP channel at the built-in `--confirm` listener
(or any endpoint you own) and the far side records the hit, so you confirm the
traffic *arrived*, not just that a socket opened. Exit code is 1 if any channel
left the host. "All blocked" is a genuine mitigating signal for a
vulnerable-but-segmented host; it is not a blanket air-gap proof, only a
statement about the channels and destinations you tested.

### Confidence, stated plainly

- `confirmed` - an out-of-band callback or a live code-path signal proved it.
- `likely` - a version in the known-vulnerable range, or a strong behavioural tell.
- `possible` - the vulnerable component looks present but the version is unknown.
- `not detected` - looked and found nothing. That is not the same as safe; see [Known limits](#known-limits).
- `error` - the probe could not complete.

A `possible` is an invitation to confirm host-side (an SBOM, `npm ls`, a package
changelog), not a verdict.

### Correlating the scan in your logs

Every request a run sends carries a unique marker header,
`X-Detect2Shell-Probe: d2s-<random>`, printed at the top of the run. Search your
web logs, WAF, or SIEM for that one token to pull back exactly what the scan
sent - useful when you are running against your own endpoint to see how a
trigger-shaped request travels through your stack and to build a detection from
its shape while you patch. `--trace <path>` writes every request (method, URL,
status, timestamp, marker) as JSON lines for the same purpose.

## Install

Detect2Shell needs **Python 3.8 or newer and nothing else**. No pip packages,
no build step, no virtualenv required. That is deliberate: you can drop it onto
a jump box or an old server and it just runs.

```bash
git clone https://github.com/Sec-Dan/Detect2Shell.git
cd Detect2Shell
python3 -m detect2shell --help
```

If you would rather have it on your PATH as `detect2shell`:

```bash
pip install -e .
```

## Usage

Passive sweep of one host:

```bash
python3 -m detect2shell https://target.example.com
```

Confirm Log4Shell and Text4Shell with the out-of-band canary. Tell the tool the
address the target can reach you on:

```bash
python3 -m detect2shell https://target.example.com \
    --only log4shell,text4shell \
    --confirm --listener-host 203.0.113.9 \
    --i-am-authorised
```

Full run, including the prove tier, against a scope list, writing JSON:

```bash
python3 -m detect2shell -f targets.txt \
    --prove --scope allowed.txt \
    --json results.json --i-am-authorised
```

Targets can be URLs, bare hosts, `host:port`, or CIDR ranges. A bare host is
tried on both https and http unless you pin it.

Prove-tier run that also writes a request trace, so you can pull the scan out of
your own logs by its run marker:

```bash
python3 -m detect2shell https://target.example.com \
    --prove --trace scan-trace.jsonl --i-am-authorised
```

The two local modes take no targets and touch no network beyond what you ask
(`--host-check` touches none at all):

```bash
# Is this box actually exploitable? (asks the JVM directly)
python3 -m detect2shell --host-check

# Can this box reach a destination you control? (egress canary)
python3 -m detect2shell --egress-check --egress-url http://canary.example.com/c/<token>
```

See [Host-side exploitability check](#host-side-exploitability-check),
[Egress canary](#egress-canary) and
[Correlating the scan in your logs](#correlating-the-scan-in-your-logs) for what
each reports.

### The out-of-band listener

Tiers 2 and 3 start a small listener so the target has somewhere to call back
to. It has two halves, both of which record a hit and nothing more:

- an HTTP endpoint, for lookups that fetch a URL (such as Text4Shell's `url`
  lookup), where the token travels in the request path;
- a set of raw TCP ports, one per token, for `ldap://` / `rmi://` style JNDI
  callbacks, where the destination port is what ties a hit back to a target.

Point the target at an address it can actually reach with `--listener-host`. On
an internal engagement that is usually your box's IP. If you cannot expose a
port, the out-of-band tiers will not confirm, and the tool says so rather than
guessing.

### Scope lists

`--scope allowed.txt` takes one pattern per line: an exact host, a `*.wildcard`,
or a CIDR range. Anything outside the list is skipped and named on stderr. Use
it as a guard rail so a fat-fingered target never gets touched.

## Output and exit codes

Findings print grouped by target, worst first, with the confidence, severity,
CVEs, the evidence behind the call, and the fix. An active-tier finding carries a
coloured `probed:<tier>` tag for the deepest tier that ran (passive findings
carry none), and every evidence line is tagged with the tier that produced it
(`passive:`, `confirm:`, `prove:`), so a `--prove` run never looks identical to a
passive one and you can see exactly what each stage found. `--json` writes the whole set, including the
clean results, for a pipeline to consume. `--show-clean` adds the `not detected`
lines to the terminal view.

A note on the memory-corruption bugs: none of them earns a remote `confirmed`
*for exploitability* - proving that would mean driving the exploit chain to code
execution, which a detector deliberately does not carry. The prove tier instead
checks reachability, and says so plainly: `java4shell` reports whether a
trigger-shaped request is blocked at the edge or reaches the app; `http2shell`
reports whether br request-body decoding is reachable (and the decoder's error
tier where the app surfaces it); `php2shell` stays recon-only because a patched
build fails the same way. A `java4shell` run with `--allow-disruptive` can earn
`confirmed` in one specific sense only: the opted-in burst actually disrupted
the service. That is a crash/reachability fact, never a claim of code execution.

| Exit code | Meaning |
|---|---|
| `0` | nothing exposed |
| `1` | at least one positive finding |
| `2` | only errors, or nothing to scan |
| `3` | authorisation not confirmed |

## Safety by design

- The canary listener answers every request with one fixed string and discards
  raw TCP bytes after noting the connection. It has no code path that serves
  attacker-chosen content, so it cannot become the second stage of an exploit.
- No check ships a weaponised primitive: no rogue JNDI class server, no webshell
  or file write, no prototype-pollution gadget, no memory-corruption control
  payload, no memory-disclosure read. The payloads it does send carry no content
  that steers memory corruption, and no check parses responses for leaked bytes.
- The one deliberate crash path is `java4shell`'s disruptive burst. It is gated
  behind `--allow-disruptive` and a second confirmation, it sends only
  trigger-shaped (not memory-control) requests, and it observes nothing but
  whether the service fell over. It exists so an operator can prove, against
  their own service, that a reachable path is unprotected - never to hand over
  access.
- Active tiers refuse to run without authorisation. Disruptive probes need a
  second opt-in on top of that.
- The User-Agent is always honest and is never the carrier for an injected
  payload.

## Known limits

- A clean result is not proof of safety. Detect2Shell probes a generic surface
  (a handful of paths, parameters and headers); a real application often logs or
  evaluates untrusted input somewhere more specific, so a vulnerable target can
  still come back `not detected`. A `not detected` means nothing was found on the
  surface checked, not that the target is safe.
- A `confirmed` from the HTTP canary (Text4Shell's url lookup, Spring Cloud
  Function's SpEL fetch) means something behind your request fetched the canary
  URL. That is almost always the target, but a URL-inspecting middlebox in the
  path - a forward proxy, a link-preview service, a scanner that follows URLs it
  sees - could trigger the same callback. The raw LDAP/RMI canary used for
  Log4Shell is not susceptible, since those middleboxes do not speak LDAP/RMI; if
  in doubt, correlate the callback's source with the target.
- Remote version fingerprinting is unreliable for library-embedded bugs
  (Log4Shell, Text4Shell) and for backported distro packages. Passive results
  are a starting point; confirm host-side where you can.
- PHP2Shell, HTTP2Shell and Java4Shell are memory-corruption bugs with no safe remote proof:
  a real proof means the full exploit chain to code execution, which this tool
  does not carry. It reads the version and flags the exposed stack, then leaves
  the verdict to a host-side package check - correctness of the host over a crash
  on the target. HTTP2Shell's passive tell also watches whether the server offers
  `Content-Encoding: br`, which detects the Brotli *encoder* and is only a weak
  proxy for the vulnerable *decoder*; a stack can run a vulnerable decoder without
  ever advertising br, so expect false negatives there.
- Java4Shell depends on three things a remote scan cannot see: the JDK build,
  the host CPU (it needs AVX-512 VBMI, which means Intel Ice Lake or newer, or
  AMD Zen 4 or newer) and the JVM flags (`-XX:-UseBASE64Intrinsics` or
  `-XX:UseAVX=2` remove the vulnerable path). There is no callback to catch and
  no safe malformed input to send, because the trigger is the corrupting input
  itself. The check finds Java services, flags the products with a reported
  pre-auth path (Keycloak, Jira, Confluence, Artifactory, Jenkins,
  PingFederate) and reads the JVM version where Solr leaves it exposed. It
  never reports higher than `likely`. Some vendors ship the fix without changing
  the version string, so confirm host-side: run `java -version` and check
  `/proc/cpuinfo` for `avx512vbmi` on every host and in every container.
- IPv6 literals should be given with an explicit scheme (`http://[::1]:8080`).

## Roadmap

- Host-side companion mode: read JARs, lockfiles and package changelogs for a
  definitive version verdict.
- A DNS-based canary for environments where only DNS egress is allowed.
- Per-field attribution, so a confirmed hit names the exact input that reached
  the sink.

## Licence

MIT. See [LICENSE](LICENSE). Written by DanSec.
