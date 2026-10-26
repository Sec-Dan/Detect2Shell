# Security policy

## Responsible use

Detect2Shell is a detector for **authorised** security testing. Only run it against
systems you own or have explicit, written permission to test. Even its passive
checks send requests to the target, and unauthorised scanning is unlawful in many
jurisdictions. You alone are responsible for how you use it.

## What the tool does and does not do

Detect2Shell proves *exposure* and stops. It ships no weaponised primitive: no
webshell or file write, no rogue JNDI/class server, no prototype-pollution gadget,
no memory-corruption control payload, no out-of-memory or crash trigger, and no
memory-disclosure read. Its out-of-band canary answers with a single fixed string
and records nothing but the fact that a callback arrived. See "Safety by design"
in the README for the detail.

## No warranty and no guarantee of accuracy

Provided as-is under the MIT licence, with no warranty. The authors accept no
liability for any damage, disruption or legal consequence arising from its use or
misuse. Nothing here makes unauthorised testing lawful.

Results are best-effort and are not a guarantee. A clean or `not detected` result
is not proof that a target is safe: the tool probes a limited surface and can miss
real exposure. Do not rely on it as the sole basis for deciding a system is
unaffected; confirm component versions host-side.

## Reporting a vulnerability in Detect2Shell

If you find a security issue in the tool itself (as opposed to in a target you are
scanning), please report it privately rather than opening a public issue:

- Use GitHub's private vulnerability reporting on the repository
  (**Security -> Report a vulnerability**); or
- if that is unavailable, open a minimal public issue asking for a private channel,
  without exploit detail.

Please include the version, your platform and Python version, and the steps to
reproduce. We aim to acknowledge reports promptly and will credit reporters who
ask to be credited.

## Supported versions

Detect2Shell is alpha (0.x). Fixes land on the latest release only.
