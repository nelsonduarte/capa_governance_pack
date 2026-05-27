# Security policy

`capa_governance_pack` is a CLI tool that turns a CycloneDX SBOM,
a governance policy, and a VEX exclusions list into a regulator-
readable audit pack plus a JSON attestation. It is written in
[Capa](https://github.com/nelsonduarte/capa-language), so the
per-function capability discipline is the structural defence:
the entry point in `governance.capa` declares only
`Fs + Env + Net + Clock + Stdio`, and the SBOM that the Capa
compiler emits (`capa --cyclonedx governance.capa`) proves it.

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | yes                |
| < 0.1   | no, please upgrade |

## Reporting a vulnerability

Email **nelson.duarte31@gmail.com** with the subject prefix
`[security] capa_governance_pack: ...`. Include a reproducer if
possible: the input files (SBOM, policy, VEX), the command line,
and the observed vs. expected behaviour.

GitHub Security Advisories are not yet enabled on this
repository; that will be set up later. Until then, please use
email and do not open a public issue for security reports.

Response SLA:

- Acknowledgement within **7 days**.
- Fix or a coordinated-disclosure plan within **90 days**.

## In scope

A bug is in scope if a crafted input (SBOM, policy, VEX file)
causes the program to:

- Read or write outside the current working directory.
- Exfiltrate data to a host other than `api.osv.dev` (the one
  network destination the optional enrichment step is allowed
  to reach).
- Hang indefinitely or consume unbounded memory.
- Produce a falsified `attestation.json`, i.e. one whose
  contents do not match the inputs the tool was given.

## Out of scope

- The Capa compiler itself. Report at
  <https://github.com/nelsonduarte/capa-language/security/advisories/new>.
- The OSV.dev API. Report upstream.
- The editor's behaviour with the Capa LSP.
- A program that legitimately receives a capability and uses it
  as declared. The audit pack reflects what the SBOM says; if
  the SBOM is wrong, that is a compiler-side issue.
