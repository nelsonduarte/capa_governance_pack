# capa_governance_pack

A CRA / NIS2 / SOC2 evidence-pack generator written in the
[Capa](https://github.com/nelsonduarte/capa-language) language.
Takes a CycloneDX SBOM, a governance policy, and a VEX
exclusions list; emits a regulator-readable Markdown audit pack
plus a machine-readable JSON attestation suitable for ingestion
by GRC platforms.

## Why this exists

The EU Cyber Resilience Act enters mandatory enforcement in
2027. NIS2 has been in force since October 2024, with member-
state transpositions cascading through 2025-2026. SOC2 Type II
audits are increasingly asking for software-bill-of-materials
evidence as part of CC8.1 change-management controls. None of
this is theoretical anymore.

The gap is not "how do I make an SBOM". Every modern build
toolchain emits one. Syft, CycloneDX, SPDX, OWASP Dependency-
Track, and the Capa compiler itself all produce CycloneDX 1.5
output. The gap is "how do I turn that SBOM into something a
regulator will accept as evidence that I have minimised attack
surface (CRA Annex I, Part I) and documented my supply-chain
risk posture (NIS2 Art. 21(2)(d))".

Concretely, an auditor reading CRA Annex I, Part II, item 1,
expects "a software bill of materials in a commonly used and
machine-readable format covering at least the top-level
dependencies of the product". An auditor reading Part I,
item (3)(e) expects evidence that "exposure to vulnerabilities"
has been reduced "by, among other things, reducing attack
surfaces". An SBOM alone does not answer the second clause.
You need to show that each component's authority is bounded
and that every exception is documented.

This is the gap `capa_governance_pack` closes.

## The problem

Every compliance team that ships software into the EU after
December 2027 will need, at minimum:

- **Per-function attribution**: not just "the binary uses
  `requests`", but "function X reaches the network, function Y
  does not". Coarse component-level SBOMs do not support the
  attack-surface clause; per-function evidence does.
- **Policy comparison**: a written allow-list of capabilities
  (Net, Fs, Env, Stdio, ...) per function and per product,
  diffed against what the compiler actually emitted. Anything
  outside the allow-list is a finding.
- **VEX-aware exception tracking**: when a function legitimately
  needs an unusual capability, the rationale travels with the
  evidence pack as a Vulnerability Exploitability eXchange
  entry. The auditor sees the waiver and the reason in the same
  document.
- **Machine-readable attestation**: a JSON document a GRC
  platform (Vanta, Drata, Hyperproof, ServiceNow GRC) can
  ingest without a human re-keying the findings.
- **Optional CVE enrichment**: cross-reference component names
  against OSV.dev so the report carries known-vulnerability
  context alongside the capability evidence.

`capa_governance_pack` does these five things on three inputs
and produces two outputs.

## What this tool does

```
                +------------------+   +------------------+
data/sample_sbom.json  -->  parse_sbom    --> SbomSummary
data/sample_policy.json -> parse_policy   --> Policy
data/sample_vex.json    -> parse_vex      --> VexList
                +------------------+   +------------------+
                                       |
                                       v
                                evaluate (pure)
                                       |
                  +--------------------+--------------------+
                  |                                         |
                  v                                         v
            List<Finding>                              Aggregate
                  |                                         |
                  |                  (optional)             |
                  |               GOV_PACK_INCLUDE_CVE=1    |
                  |                       |                 |
                  |                       v                 |
                  |                enrich_with_cves         |
                  |                       |                 |
                  +-----------+-----------+-----------------+
                              |
                              v
                +------------------+   +------------------+
                | render_audit_pack | + | render_attestation
                +------------------+   +------------------+
                              |
                              v
                audit_pack.md  +  attestation.json
```

Seven steps end-to-end:

1. Read inputs (SBOM, policy, VEX) through an `Fs` cap.
2. Parse each input into typed Capa values.
3. Optionally enrich with OSV.dev CVE matches through a
   restricted `Net` cap (host narrowed to `api.osv.dev`).
4. Evaluate every function: classify as `Ok` / `Widened` /
   `ExcludedByVex` / `NotEvaluated`.
5. Aggregate: counts, distinct capability axes, pure-function
   ratio, total compliance score in `[0, 100]`.
6. Render the Markdown audit pack and the JSON attestation.
7. Write both files and print a one-line summary to stdout.

## Usage

From the repo root:

```bash
capa --run governance.capa
```

That writes `audit_pack.md` and `attestation.json` to the
current working directory and prints a single summary line.

To enable OSV.dev CVE enrichment (the only step that touches
the network), set the env var:

```bash
GOV_PACK_INCLUDE_CVE=1 capa --run governance.capa
```

The `Net` capability is forwarded into `enrich_with_cves` only
when the opt-in is set; a default run is provably Net-quiet at
the call-site granularity.

## Output files

`audit_pack.md` (first 10 lines, abridged):

```
# CRA / NIS2 evidence pack

- **Product:** example-product
- **Version:** 1.0.0
- **Tier:** L1
- **Audit timestamp (UTC):** 2026-05-26T19:34:11Z
- **Functions audited:** 6
- **Pure (compiler-verified):** 2 / 6 (33%)
- **Compliance score:** 83.33 / 100.00
```

`attestation.json` (top-level shape):

```json
{
  "product_name": "example-product",
  "product_version": "1.0.0",
  "audit_timestamp_unix": 1748287000,
  "tier": "L1",
  "summary": {
    "total_functions": 6,
    "pure_functions": 2,
    "with_caps": 4,
    "exclusions_applied": 1,
    "distinct_cap_axes": ["Fs", "Env", "Net", "Stdio"],
    "compliance_score": 83.33
  },
  "findings": [...],
  "regulatory_attestation": {
    "cra_annex_i_part_ii_1_machine_sbom": "SATISFIED",
    "cra_annex_i_part_i_attack_surface": "ATTESTED_PER_FUNCTION",
    "nis2_supply_chain_documentation": "SATISFIED"
  }
}
```

## Why Capa

CRA Annex I, Part I, asks for evidence of attack-surface
minimisation. In every other ecosystem this is a heuristic:
static taint analysis, runtime sandboxing, manual review.
Capa's per-function capability typing gives you the
attestation for free. Every function in the input SBOM
carries a `capa:declared_capability` property derived not from
a guess but from the function's signature. A function with no
capability parameters is provably pure; the compiler will
reject a diff that tries to add a `stdio.println` to it
without also widening the signature.

The audit logic itself, written here in Capa, exercises the
same discipline. The pure half of the pipeline (`evaluate.capa`,
`render.capa`) is provably pure: it cannot read, write, log,
fetch, or wall-clock-time. The capability-bearing half is
explicit in every signature. An auditor reviewing this tool's
own SBOM would see exactly which functions can touch disk and
which can speak to the network.

That property does not exist in TypeScript, in Python, in Go,
or in Rust. It is the reason the audit pack is structural
evidence rather than a self-attestation.

## Repo layout

```
.
governance.capa     entry point: main, pipeline, ANSI-colored summary
model.capa          shared types: SbomSummary, Policy, VexList, Finding, Aggregate
parse.capa          JSON readers for the three input shapes
evaluate.capa       pure classification: Ok / Widened / ExcludedByVex / NotEvaluated
render.capa         pure renderers: Markdown audit pack + JSON attestation
enrich.capa         optional OSV.dev CVE lookup, scoped to api.osv.dev
data/
  sample_sbom.json    CycloneDX 1.5 fixture (6 function components)
  sample_policy.json  product allow-list + per-function override
  sample_vex.json     one written exception with rationale
LICENSE             Apache-2.0
README.md           this file
capa.toml           manifest, no dependencies
```

## What this exercises in Capa

- **Multi-module project** with a flat root layout.
- **Five built-in caps**: `Stdio`, `Fs`, `Env`, `Net`,
  `Clock`. The optional `Net` step demonstrates host
  attenuation via `Net.restrict_to("api.osv.dev")`.
- **Heavy `JsonValue` traversal**: nested objects + arrays in
  three different shapes (Capa-emitted CycloneDX, governance
  policy, VEX exclusions).
- **Sum types with payloads** (`FindingStatus = Ok |
  Widened(List<String>) | ExcludedByVex(String) |
  NotEvaluated(String)`) and a five-variant error type
  (`GovError`).
- **The `?` operator** for error propagation through every
  parser and through the pipeline orchestrator.
- **Tuple destructure** on the `evaluate_all` and
  `civil_from_days` return values.
- **A generic helper** (`first<T>(xs: List<T>, default: T) -> T`).
- **Lambdas as `List<T>.filter` arguments** for the
  pure-function and capability-bearing-function partitions.

## Limitations

- **Component-name-only OSV lookup**. The enricher submits a
  substring query (`?q=...`); for production use, the v2
  iteration would parse PURLs and use OSV's typed package
  identifiers (`pkg:pypi/...`, `pkg:npm/...`).
- **Allow-list semantics only**. Per-function rules are
  membership checks; structural rules ("Net only in impls of
  HttpClient") are out of scope and live in
  [`sbom_capability_audit.capa`](https://github.com/nelsonduarte/Capa_language/blob/main/examples/sbom_capability_audit.capa)
  in the main Capa repo.
- **No SLSA / in-toto envelope**. The attestation is a flat
  JSON document, not a signed predicate. Wrapping it in an
  in-toto Statement (and signing with cosign) is a downstream
  exercise; the JSON shape is intentionally compatible.
- **Simplified timestamp formatter**. The pack emits an ISO
  8601 string built from `Clock.now_secs()` via Hinnant's
  civil-from-days algorithm. It is exact for the proleptic
  Gregorian calendar, which is what every regulator means by
  "UTC date", but the routine does not call out to a system
  zoneinfo database.

## License

Apache-2.0. See [LICENSE](./LICENSE).
