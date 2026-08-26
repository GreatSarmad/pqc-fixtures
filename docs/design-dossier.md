# Design Dossier — `pqc-fixtures`

**Status:** v0.2 — approved 2026-07-27. Open questions Q1–Q4 are resolved as ADR-001…ADR-005 in [decisions.md](decisions.md); the work queue is [ROADMAP.md](../ROADMAP.md).
**Date:** 2026-07-27
**Basis:** Initial market research brief ("Under-Served PQC Migration Niches", idea A). This dossier turns that brief into an implementable product architecture. It deliberately contains no technology choices made for popularity; every choice is tied to a stated constraint.

---

## 1. The user outcome

> Within five minutes of hearing about the tool, a developer with no cryptography background has a directory of **valid, realistic, oversized post-quantum artifacts** on their machine and a definitive, local answer to the question: *"Which of my buffers, parsers, database columns, and protocol assumptions break at post-quantum sizes?"* — before any production migration work begins. In CI, the same answer becomes a regression gate: a build goes red when someone reintroduces a size assumption.

The outcome is an *answer*, not artifacts. Artifacts are the mechanism.

## 2. Primary users and their most important journey

| Persona | Who | What they need |
|---|---|---|
| **P1 (core)** | Backend/platform engineer (Node/Go/Java/Python), not a cryptographer | Prove locally what breaks, in minutes, no crypto reading required |
| **P2** | SRE / security engineer scoping a PQC migration | Reproducible worst-case artifacts to hand to app teams |
| **P3 (paying, later)** | Security/compliance lead under FINMA/NIS2/CNSA timelines | Exportable evidence that systems were tested against PQC sizes |

**The journey to optimize (P1):**

1. Install via one command (Homebrew / npx / pipx — no compiler, no OpenSSL setup).
2. `pqc-fixtures gen --preset worst-case-tls --out ./testdata` → done in seconds, offline.
3. Point their own code at the fixtures: parse the cert, insert the key into their DB column, connect a client to `pqc-fixtures serve`.
4. Something breaks visibly → they now know exactly what and why.
5. Add the GitHub Action → the finding becomes a permanent CI gate.

Steps 1–4 are the product's "aha". Everything in v1 exists to make them frictionless.

## 3. Explicit non-goals

- **No cryptography of our own.** We orchestrate existing engines (OpenSSL 3.5+, later possibly liboqs/Bouncy Castle). Never implement or modify primitives.
- **No discovery / inventory / CBOM scanning.** Saturated market (IBM CBOMkit, SandboxAQ, Keyfactor, existing solos). Explicit strategic exclusion.
- **No static analysis / linter / codemod in v1.** Possible later feature; out of scope now.
- **No hosted SaaS, accounts, dashboards, or telemetry in v1.** Everything runs offline on the user's machine or CI runner.
- **No QRNG or quantum-hardware integration, ever.** Credibility requirement, per the brief.
- **Not a CA or PKI management product.** Artifacts are test-only by construction (see §9).
- **No PQC performance benchmarking.**
- **No Windows-native guarantee in v1** (WSL documented as the path). *Assumption — see Q4.*

## 4. Assumptions that may be wrong

| # | Assumption | How it could be wrong | How we'd notice | Impact if wrong |
|---|---|---|---|---|
| A1 | OpenSSL 3.5+ CLI/API can emit all v1 artifacts (ML-DSA & SLH-DSA keys/certs/chains, ML-KEM keys) without an OQS fork | Some artifact (esp. anything composite/hybrid-certificate shaped) may need liboqs or Bouncy Castle | Spike in week 1: generate every v1 artifact by hand with stock OpenSSL 3.5 | Engine adapter gets a second implementation earlier than planned (§7 seam exists for this) |
| A2 | *Realism matters*: users need valid, verifiable chains, not just big byte blobs | Maybe `head -c 50000 /dev/urandom` is 80% of the value | If demo feedback says "I just needed a big blob", product is over-built | Core shrinks; the readiness-evidence work, which depends on realism, weakens |
| A3 | Bottom-up adoption works: developers install a security-adjacent CLI on a colleague's recommendation | Security tooling adoption may be top-down in target orgs | Inbound interest after the demo post — issues, questions, forks | Distribution emphasis shifts from developer channels to organisational ones |
| A4 | Static artifact dumps (IETF-Hackathon repo) are not "good enough" — parameterization (your chain depth, SANs, formats) is the value | Teams may copy static artifacts once and never need generation | Users asking for "just publish the bundle" | Ship pre-generated bundles as a free artifact anyway (cheap hedge); CLI remains for CI freshness |
| A5 | Composite/hybrid certificate formats keep churning through 2026–27 | They could stabilize fast | IETF LAMPS/TLS WG output | Feature flag graduates from experimental earlier — good problem |
| A6 | GitHub Actions is the right first CI seam | Target orgs may be GitLab/Jenkins-heavy | Inbound requests | Core is CI-agnostic (exit codes + SARIF + manifest); Action is a thin wrapper, so a GitLab template is days, not weeks |
| A7 | One compiled core binary with thin npm/pip/brew wrapper packages is acceptable to those ecosystems | Python users sometimes reject binary-only wheels | Install analytics are out (no telemetry) — watch issue tracker | Per-language rewrite would be the wrong fix; better docs/binary provenance |
| A8 | Deterministic (seeded, byte-reproducible) generation is **not** required in v1 | CI users may demand byte-stable golden fixtures | Early CI-tier conversations | Forces seeded keygen → OpenSSL CLI can't cleanly do this → pulls liboqs adapter forward. **See Q2** |
| A9 | Open-source crypto tooling distribution from Switzerland is fine under public-availability exemptions (SECO; US EAR via GitHub) | Edge cases exist | One-time check before first public release | Release checklist item; not a design change |

## 5. The smallest useful vertical slice

**"Generate one verifiable oversized chain and prove the pain."**

- `pqc-fixtures gen --algo ml-dsa-65 --chain 3 --out ./testdata`
- Emits: root CA cert, intermediate, leaf + private keys; `fullchain.pem`; DER copies; `manifest.json` (algorithms, byte sizes, SHA-256 hashes, engine version, validity window).
- The chain passes `openssl verify`; the leaf is usable as a TLS server cert (SANs: `localhost`, `127.0.0.1`).
- One worst-case preset: `--preset jumbo` (SLH-DSA-SHA2-256f leaf → 49,856-byte signatures).
- Distribution for the slice: GitHub release binaries + a Homebrew tap + `npx`. (pip/brew-core/Marketplace come later.)
- Accompanied by the Stage-0 demo: "watch a ~50 KB post-quantum cert break a default Node/Java/Postgres path" — blog post + GIF.

Everything else — `serve`, the Action, JWT fixtures, composite certs, reports — is excluded from the slice. This slice alone is post-worthy and directly executes Stage 0 of the business plan.

## 6. Core entities and data flows

Everything is files on disk; there is no database and no server-side state.

| Entity | What it is | Notes |
|---|---|---|
| **AlgorithmProfile** | Static registry of parameter sets and their exact size envelopes (FIPS 203/204/205 numbers: ML-DSA-65 sig = 3,309 B; SLH-DSA-SHA2-256f sig = 49,856 B; ML-KEM-768 encaps key = 1,184 B; …) | Ships with the tool, versioned; the source of truth for size assertions |
| **FixtureSpec** | Fully resolved generation request: artifact kinds, algorithms, chain shape, subject/SAN template, output formats, validity window | **Presets are named FixtureSpecs shipped as data files**, not code |
| **Artifact** | A generated file + metadata: kind (key / cert / chain / bundle / jwt), encoding, byte size, hash, parent references | |
| **Manifest** | Machine-readable record of one generation run: spec in, artifacts out, tool + engine versions, timestamps. Published JSON Schema | **The only contract between components** — consumed by `serve`, the Action, and future report generation |
| **Probe** (CI phase) | A user-supplied command run against the fixtures; exit code + output feed a RunReport | |
| **RunReport** (CI phase) | Probe results → SARIF + exit code; later, input to the paid report | |

**Flows:**

1. **Generation (offline):** CLI args/preset → FixtureSpec → planner orders the work (keys → CSRs → certs → chains → bundles) → engine adapter executes it (OpenSSL subprocess with a generated temp config) → artifacts + Manifest written atomically to the out dir.
2. **Serving:** `pqc-fixtures serve` reads a Manifest, picks a chain, presents it on a local TLS listener so any client can be pointed at it.
3. **CI:** Action → run `gen` (or restore cached fixtures) → run probes → RunReport → SARIF upload + red/green exit code.

No network traffic anywhere except the local listener the user explicitly starts.

## 7. Architecture boundaries (deliberately few)

```
┌─────────┐   ┌──────────────────────────────┐   ┌────────────────┐
│  CLI    │──▶│  core                        │──▶│ engine adapter │──▶ OpenSSL 3.5 (subprocess)
│ (thin)  │   │  spec resolution · planning  │   │ (one interface,│
└─────────┘   │  manifest · size assertions  │   │  one impl v1)  │
              └──────────────┬───────────────┘   └────────────────┘
                             │ Manifest (JSON, schema'd)
              ┌──────────────┴───────────────┐
              ▼                              ▼
        ┌──────────┐                  ┌──────────────┐
        │  serve   │                  │ GitHub Action│  (separate repo, zero
        └──────────┘                  └──────────────┘   generation logic)
```

- **core** — pure logic (spec resolution, planning, manifest, size assertions). Engine-agnostic. Where almost all unit tests live.
- **engine adapter** — one narrow interface (`generateKey`, `issueCert`, `assembleChain`). Exactly one v1 implementation: OpenSSL 3.5 subprocess. The seam exists because A1/A8 may force a second implementation (liboqs/Bouncy Castle) — but it is an interface, **not** a plugin framework: no dynamic loading, no registry.
- **CLI** — thin argument parsing over core.
- **serve** — consumes artifacts *only* via the Manifest; never reaches into core internals.
- **Action** — a thin wrapper that downloads the released CLI and interprets exit codes/SARIF. Contains zero generation logic, so other CI systems cost days.
- **Distribution** — one compiled artifact per platform; npm/pip/Homebrew packages are *installers* for that artifact, not ports (pending Q3).

**Explicitly rejected as overengineering for this stage:** plugin system, configuration DSL beyond flags + preset files, daemon, database, telemetry pipeline, multi-engine support matrix, hosted anything.

## 8. Acceptance criteria (testable)

For the slice and v1; each is automatable in the project's own CI.

1. **Zero-setup:** on a clean macOS or Linux machine with *no* OpenSSL 3.5 preinstalled, install → first fixtures completes in ≤ 5 minutes; `gen` itself ≤ 30 s (ML-DSA chains) / ≤ 60 s (SLH-DSA presets).
2. **Validity:** `openssl verify -CAfile root.pem -untrusted intermediate.pem leaf.pem` succeeds for every generated chain, checked against a pinned OpenSSL 3.5.x in CI.
3. **Size fidelity:** artifact byte sizes match the AlgorithmProfile envelopes (e.g. ML-DSA-65 signature = 3,309 B; SLH-DSA-SHA2-256f signature = 49,856 B; ML-KEM-768 encapsulation key = 1,184 B), asserted in tests and stamped into the Manifest.
4. **Manifest contract:** every Manifest validates against its published JSON Schema; every listed hash matches the file on disk.
5. **Offline:** `gen` succeeds with networking disabled (enforced in CI).
6. **Safety:** every generated certificate carries a `PQC-FIXTURES TEST ONLY` marker in Subject and Issuer; validity ≤ 30 days; a test asserts no generated cert chains to any system trust store.
7. **serve:** an `openssl s_client` handshake (pinned 3.5.x) against the `jumbo` preset succeeds and transfers a certificate chain ≥ 45 KB; clients lacking PQC support fail *loudly*, and the failure modes are documented.
8. **Action:** a failing probe (non-zero exit) fails the workflow and emits SARIF valid against the SARIF 2.1.0 schema; passing probes yield a green build.
9. **Platforms:** criteria 1–7 pass in CI on macOS (arm64) and Linux (x86_64 + arm64). Windows not asserted in v1 (Q4).

## 9. Security, privacy, and failure risks

| Risk | Mitigation |
|---|---|
| **Test keys/certs leak into production use** | `TEST ONLY` DN markers; ≤ 30-day validity; `INSECURE-TEST-` filename prefixes; loud README/output warnings; never emit anything that chains to a real trust store |
| **Supply-chain scrutiny** (our audience is professionally paranoid) | Minimal dependencies; pinned + checksummed vendored engine build; signed releases (Sigstore or minisign); SBOM published per release |
| **Bundled OpenSSL CVE burden** (if Q1 → bundle) | Track advisories; release pipeline can rebuild + republish within days; engine version stamped in every Manifest so users can audit exposure |
| **Privacy / trust** | No telemetry, no network calls, ever, in the free tool; any future analytics strictly opt-in. This is a *feature* for this audience — state it prominently |
| **Standards churn breaks presets** (HQC 2027, FN-DSA, nine new signature candidates, composite-vs-hybrid debates) | Presets are versioned data; deprecated presets warn but keep working; Manifest records preset + engine versions so old CI runs stay interpretable. Churn is the reason this tooling keeps earning its place |
| **Partial/corrupt generation** | Atomic output: write to temp dir, move into place only on success; non-zero exit + actionable diagnostics otherwise |
| **Export control / legal** | One-time SECO + US EAR public-availability check before first release (A9) — maintainer task, on the release checklist |
| **Name-squatting** | Register the chosen name on npm, PyPI, and a Homebrew tap at slice launch, before the HN post |

## 10. Feature-by-feature implementation plan

Effort in solo nights-and-weekends terms. Order F0→F5 is fixed; F6–F8 reorder on user signal.

| # | Feature | Deliverable | Done when | Effort |
|---|---|---|---|---|
| F0 | Bootstrap | Standard Go project layout, CI, release pipeline skeleton | Tagged v0.0.1 produces binaries for macOS arm64 / Linux x86_64 / Linux arm64 | ~1 wk |
| F1 | **Core gen: ML-DSA chains** (= the slice, §5) | `gen` command, ML-DSA-44/65/87, chain depth, PEM+DER, Manifest | Acceptance 1–6 pass | 3–4 wks |
| F2 | Worst-case presets | `jumbo` (SLH-DSA-SHA2-256f), `deep-chain`, `worst-case-tls` | Criterion 3 for SLH-DSA sizes; presets documented | 1–2 wks |
| F3 | ML-KEM key artifacts | ML-KEM-512/768/1024 keys, raw/DER/PEM; hybrid-context bundle | Sizes asserted; docs | ~1 wk |
| F4 | `serve` | Local TLS server presenting any generated chain | Criterion 7 | 1–2 wks |
| F5 | GitHub Action + SARIF | Marketplace-listed Action wrapping the CLI; probe runner | Criterion 8; listed on Marketplace | ~2 wks |
| F6 | Format matrix | PKCS#12 bundles; oversized ML-DSA JWTs; certs with unknown-critical-extensions (documented breakage path) | Each format has a verify test + docs | 2–3 wks |
| F7 | Composite/hybrid certs — `--experimental` | Second engine adapter impl if A1 demands (liboqs or Bouncy Castle) | Gated, instability documented | 3+ wks, **only on demand signal** |
| F8 | `report` | Readiness-evidence export (HTML/PDF) built from Manifests + RunReports | Sample report exists | ~2 wks, Stage 2 |

---

## Confirmed requirements vs. assumptions

**Confirmed (from the research brief):**
- Product = test-fixture generator + breakage simulation (idea A); CLI + GitHub Action; optional local test server.
- Distribution targets: npm, PyPI, Homebrew; GitHub Marketplace.
- Wrap existing engines; never implement crypto.
- The CLI is MIT-licensed and free.
- Solo, nights-and-weekends feasible; no scanner, no QRNG, no quantum-hardware APIs.
- Artifact scope: oversized ML-DSA/SLH-DSA certs, deep/composite chains, large ML-KEM keys, JWT/X.509-extension fixtures.
- SARIF output for the Action.

**Assumptions made in this dossier (overridable):** A1–A9 (§4); plus: single compiled core binary with wrapper packages (Q3); OpenSSL-subprocess as sole v1 engine (Q1/A1); no determinism in v1 (Q2/A8); Windows deferred (Q4); `serve` in v1 scope but after the slice; Action lives in a separate repo.

## Resolved architecture questions

- **Q1 — Engine packaging.** Release archives bundle a pinned, statically built OpenSSL 3.5 engine beside the CLI; the tool never depends on system OpenSSL (ADR-001, ADR-008).
- **Q2 — Determinism.** Seeded generation provides byte-identical ML-DSA and ML-KEM keys. Certificates remain stable in structure but are not guaranteed byte-identical; SLH-DSA generation is unseeded (ADR-002).
- **Q3 — Core runtime.** The core is a static Go binary with thin distribution wrappers for npm, PyPI, and Homebrew (ADR-003).
- **Q4 — Windows.** Native Windows support is deferred; WSL is the supported path for v1 (ADR-004).
