# Architecture Decision Records — pqc-fixtures

Decisions are binding until superseded by a later ADR. Each records confidence at decision time.
Publishing, registrations, public posts, and releases require explicit maintainer approval.

---

## ADR-001: Bundle a pinned OpenSSL 3.5.x LTS engine (resolves Q1)

**Decision:** Ship a vendored, pinned, per-platform OpenSSL 3.5.x build inside our release artifacts and invoke it as a subprocess. Never depend on system OpenSSL.

**Rationale:**
- OpenSSL 3.5 is an LTS release (supported until 2030-04-08) with native ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) in the default provider — everything v1 needs, no OQS provider fork.
- "Zero-setup" is the product promise. System OpenSSL ≥ 3.5 is not ubiquitous (Ubuntu 24.04 LTS ships 3.0.x; RHEL 9 ships 3.0/3.2; macOS ships LibreSSL). Requiring it would contradict the 5-minute journey.
- Pinning makes generation reproducible across machines and CI, and lets the Manifest record an exact engine version.

**Costs accepted:** larger downloads; we own CVE response (see ADR-007 — the maintenance policy requires regular OpenSSL advisory checks and prompt rebuilds).

**Confidence:** ~97%.

## ADR-002: Determinism policy — deterministic keys, stable-structure certs (resolves Q2)

**Decision:** v1 offers `--seed <hex>` producing **deterministic keys** (byte-identical) for ML-DSA and ML-KEM via OpenSSL's native `hexseed` keygen parameter. Certificates are **stable-structure** (same sizes, same DN/extensions) but not guaranteed byte-identical in v1 (validity timestamps; ML-DSA hedged signing default). Byte-identical certificates are out of scope until a concrete CI use case demands them.

**Rationale:** OpenSSL 3.5 supports seed-based ML-DSA/ML-KEM key generation natively (32-byte seed, retained in PKCS#8 output), so deterministic keys cost nothing and need no liboqs FFI. Full cert determinism would require fixed timestamps plus deterministic signing and buys little: CI stability is achieved by caching fixtures keyed on the Manifest, not by regenerating identical bytes.

**Consequence:** liboqs stays out of v1 entirely. SLH-DSA seeds may differ in mechanics — verify during the F1 spike; if SLH-DSA can't be seeded via CLI, document keys-only determinism for ML-DSA/ML-KEM.

**Confidence:** ~95%.

**S1 spike update (2026-07-27, see [docs/spike-notes.md](spike-notes.md)):** verified against stock OpenSSL 3.6.2. ML-DSA and ML-KEM `hexseed` keygen is confirmed byte-identical across repeated runs, but the seed length is **algorithm-family-specific, not uniform**: ML-DSA takes a 32-byte seed, ML-KEM takes a 64-byte seed (FIPS 203's `d ‖ z`). SLH-DSA rejects `hexseed` outright — no seed-shaped keygen parameter exists in the provider — confirming the fallback this ADR already anticipated. `--seed` in v1 therefore applies to ML-DSA and ML-KEM only; SLH-DSA presets stay non-deterministic even with `--seed` passed, and this must be surfaced per-artifact in the Manifest (`seeded: bool`), not as one global flag. Implementation detail, not a decision change — original confidence and decision stand.

## ADR-003: Core implemented in Go, single static binary per platform (resolves Q3)

**Decision:** The core, CLI, and serve supervisor are one Go codebase compiled to a static binary per platform (darwin/arm64, linux/amd64, linux/arm64). npm, PyPI, and Homebrew packages are thin installers for that binary (per-platform package pattern, as used by esbuild and similar tools) — never ports.

**Rationale (criteria-based, not popularity):**
- One codebase must serve three registries with no runtime prerequisite for users → compiled static binary.
- The tool is an *orchestrator* (subprocess control, file I/O, JSON) — Rust's memory-safety guarantees add cost without benefit here because we implement no cryptography (see dossier §3). Go's toolchain gives straightforward cross-compilation and mature single-command release automation, which suits a small maintainer team.
- The project has no language constraint, so maintainability and ecosystem fit decide.

**Confidence:** ~95%.

## ADR-004: Windows deferred past v1 (resolves Q4)

**Decision:** No native Windows support in v1. Document WSL as the supported path. Revisit when there is demand signal (issues/inbound).

**Confidence:** ~96%.

## ADR-005: `serve` delegates TLS to the bundled OpenSSL (`s_server`), no native TLS stack

**Decision:** The `serve` command supervises the bundled OpenSSL `s_server` process (friendly UX, diagnostics, lifecycle handling in Go) rather than terminating TLS in Go.

**Rationale:** Go's `crypto/tls` supports hybrid ML-KEM key exchange but **not** PQC certificate signatures (ML-DSA/SLH-DSA server certs), and cgo-linking OpenSSL contradicts the static-binary and no-crypto-in-core principles. Delegating to the engine keeps a single source of cryptographic truth.

**Risk & verification:** `s_server` flag surface must cover our needs (cert chain presentation, port binding, ALPN basics) — verify in an F4 spike before building UX around it. Fallback if it can't: a thin TCP proxy in front of `s_server`, still no native TLS.

**Confidence:** ~90% (below the 95% action bar for *design-freeze*, so F4 begins with the spike; the direction itself is safe because both outcomes keep OpenSSL as the TLS terminator).

## ADR-006: Naming, licensing, repo conventions

- **Name:** `pqc-fixtures` — verified unclaimed on npm and PyPI as of 2026-07-27 (both registries 404). **Maintainer action:** register the npm and PyPI names at slice launch, before any public post. Homebrew distribution starts as a personal tap (no squatting risk).
- **License:** MIT (per business plan; open-core).
- **Default branch:** `main` (repo's unborn `master` renamed before first commit).
- **Go module path:** `github.com/GreatSarmad/pqc-fixtures`.

**Confidence:** ~98%.

**F0 addendum (2026-07-27):** `go.mod` initially declared `module pqc-fixtures` (no domain) as a placeholder before the GitHub repository existed. Renaming it to the canonical import path was a mechanical change, not a new design decision.

**Publication update (2026-07-27):** the module and imports now use `github.com/GreatSarmad/pqc-fixtures`. This closes the F0 placeholder-path addendum without changing the ADR.

## ADR-007: Maintenance and release boundaries

**Decision:** Repository maintenance may update code and documentation, add tests, run builds, and research upstream releases, standards, and advisories. Changes land on `main` only after the relevant checks pass.

Publishing packages, creating public releases or tags, registering names or accounts, and posting publicly require explicit maintainer approval. Product code must not add telemetry or implicit network calls, introduce new cryptographic implementations, or store credentials in the repository. The core remains an orchestrator for the pinned engine.

Low-confidence design choices are documented for review rather than silently becoming implementation policy.

**Confidence:** ~97%.

## ADR-008: Engine vendoring mechanics — native per-platform builds, sibling `engine/` directory

**Decision:** Operationalizes ADR-001. Three parts:

1. **Build natively per platform, from pinned source.** `scripts/build-openssl.sh` downloads the pinned tarball, verifies its SHA-256 against `scripts/openssl-pin.env`, and configures with an explicit `Configure` target (`darwin64-arm64-cc`, `linux-x86_64`, `linux-aarch64`) — never `./config` autodetection. The release workflow therefore runs one native runner per platform (`macos-14`, `ubuntu-latest`, `ubuntu-24.04-arm`) instead of cross-compiling everything on one Linux runner. The Go core still cross-compiles trivially, but it is built on the same native runner so the archive is assembled and smoke-tested in one place.
2. **Ship the engine as a sibling directory, not embedded.** A release archive unpacks to `pqc-fixtures` + `engine/{openssl,ENGINE-VERSION,LICENSE.txt}` plus top-level `LICENSE` and `THIRD-PARTY-NOTICES.md`. The CLI resolves the engine at `<dir-of-executable>/engine/openssl`, with `PQC_FIXTURES_OPENSSL` as an explicit override for development and for packagers.
3. **Static, config-free engine.** Built `no-shared no-docs no-tests no-legacy` with `--openssldir=/nonexistent/pqc-fixtures-engine/ssl`, and always invoked with `OPENSSL_CONF=/dev/null`. The engine cannot pick up a system `openssl.cnf` and cannot resolve a system `libcrypto`, so output depends only on the pinned build.

**Rationale:**
- Cross-compiling OpenSSL needs a per-target toolchain and gives a build that cannot be smoke-tested on the builder; GitHub provides all three ADR-003 platforms as native runners, so the fragile path buys nothing.
- Embedding the engine in the Go binary (via `embed` + extract-to-temp) was considered and rejected: it doubles disk use per invocation, complicates future macOS notarization (the extracted binary is unsigned at its execution path), and makes the shipped engine harder for a security-minded user to inspect. A visible `engine/openssl` alongside `ENGINE-VERSION` is directly auditable — which matters for this audience (dossier §9).
- Downloading the engine on first run was rejected outright: it violates offline-by-default (dossier §3, ADR-007).
- The `--openssldir` pointing at a path that does not exist is deliberate: a stray system config is the most likely cause of "works on my machine" divergence in generated artifacts.

**Initial verification** on macOS arm64 against OpenSSL 3.5.7 confirmed a static build (only `libSystem` linked), a 6.2 MB engine binary, every required ML-DSA/SLH-DSA/ML-KEM parameter set, an end-to-end ML-DSA-65 certificate verification, and byte-identical seeded key generation. The first GitHub Actions run subsequently built and verified the same engine pipeline on Linux x86_64 and arm64.

**Costs accepted:** release wall-clock grows by the engine build (~2 min on an M-series runner; cached between releases on the pinned version); the archive grows by ~6 MB per platform.

**Confidence:** ~96%. The residual 4% is the unexecuted Linux build path, which fails loudly in CI rather than silently shipping something wrong.

## ADR-009: Public-release history policy — squash to a single initial commit, noreply authorship

**Decision:** The public `GreatSarmad/pqc-fixtures` repository starts from a **single squashed "initial public release" commit** on an orphan branch built from the current tracked tree — the local pre-publication history is never pushed. The public commit (and all future public commits) is authored as `GreatSarmad <97066252+GreatSarmad@users.noreply.github.com>`. The full local history is preserved on a local-only branch `pre-public-history` for archaeology.

**Rationale:**
- A gitignore entry cannot remove anything from already-committed history; publishing history publishes every path and author email it has ever contained. Squashing plus noreply authorship removes accidental identity exposure instead of requiring perpetual audits of pre-release history.
- Pre-launch history has zero audience value; a clean initial commit is the norm for tools open-sourced at first release.
- Acceptance is a **check, not an assertion**: a full-history secret scan (gitleaks) must pass on whatever is pushed, and the local git identity for this repo is switched to the noreply address so the policy holds for future commits.

**Confidence:** ~97%.

## ADR-010: Zero dependencies, including for tests; the manifest schema is checked by a purpose-built subset validator

**Decision:** `go.mod` declares no `require`d modules and none will be added without a new ADR — test-only dependencies included. Design-dossier §8 criterion 4 ("every Manifest validates against its published JSON Schema") is enforced by `tests/internal/schemacheck`, a ~200-line validator covering exactly the JSON Schema keywords `src/manifest/manifest.schema.json` uses (`type`, `properties`, `required`, `additionalProperties: false`, `items`, `enum`, `const`, `minimum`, `pattern`).

**Rationale:**
- Our audience is professionally paranoid about supply chain (dossier §9). A `go.mod` with an empty require block is a claim they can verify in five seconds, and `tests/cmd` asserts it stays that way. Go does not distinguish test-only dependencies in the module graph, so a jsonschema library would appear in every consumer's `go list -m all`.
- The alternative — a full JSON Schema library (e.g. `santhosh-tekuri/jsonschema`) — is less code for us and more code for everyone auditing us. For a schema this small the trade favours writing it.

**What makes a hand-written subset safe:** the validator treats *any* keyword it does not implement as a hard failure, not a silent pass. If the schema grows past the subset, the test fails and the choice (extend the validator, or take the dependency) is made deliberately rather than by omission. A negative-case test suite proves the validator can reject: missing required fields, wrong types, undeclared properties, bad enum values, malformed hashes.

**Consequence:** if a future feature needs real JSON Schema (`$ref`, `oneOf`, `if`/`then`, format assertions), take the dependency and supersede this ADR rather than growing a home-made implementation of a specification.

**Confidence:** ~96%.

## ADR-011: The `gen` output layout is a public contract

**Decision:** F1 fixes the following as the contract every downstream consumer (`serve`, the GitHub Action, `report`) may rely on, changeable only by bumping `manifest.schemaVersion`:

1. **Chain semantics.** `--chain N` is the number of certificates from root to leaf inclusive, 1–16. N=1 is a single self-signed certificate that is both the trust anchor and the TLS end entity; N=2 is root + leaf; N≥3 inserts `intermediate-1`…`intermediate-(N-2)` numbered from the root down. Each CA's `pathlen` equals the number of CAs below it, so a generated chain cannot be silently extended.
2. **Filenames.** `INSECURE-TEST-<role>.{key,cert}.{pem,der}`, plus `INSECURE-TEST-fullchain.pem` (leaf first), `INSECURE-TEST-README.txt`, and `manifest.json`. The prefix is a safety marker (dossier §9), not decoration, so it applies to every generated file except the manifest itself.
3. **`fullchain.pem` is always PEM**, whatever `--formats` says: DER has no representation for a sequence of certificates.
4. **Atomic replacement.** Output is staged in a sibling temp directory and moved into place only after the chain verifies and every size assertion passes. `--force` replaces a directory only if it contains a `manifest.json` that pqc-fixtures wrote; anything else is refused, so a mistyped `--out` cannot delete a user's data.
5. **Seed derivation.** A chain needs one key per certificate but a user supplies one `--seed`. Per-role sub-seeds are `SHA-256`-derived with domain separation, so the whole chain — keys and serial numbers — is reproducible from one value. This is labelling, not a security construction; the keys protect nothing.

**Rationale:** the Manifest is "the only contract between components" (dossier §6), and a contract that only describes the file *list* is not enough — `serve` needs to know which file is the chain, and CI caching needs stable names. Fixing the layout now costs nothing; discovering it later, after an Action depends on it, costs a breaking change.

**Confidence:** ~95%. The residual risk is chain-depth semantics: someone may read `--chain 3` as "three intermediates". The help text and README state the definition explicitly, and depth is recorded in the manifest.

### ADR-007 amendment: standing push authorization

**Granted by the founder, 2026-08-12.** Repository maintenance may push commits to `origin main` without asking each time, provided **all** of the following hold for that push:

- `make lint`, `make test`, and `make build` are green;
- `gitleaks git` exits 0;
- the repository-local `git config user.email` is `97066252+GreatSarmad@users.noreply.github.com`;
- the command is exactly `git push origin main` — never `--force`, never `--mirror`, never a tag or another branch.

Everything else in ADR-007 is unchanged. **Tags, releases, package publication, registrations, and public posts remain the founder's alone** — this amendment covers pushing already-reviewed commits to the default branch, nothing more. A push that cannot satisfy every condition above is a founder action item, not a judgement call.

### ADR-006 amendment: registry names are claimed by shipping, not before

**Decided by the founder, 2026-08-12**, superseding this ADR's original "register the npm and PyPI names at slice launch, before any public post."

Neither npm nor PyPI offers name reservation. Claiming `pqc-fixtures` on either requires publishing a real, installable package, and both registries treat empty placeholders as squatting and removable on request. "Register the name early" and "ship a distribution wrapper" are therefore the same action, and the original instruction assumed a cheap half that does not exist.

**New position:** registry names are claimed when the installer packages are genuinely functional — no earlier than the Stage-0 distribution wrappers, and after the CLI has consolidated (F2 presets at minimum). The GitHub release is the distribution channel until then.

**Risk accepted:** `pqc-fixtures` could be taken in the interval. Judged low — the name is specific, the project is now publicly visible under it with a tagged release, and a squatter would have no plausible package to publish. If either name is lost, renaming before wrappers exist is cheap; the Go module path and repository would change, the product would not.

**Consequence for sequencing:** the ROADMAP's "Release gate" item no longer blocks the demo post on registration. Publishing the demo post before the names exist is now an accepted, deliberate exposure rather than an oversight.
