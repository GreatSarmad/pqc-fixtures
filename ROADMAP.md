# Roadmap — pqc-fixtures

Work queue for project development. Execute top-to-bottom within a stage unless an ADR reorders it.
Definitions and acceptance criteria live
in [docs/design-dossier.md](docs/design-dossier.md); binding decisions in [docs/decisions.md](docs/decisions.md).

Project conventions:
- Mark items `[x]` only when their acceptance criteria pass in a test.
- Merge to `main` only with a green test suite.
- Regularly check OpenSSL security advisories / 3.5.x patches and material NIST/IETF PQC changes.

## Stage 0 — validate (target: ~1 month)

- [x] **S1 spike (do first):** with a local OpenSSL 3.5 build, hand-generate every v1 artifact: ML-DSA-44/65/87 keys + self-signed certs + 3-deep chain; SLH-DSA-SHA2-256f cert; ML-KEM-512/768/1024 keys; seeded (`hexseed`) ML-DSA + ML-KEM keys; record exact commands + observed byte sizes in `docs/spike-notes.md`. This retires assumption A1 and pins ADR-002's SLH-DSA question. **Done 2026-07-27** — see [docs/spike-notes.md](docs/spike-notes.md): A1 confirmed (no OQS fork needed), size-fidelity numbers match the dossier exactly, SLH-DSA cannot be seeded via CLI (confirms ADR-002's fallback), ML-KEM seed is 64 B not 32 B.
- [ ] **F0 bootstrap:** Go module, standard Go project layout (`src/` packages with mirrored `tests/`), CI on macOS arm64 + Linux x86_64/arm64, and a release pipeline producing per-platform binaries with vendored OpenSSL 3.5.x (ADR-001). **Implementation and cross-platform validation completed 2026-07-27.** Landed: Go module (`src/cmd/pqc-fixtures`, `src/cli`, `src/engine`, mirrored `tests/`), `make build/test/lint/engine/verify-engine`, CI matrix, and the vendored-engine pipeline — pinned + checksummed OpenSSL 3.5.7 built from source (`scripts/build-openssl.sh`), verified (`scripts/verify-openssl.sh`), packaged per platform and smoke-tested in `release.yml`; mechanics recorded as ADR-008, evidence in [docs/engine-build-notes.md](docs/engine-build-notes.md). **Remaining before this item checks off:** tag `v0.0.1` and verify all three release archives.
- [ ] **F1 core gen (the vertical slice):** `pqc-fixtures gen --algo ml-dsa-65 --chain 3 --out ./testdata`; PEM+DER; `manifest.json` with JSON Schema; safety markers (TEST ONLY DN, ≤30-day validity, INSECURE-TEST- filenames); acceptance criteria 1–6 of the dossier.
- [ ] **F2 worst-case presets:** `jumbo` (SLH-DSA-SHA2-256f, 49,856 B signatures), `deep-chain`, `worst-case-tls`; size assertions from the AlgorithmProfile registry.
- [x] **Repository launch:** README + THIRD-PARTY-NOTICES; engine caching with verification; release archive compliance checks; safe development-build naming; weekly OpenSSL version watch; canonical Go module path; clean public history (ADR-009).
- [ ] **Demo assets:** draft blog post "watch a ~50 KB post-quantum cert break a default Node/Java/Postgres path" + reproduction scripts under `docs/demo/`.
- [ ] **Release gate:** publish `v0.0.1`; register `pqc-fixtures` on npm + PyPI; publish the demo post. *Stage-0 threshold: ~300 stars or clear inbound interest within 6–8 weeks.*

## Stage 1 — ship v1 (months 1–4)

- [ ] **F3 ML-KEM artifacts:** ML-KEM-512/768/1024 keys, raw/DER/PEM, hybrid-context bundle, `--seed` support (ADR-002).
- [ ] **F4 serve:** spike `s_server` flag coverage first (ADR-005), then `pqc-fixtures serve` presenting any generated chain; dossier criterion 7.
- [ ] **F5 GitHub Action + SARIF:** thin wrapper repo, probe runner, SARIF 2.1.0 output; dossier criterion 8. Marketplace listing requires maintainer approval.
- [ ] **F6 format matrix:** PKCS#12 bundles; oversized ML-DSA JWTs; unknown-critical-extension certs.
- [ ] Distribution wrappers: Homebrew tap formula, npm installer package, PyPI wheels (publishing requires maintainer approval).

## Stage 2 — monetize (months 4–12, gated on Stage-0/1 signal)

- [ ] **F7 composite/hybrid certificates** behind `--experimental` (needs second engine adapter; only on demand signal).
- [ ] **F8 `report`:** readiness-evidence export (HTML/PDF) from Manifests + RunReports; licensing gate design.
- [ ] Paid-tier mechanics, GitHub Sponsors, Einzelfirma registration (maintainer actions).

## Maintenance

- [ ] Ongoing OpenSSL advisory checks and PQC standards monitoring.

## Watchlist (leading indicators that change plans)

- IETF size-reduction work (Merkle Tree Certificates, cert compression) landing → shift emphasis to agility-regression testing (dossier "what would change the recommendation").
- A funded player shipping a developer-first fixture CLI → pivot to codemod (idea B) or composite-cert generator (idea E).
- OpenSSL 3.5.x security advisories → patch-bump the vendored engine and re-release.
- FN-DSA (FIPS 206) draft finalization; HQC standardization (2027); the nine round-3 signature candidates.
