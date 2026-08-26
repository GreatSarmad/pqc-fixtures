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
- [x] **F0 bootstrap:** Go module, standard Go project layout (`src/` packages with mirrored `tests/`), CI on macOS arm64 + Linux x86_64/arm64, and a release pipeline producing per-platform binaries with vendored OpenSSL 3.5.x (ADR-001). **Implementation and cross-platform validation completed 2026-07-27.** Landed: Go module (`src/cmd/pqc-fixtures`, `src/cli`, `src/engine`, mirrored `tests/`), `make build/test/lint/engine/verify-engine`, CI matrix, and the vendored-engine pipeline — pinned + checksummed OpenSSL 3.5.7 built from source (`scripts/build-openssl.sh`), verified (`scripts/verify-openssl.sh`), packaged per platform and smoke-tested in `release.yml`; mechanics recorded as ADR-008, evidence in [docs/engine-build-notes.md](docs/engine-build-notes.md). **Closed 2026-08-12:** `v0.0.1` tagged; `release.yml` produced and smoke-tested all three archives (darwin-arm64 5.9 MB, linux-amd64 6.3 MB, linux-arm64 6.4 MB), each asserting the licence files, `ENGINE-VERSION`, a `v0.0.1` version stamp, and a bundled engine reporting 3.5.7. The archives are workflow artifacts; turning them into a published GitHub release is a founder action (ADR-007).
- [x] **F1 core gen (the vertical slice):** `pqc-fixtures gen --algo ml-dsa-65 --chain 3 --out ./testdata`; PEM+DER; `manifest.json` with JSON Schema; safety markers (TEST ONLY DN, ≤30-day validity, INSECURE-TEST- filenames); acceptance criteria 1–6 of the dossier. **Done 2026-08-12.** `src/profile` (AlgorithmProfile registry), `src/manifest` (schema + embedded contract), `src/gen` (resolution, planning, atomic generation, size assertions), `gen`/`schema` CLI commands; layout fixed as ADR-011, dependency policy as ADR-010. 66 tests; the engine-backed ones (criteria 1–6) run via `make test-engine` in `engine.yml` on all three platforms.
- [x] **F2 worst-case presets:** `jumbo` (SLH-DSA-SHA2-256f, 49,856 B signatures), `deep-chain`, `worst-case-tls`; size assertions from the AlgorithmProfile registry. **Done 2026-08-19.** `src/preset` loads versioned JSON data files (design-dossier §6: presets are data, not code) with `gen --preset` and a `presets` command; no preset file carries a byte count — every size is derived from `src/profile`, and `gen` now asserts the whole chain against a registry-derived floor. The manifest records the preset name, version, and whether a flag overrode it. Measured against the pinned 3.5.7 engine: `jumbo` 50,309 B, `deep-chain` 76,079 B, `worst-case-tls` 150,911 B of DER, all in under half a second.
- [x] **Repository launch:** README + THIRD-PARTY-NOTICES; engine caching with verification; release archive compliance checks; safe development-build naming; weekly OpenSSL version watch; canonical Go module path; clean public history (ADR-009).
- [x] **Demo assets:** draft blog post "watch a ~50 KB post-quantum cert break a default Node/Java/Postgres path" + reproduction scripts under `docs/demo/`. **Done 2026-08-25.** `docs/demo/run.sh` plus four probes; [`demo.yml`](.github/workflows/demo.yml) runs all of them on a runner with every runtime, fails if any probe is skipped, and uploads the transcript. Every claim is measured: an ML-DSA-65 *chain* (23,088 B PEM → 25,200 B escaped) overflows Node's 16,384 B default header budget as `HPE_HEADER_OVERFLOW` → `ECONNRESET`; Node refuses SLH-DSA at `tls.createSecureContext` while handshaking ML-DSA fine; Temurin 21 exceeds `jdk.tls.maxHandshakeMessageSize` at 461% (`worst-case-tls`) and 232% (`deep-chain`, which also exceeds the server-side 8-certificate cap); PostgreSQL 17 rejects the chain from `varchar(4096)` and from a btree index (`requires 23104 bytes, maximum size is 8191`), and accepts a `digest(pem,'sha256')` index. [POST-DRAFT.md](docs/demo/POST-DRAFT.md) is structured with all numbers filled in. **Remaining is founder-only:** writing the final prose, deciding the visual asset, and publishing (ADR-007).

- [x] **Release gate:** **`v0.0.3` published 2026-08-26** as a pre-release, with all three archives and their checksums. It carries the OpenSSL 3.5.8 security bump, the F2 presets, the symlink install fix, and the README's first install section. Verified as a user would: downloaded from the public release URL unauthenticated, checksum verified, unpacked, `--version` = `v0.0.3`, engine reports 3.5.8 / `source: bundled`, and a generated ML-DSA-65 chain verifies against its own root. `v0.0.1` is annotated as superseded. (`v0.0.2` was tagged and built but never published — the symlink fix landed first; the tag remains and points at a working build.) The remaining Stage-0 step is the demo post.

## Stage 1 — ship v1 (months 1–4)

- [ ] **F3 ML-KEM artifacts:** ML-KEM-512/768/1024 keys, raw/DER/PEM, hybrid-context bundle, `--seed` support (ADR-002). *Audit note (2026-08-19): the anticipatory public-key surface — `engine.PublicKey`, manifest kind `publicKey` and its schema enum value — was removed as dead code; reintroduce it here, with tests, when the first bare-key artifact needs it.*
- [ ] **F4 serve:** spike `s_server` flag coverage first (ADR-005), then `pqc-fixtures serve` presenting any generated chain; dossier criterion 7.
- [ ] **F5 GitHub Action + SARIF:** thin wrapper repo, probe runner, SARIF 2.1.0 output; dossier criterion 8. Marketplace listing requires maintainer approval.
- [ ] **F6 format matrix:** PKCS#12 bundles; oversized ML-DSA JWTs; unknown-critical-extension certs.
- [ ] Distribution wrappers: Homebrew tap formula, npm installer package, PyPI wheels (publishing requires maintainer approval).

## Stage 2 — later (gated on demand signal)

- [ ] **F7 composite/hybrid certificates** behind `--experimental` (needs a second engine adapter; only on demand signal).
- [ ] **F8 `report`:** readiness-evidence export (HTML/PDF) built from Manifests and RunReports.

## Maintenance

- [ ] Ongoing OpenSSL advisory checks and PQC standards monitoring.

## Watchlist (leading indicators that change plans)

- IETF size-reduction work (Merkle Tree Certificates, certificate compression) landing → shift emphasis from size fixtures to agility-regression testing.
- OpenSSL 3.5.x security advisories → patch-bump the vendored engine and re-release.
- FN-DSA (FIPS 206) draft finalization; HQC standardization (2027); the nine round-3 signature candidates.
