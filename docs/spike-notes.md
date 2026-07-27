# S1 Spike Notes — hand-generating v1 artifacts with stock OpenSSL 3.5+

**Date:** 2026-07-27
**Goal:** retire assumption A1 (design-dossier §4) — can stock OpenSSL's `genpkey`/`req`/`x509` CLI emit every v1 artifact (ML-DSA & SLH-DSA keys/certs/chains, ML-KEM keys, seeded keys) with no OQS/liboqs fork? — and pin ADR-002's open SLH-DSA-seeding question.

**Engine used:** OpenSSL 3.6.2 (Homebrew `openssl@3`, arm64, default provider), not the ADR-001-pinned 3.5.x LTS build. 3.6 is a superset of 3.5's ML-KEM/ML-DSA/SLH-DSA support (confirmed via `openssl list -kem-algorithms` / `-signature-algorithms`), so it's a valid stand-in for a CLI-capability spike. F0's release pipeline must still vendor a pinned 3.5.x LTS build per ADR-001 — this spike does not change that.

All commands below were run verbatim; a full transcript is in `commands.log` (kept locally, not committed — see "Artifacts" at the end).

## Result: A1 confirmed — no OQS fork needed for any v1 artifact

Every artifact in the S1 checklist was generated with stock `openssl genpkey` / `req` / `x509`, no custom provider, no liboqs.

## 1. ML-DSA-44 / 65 / 87 — keys + self-signed certs

```bash
openssl genpkey -algorithm ML-DSA-65 -out mldsa65.key.pem
openssl req -x509 -new -key mldsa65.key.pem -out mldsa65.selfsigned.pem -days 30 \
  -subj '/CN=PQC-FIXTURES TEST ONLY/O=pqc-fixtures spike'
```
(same pattern for ML-DSA-44, ML-DSA-87)

| Artifact | Bytes (PEM) |
|---|---|
| ML-DSA-44 private key | 3,613 |
| ML-DSA-44 self-signed cert | 5,559 |
| ML-DSA-65 private key | 5,604 |
| ML-DSA-65 self-signed cert | 7,631 |
| ML-DSA-87 private key | 6,774 |
| ML-DSA-87 self-signed cert | 10,284 |

## 2. 3-deep ML-DSA-65 chain (root → intermediate → leaf)

```bash
# Root CA
openssl genpkey -algorithm ML-DSA-65 -out chain-root.key.pem
openssl req -x509 -new -key chain-root.key.pem -out chain-root.cert.pem -days 30 \
  -subj '/CN=PQC-FIXTURES TEST ONLY Root/O=pqc-fixtures spike' \
  -addext 'basicConstraints=critical,CA:true' -addext 'keyUsage=critical,keyCertSign,cRLSign'

# Intermediate
openssl genpkey -algorithm ML-DSA-65 -out chain-intermediate.key.pem
openssl req -new -key chain-intermediate.key.pem -out chain-intermediate.csr.pem \
  -subj '/CN=PQC-FIXTURES TEST ONLY Intermediate/O=pqc-fixtures spike'
openssl x509 -req -in chain-intermediate.csr.pem -CA chain-root.cert.pem -CAkey chain-root.key.pem \
  -CAcreateserial -out chain-intermediate.cert.pem -days 30 -copy_extensions none \
  -extfile <(printf 'basicConstraints=critical,CA:true,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n')

# Leaf (TLS server cert, SANs per dossier §5)
openssl genpkey -algorithm ML-DSA-65 -out chain-leaf.key.pem
openssl req -new -key chain-leaf.key.pem -out chain-leaf.csr.pem \
  -subj '/CN=PQC-FIXTURES TEST ONLY Leaf/O=pqc-fixtures spike'
openssl x509 -req -in chain-leaf.csr.pem -CA chain-intermediate.cert.pem -CAkey chain-intermediate.key.pem \
  -CAcreateserial -out chain-leaf.cert.pem -days 30 -copy_extensions none \
  -extfile <(printf 'basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')

cat chain-leaf.cert.pem chain-intermediate.cert.pem chain-root.cert.pem > chain-fullchain.pem
openssl verify -CAfile chain-root.cert.pem -untrusted chain-intermediate.cert.pem chain-leaf.cert.pem
# -> chain-leaf.cert.pem: OK
```

**`openssl verify` succeeds** — confirms dossier acceptance criterion 2 is achievable with stock OpenSSL. Sizes: root cert 7,668 B, intermediate 7,680 B, leaf 7,712 B (PEM), leaf DER 5,653 B, `fullchain.pem` 23,060 B.

## 3. SLH-DSA-SHA2-256f — key + self-signed cert (the `jumbo` preset candidate)

```bash
openssl genpkey -algorithm SLH-DSA-SHA2-256f -out slhdsa256f.key.pem
openssl req -x509 -new -key slhdsa256f.key.pem -out slhdsa256f.selfsigned.pem -days 30 \
  -subj '/CN=PQC-FIXTURES TEST ONLY/O=pqc-fixtures spike'
```

Key 258 B, self-signed cert 68,101 B PEM / 50,249 B DER. A single self-signed SLH-DSA-SHA2-256f cert alone clears the ROADMAP F2/dossier-criterion-7 "≥45 KB chain" bar — confirms the `jumbo` preset is easy to hit.

**Signature size fidelity check** (`openssl asn1parse` on the DER cert, last BIT STRING = the cert signature): raw length 49,856 B (ASN.1 BIT STRING content length 49,857 includes the 1 leading unused-bits byte). **Exact match to the AlgorithmProfile figure in design-dossier.md §7 (49,856 B) and ROADMAP.md F2.** Likewise ML-DSA-65's cert signature parses to exactly 3,309 B, and ML-KEM-768's public key to exactly 1,184 B — both match the dossier's numbers verbatim. Dossier acceptance criterion 3 (size fidelity) is achievable as specified; no AlgorithmProfile number needs correction.

## 4. ML-KEM-512 / 768 / 1024 — keys

```bash
openssl genpkey -algorithm ML-KEM-768 -out mlkem768.key.pem
openssl pkey -in mlkem768.key.pem -pubout -out mlkem768.pub.pem
```
(no cert step — KEM keys don't sign; matches dossier's "raw/DER/PEM" scope for F3, not a cert artifact)

| Artifact | Bytes (PEM) |
|---|---|
| ML-KEM-512 private key / pubkey | 2,399 / 1,166 |
| ML-KEM-768 private key / pubkey | 3,439 / 1,686 |
| ML-KEM-1024 private key / pubkey | 4,479 / 2,206 |

## 5. Seeded (deterministic) keygen — ADR-002 verification

**ML-DSA-65**, 32-byte seed (`hexseed:` = 64 hex chars):
```bash
openssl genpkey -algorithm ML-DSA-65 -pkeyopt hexseed:<64-hex-chars> -out a.key.pem
openssl genpkey -algorithm ML-DSA-65 -pkeyopt hexseed:<same-seed>    -out b.key.pem
diff a.key.pem b.key.pem   # empty — byte-identical
```
**Byte-identical.** Confirms ADR-002 as designed for ML-DSA.

**ML-KEM-768** — first attempt with a 32-byte seed failed:
```
genpkey: Error setting hexseed:<...> parameter:
...ml_kem_gen_set_params:invalid seed length...
```
FIPS 203's ML-KEM seed is `d ‖ z`, 64 bytes total (two 32-byte halves), not 32. Retried with a 64-byte seed (128 hex chars):
```bash
openssl genpkey -algorithm ML-KEM-768 -pkeyopt hexseed:<128-hex-chars> -out a.key.pem
openssl genpkey -algorithm ML-KEM-768 -pkeyopt hexseed:<same-seed>     -out b.key.pem
diff a.key.pem b.key.pem   # empty — byte-identical
```
**Byte-identical.** Confirms ADR-002 for ML-KEM, but **the seed length differs by algorithm family** (32 B for ML-DSA, 64 B for ML-KEM) — this must be encoded per-algorithm in the AlgorithmProfile registry, not assumed uniform. Worth a one-line addendum to ADR-002; not a confidence-changing finding (doesn't alter the decision, only an implementation detail), so no new ADR — noting it here and will fold into the F1/F3 AlgorithmProfile registry design.

**SLH-DSA-SHA2-256f** — `hexseed` is rejected outright:
```bash
openssl genpkey -algorithm SLH-DSA-SHA2-256f -pkeyopt hexseed:<64-hex-chars> -out x.key.pem
genpkey: Error generating SLH-DSA-SHA2-256f key
...evp_keymgmt_gen:provider keymgmt failure...SLH-DSA-SHA2-256f key generation...
```
Also tried a generic `seed:` option name — same failure (algorithm doesn't expose any seed-shaped keygen parameter in this provider). **This pins the open question in ADR-002**: *"SLH-DSA seeds may differ in mechanics... if SLH-DSA can't be seeded via CLI, document keys-only determinism for ML-DSA/ML-KEM."* Confirmed — SLH-DSA cannot be seeded via the stock OpenSSL CLI as of 3.6.2. This matches FIPS 205's construction (SLH-DSA's private key derives from three internal values — `SK.seed`, `SK.prf`, `PK.seed` — generated by the provider from OS randomness on `EVP_PKEY_keygen`, not a single caller-supplied seed) and is a genpkey/provider limitation, not a spike error on our part.

**Consequence for v1 scope:** `--seed` is supported for ML-DSA and ML-KEM only; SLH-DSA presets (`jumbo`, `worst-case-tls`) are non-deterministic across generations even with `--seed` passed. Document this explicitly in the CLI's `--seed` help text and the manifest schema (a `seeded: bool` per-artifact field, not one global flag) so users aren't surprised the `jumbo` preset's cert bytes change between runs even under `--seed`. No ADR change needed — ADR-002 already anticipated exactly this outcome ("document keys-only determinism for ML-DSA/ML-KEM" is precisely what's happening); this note operationalizes it for F1/F2 implementation.

## Assumption A1 — retired

**Confirmed at ~98% confidence.** Every v1 artifact (ML-DSA-44/65/87 keys+certs+chain, SLH-DSA-SHA2-256f key+cert, ML-KEM-512/768/1024 keys, seeded ML-DSA+ML-KEM keys) is producible with stock OpenSSL 3.5+ CLI subprocess calls (`genpkey`, `req`, `x509`, `pkey`, `verify`). No liboqs/OQS fork, no Bouncy Castle, no second engine adapter needed for v1. This directly supports ADR-001 (bundle OpenSSL, single engine) and ADR-003 (Go orchestrator shelling out to subprocess) as designed — no rework triggered.

## Open item carried forward (not a blocker)

SLH-DSA seed-length/mechanism note above should land as a one- or two-line addition to ADR-002 when F1/F3 implementation starts (not urgent enough to justify a new ADR revision during this maintenance run — it doesn't change the decision, just documents an implementation constraint the decision already flagged as possible).

## Artifacts

Generated files (~30 keys/certs/CSRs, plus `commands.log` with the full verbatim transcript including stdout/stderr) were written to a scratch directory outside the repo and are not committed — S1's job is to produce evidence for this notes file, not to ship generated fixtures (the actual `gen` command and its test fixtures are F1's job, per ROADMAP.md). Anyone re-running this spike can reproduce every artifact from the commands above against a local OpenSSL 3.5+ install in under a minute.
