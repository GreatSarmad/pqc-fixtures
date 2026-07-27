# Engine build notes — vendoring pinned OpenSSL 3.5.7 (F0)

**Date:** 2026-07-27
**Goal:** close the last open piece of F0 — produce the pinned, checksummed, per-platform OpenSSL engine that ADR-001 requires, and prove the shipped CLI can find and use it.
**Outcome:** the build recipe, verification harness, and release packaging are verified end-to-end on macOS arm64. GitHub Actions also built and verified the engine on native Linux x86_64 and arm64 runners. The mechanics are recorded as [ADR-008](decisions.md).

## Why 3.5.7 specifically

- **3.5.x** is the LTS branch (EOL 2030-04-08) and the first OpenSSL line with ML-KEM/ML-DSA/SLH-DSA in the *default* provider — no OQS provider, no config file, no loadable module (confirmed in the [S1 spike](spike-notes.md)).
- **.7** is the latest 3.5.x patch (released 2026-06-09) and the first with no known unpatched High-severity issue: 3.5.6 and earlier are affected by **CVE-2026-45447**, a heap use-after-free in `PKCS7_verify()`. Pinning any earlier 3.5.x would ship a known-RCE engine on day one.

The pin lives in [`scripts/openssl-pin.env`](../scripts/openssl-pin.env) — one file, read by the build script, the release workflow, and a Go test that asserts it matches `engine.PinnedVersion`.

## Provenance

```
openssl-3.5.7.tar.gz
sha256 a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8
```

The digest was taken from two independent locations that agreed byte-for-byte: `openssl-library.org/source/` and the `openssl/openssl` GitHub release asset `openssl-3.5.7.tar.gz.sha256`. The downloaded tarball (53,153,930 bytes) hashes to the same value. `scripts/build-openssl.sh` re-checks this on every build and aborts on mismatch — the tarball is never extracted before the check passes.

## Build recipe

```bash
./Configure darwin64-arm64-cc \
  no-shared no-docs no-tests no-legacy \
  --prefix=/nonexistent/pqc-fixtures-engine \
  --openssldir=/nonexistent/pqc-fixtures-engine/ssl
make -j"$(getconf _NPROCESSORS_ONLN)" build_sw
```

Target is chosen explicitly from `uname` (`darwin64-arm64-cc`, `linux-x86_64`, `linux-aarch64`) rather than via `./config` autodetection, so a misdetected host fails loudly instead of quietly producing a differently-tuned build.

Why each flag:

| Flag | Reason |
|---|---|
| `no-shared` | The engine must not resolve a system `libcrypto`/`libssl`. Verified: the built binary links only `libSystem.B.dylib`. |
| `no-docs` | Nothing is shipped from `man`/`html`, and it drops a `pod2man` build dependency. |
| `no-tests` | OpenSSL's own suite is not our gate; `scripts/verify-openssl.sh` asserts the behaviour *we* depend on. Cuts build time substantially. |
| `no-legacy` | The legacy provider (MD4, RC4, …) is dead weight for PQC fixtures. |
| `--openssldir=/nonexistent/...` | The engine can never pick up a system `openssl.cnf`. A stray system config is the likeliest cause of "works on my machine" divergence in generated artifacts. Reinforced at runtime with `OPENSSL_CONF=/dev/null`. |

`build_sw` (not `make`) is used because docs are already disabled and we only need libraries + `apps/openssl`.

## Observed on macOS arm64 (M-series, 10 cores)

| Measure | Value |
|---|---|
| Configure | ~30 s |
| Compile (1,182 objects, `-j10`) | ~20 s |
| Total wall clock incl. extract + link | ~90 s |
| Engine binary | 6,460,792 B (6.2 MB) |
| Dynamic linkage | `/usr/lib/libSystem.B.dylib` only |
| `openssl version` | `OpenSSL 3.5.7 9 Jun 2026` |
| `platform:` | `darwin64-arm64-cc` |
| `OPENSSLDIR:` | `/nonexistent/pqc-fixtures-engine/ssl` |

GitHub-hosted runners are slower than this laptop; the release workflow caches the engine on the pinned version so the cost is paid once per pin, not once per release.

## What `verify-openssl.sh` asserts

Run after every build and again on cache hits in the release workflow:

1. `openssl version` matches the pinned version exactly.
2. The binary links no shared `libcrypto`/`libssl` (via `otool -L` / `ldd`).
3. `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`, `SLH-DSA-SHA2-256f` are present in `list -signature-algorithms`.
4. `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` are present in `list -kem-algorithms`.
5. End-to-end: generate an ML-DSA-65 key → self-signed cert (`TEST ONLY` subject, 30-day validity) → `openssl verify` succeeds.
6. Seeded ML-DSA-65 keygen (`hexseed`, 32 bytes per the S1 spike) produces byte-identical keys across two runs — the property ADR-002 depends on.

All six passed against the freshly built 3.5.7 engine.

## Release layout

A release archive unpacks to:

```
pqc-fixtures            # Go core
engine/openssl          # vendored, pinned engine
engine/ENGINE-VERSION   # "3.5.7"
engine/LICENSE.txt      # OpenSSL's Apache-2.0 text, redistributed with it
LICENSE                 # our MIT license
THIRD-PARTY-NOTICES.md  # bundled-engine attribution and license pointer
```

`src/engine` resolves `<dir-of-executable>/engine/openssl`, with `PQC_FIXTURES_OPENSSL` as an explicit override. Verified locally against the real engine:

```
$ ./pqc-fixtures engine
path:    .../rel/engine/openssl
version: 3.5.7
pinned:  3.5.7
source:  bundled
```

and the failure path a user hits if they copy the binary out of the archive:

```
$ ./loose-pqc engine
pqc-fixtures: vendored OpenSSL engine not found at .../engine/openssl: ... no such file or directory

The engine ships inside the release archive; unpack the whole archive rather than
copying the binary out of it, or point PQC_FIXTURES_OPENSSL at an OpenSSL 3.5.7 build
```

## What is *not* verified

- **macOS Gatekeeper.** An unsigned, un-notarized `engine/openssl` downloaded through a browser will be quarantined; `curl`/`brew`/`npx` installs are unaffected. Signing needs an Apple Developer account and remains a release prerequisite.
- **Release signing / SBOM** (dossier §9) are not implemented; the workflow emits a `.sha256` per archive only.
