# pqc-fixtures

`pqc-fixtures` is a developer-first CLI for generating realistically oversized
post-quantum certificates, keys, chains, and TLS test fixtures. Its goal is to
help teams find fixed buffers, parser limits, database-column limits, and other
assumptions that can break during a post-quantum migration.

> [!WARNING]
> This project creates **TEST ONLY** cryptographic material. Generated keys and
> certificates must never be used as production credentials.

## Project status

This project is pre-release: certificate-chain generation works, and there is
no tagged release yet.

The CLI supports:

- `pqc-fixtures gen` — generate a post-quantum certificate chain and manifest
- `pqc-fixtures schema` — print the JSON Schema for `manifest.json`
- `pqc-fixtures engine` — diagnose the bundled OpenSSL engine
- `pqc-fixtures --help` / `--version`

Presets (`jumbo`, `worst-case-tls`), ML-KEM key artifacts, `serve`, and the
GitHub Action are not implemented yet. See [ROADMAP.md](ROADMAP.md) for the
delivery sequence.

## Generating fixtures

```sh
pqc-fixtures gen --algo ml-dsa-65 --chain 3 --out ./testdata
```

```
generating 3-certificate ML-DSA-65 chain with OpenSSL 3.5.7
  [1/3] root             signature 3,309 B, public key 1,952 B
  [2/3] intermediate-1   signature 3,309 B, public key 1,952 B
  [3/3] leaf             signature 3,309 B, public key 1,952 B
  chain verifies against its own root
wrote 15 files to /path/to/testdata
```

The output directory contains, for each certificate in the chain, a private key
and a certificate in the requested encodings, plus a concatenated chain, a
plain-text warning, and a manifest:

```
INSECURE-TEST-root.key.pem            INSECURE-TEST-root.cert.pem
INSECURE-TEST-intermediate-1.key.pem  INSECURE-TEST-intermediate-1.cert.pem
INSECURE-TEST-leaf.key.pem            INSECURE-TEST-leaf.cert.pem
INSECURE-TEST-fullchain.pem           INSECURE-TEST-README.txt
manifest.json                         (…and .der copies of each key and cert)
```

`manifest.json` records every artifact's byte size and SHA-256, the algorithm's
expected size envelope, the exact engine version used, and the resolved
request. It is the contract other tools should read; its schema is published by
`pqc-fixtures schema`.

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--out` | *(required)* | Output directory |
| `--algo` | `ml-dsa-65` | `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`, `slh-dsa-sha2-256f` |
| `--chain` | `3` | Certificates from root to leaf **inclusive** (1–16) |
| `--days` | `30` | Validity in days; capped at 30 so fixtures expire |
| `--formats` | `pem,der` | `pem`, `der`, or both |
| `--seed` | *(none)* | Hex seed for reproducible keys (ML-DSA only) |
| `--sans` | `DNS:localhost,IP:127.0.0.1` | Leaf subject alternative names |
| `--force` | off | Replace a previous pqc-fixtures output directory |
| `--quiet` | off | Suppress progress output |

`--chain 1` produces a single self-signed certificate that is both the trust
anchor and the TLS server certificate; `--chain 2` is root + leaf.

### Why the artifacts are so obviously unusable

Every generated file is a test fixture by construction, and says so three ways:
an `INSECURE-TEST-` filename prefix, a `PQC-FIXTURES TEST ONLY` distinguished
name in every subject and issuer, and a validity window of at most 30 days.
Nothing generated chains to any real trust store, and the tool refuses to
replace a directory it did not create.

## Why this exists

Post-quantum artifacts are much larger than the RSA and elliptic-curve material
most systems handle today. `pqc-fixtures` will make it easy to test cases such
as:

- parsing ML-DSA and SLH-DSA certificates;
- storing oversized keys, signatures, and certificate chains;
- exercising deep or worst-case TLS chains;
- reproducing size-related failures locally and in CI.

The Go application implements orchestration only. Cryptographic operations are
delegated to a pinned, SHA-256-verified OpenSSL 3.5 build that ships with each
release archive. The released tool runs offline and never falls back silently
to a system OpenSSL installation.

## Build and test

Requirements for ordinary development are Go and `make`:

```sh
make lint
make test
make build
bin/pqc-fixtures --help
```

`make test` skips the tests that need a real engine. To run the full suite,
including the acceptance criteria that measure bytes on disk, build the engine
first and use `make test-engine`.

Building the vendored engine requires a native compiler toolchain and downloads
the pinned OpenSSL source once:

```sh
make engine
make verify-engine
PQC_FIXTURES_OPENSSL="$PWD/dist/engine/openssl" bin/pqc-fixtures engine
```

## Supported platforms

Release builds target:

- macOS arm64;
- Linux x86_64;
- Linux arm64.

Native Windows support is deferred for v1. Windows users should use WSL2.

## Reproducibility contract

The engine version and source checksum are pinned, and every manifest records
the engine that produced it. The generation contract is more precise than
“identical output every time”:

- `--seed` produces byte-identical ML-DSA keys, for every certificate in the
  chain, along with stable serial numbers. ML-DSA takes a 32-byte seed and
  ML-KEM a 64-byte one; the per-certificate sub-seeds are derived from the one
  value you pass;
- certificates keep the same structure and size envelope, but their bytes may
  differ between runs because of validity timestamps and hedged signatures;
- SLH-DSA cannot be seeded through the OpenSSL CLI, so `--seed` is a no-op for
  it and says so on stderr.

Each artifact's `seeded` flag in the manifest reports which of these applies,
per file rather than per run.

## Security and licensing

Please report security-sensitive findings through GitHub's private
vulnerability reporting once the public repository is available.

The Go project is licensed under the [MIT License](LICENSE). Release archives
also contain a statically built OpenSSL engine under the Apache License 2.0;
see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

Architecture and product rationale live in
[docs/design-dossier.md](docs/design-dossier.md), with binding decisions in
[docs/decisions.md](docs/decisions.md).
