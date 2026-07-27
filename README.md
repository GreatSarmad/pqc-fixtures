# pqc-fixtures

`pqc-fixtures` is a developer-first CLI for generating realistically oversized
post-quantum certificates, keys, chains, and TLS test fixtures. Its goal is to
help teams find fixed buffers, parser limits, database-column limits, and other
assumptions that can break during a post-quantum migration.

> [!WARNING]
> This project creates **TEST ONLY** cryptographic material. Generated keys and
> certificates must never be used as production credentials.

## Project status

This project is pre-release. The repository bootstrap and pinned OpenSSL engine
pipeline are implemented; fixture generation is the next milestone.

The CLI currently supports:

- `pqc-fixtures --help`
- `pqc-fixtures --version`
- `pqc-fixtures engine`, which diagnoses the bundled OpenSSL engine

The `gen`, preset, and `serve` commands described in the roadmap are not yet
implemented. See [ROADMAP.md](ROADMAP.md) for the delivery sequence.

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

The engine version and source checksum are pinned, and release archives record
the engine they contain. The planned v1 generation contract is more precise
than “identical output every time”:

- `--seed` will produce byte-identical ML-DSA and ML-KEM keys; ML-DSA uses a
  32-byte seed and ML-KEM uses a 64-byte seed;
- certificates will keep the same structure and size envelope, but their bytes
  may differ because of validity timestamps and hedged signatures;
- SLH-DSA cannot be seeded through the OpenSSL CLI and will remain
  non-deterministic.

These generation behaviors are design commitments for the upcoming `gen`
milestone, not commands available in the current bootstrap release.

## Security and licensing

Please report security-sensitive findings through GitHub's private
vulnerability reporting once the public repository is available.

The Go project is licensed under the [MIT License](LICENSE). Release archives
also contain a statically built OpenSSL engine under the Apache License 2.0;
see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

Architecture and product rationale live in
[docs/design-dossier.md](docs/design-dossier.md), with binding decisions in
[docs/decisions.md](docs/decisions.md).
