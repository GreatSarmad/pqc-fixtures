# Third-party notices

## OpenSSL

Release archives for `pqc-fixtures` include a statically built OpenSSL engine.
The exact version and source checksum are recorded in
[`scripts/openssl-pin.env`](scripts/openssl-pin.env).

- Project: OpenSSL
- Copyright: The OpenSSL Project Authors
- License: Apache License 2.0
- Source: <https://github.com/openssl/openssl>

Each release archive ships the complete OpenSSL license text as
`engine/LICENSE.txt`. The pinned OpenSSL 3.5.8 source distribution contains no
upstream `NOTICE` file to reproduce.

`pqc-fixtures` invokes this engine as a subprocess and does not implement or
modify OpenSSL's cryptographic primitives.
