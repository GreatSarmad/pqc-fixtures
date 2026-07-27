#!/usr/bin/env bash
#
# Verify a vendored engine binary is the pinned OpenSSL and can actually emit
# the PQC artifacts pqc-fixtures depends on (design-dossier §8, criteria 2-3).
#
# Kept separate from build-openssl.sh so the release workflow can re-run it
# against a downloaded artifact, not just a freshly built tree.
#
# Usage: scripts/verify-openssl.sh <path-to-openssl> [expected-version]

set -euo pipefail

engine="${1:?usage: verify-openssl.sh <path-to-openssl> [expected-version]}"
expected_version="${2:-}"

# The engine must never read a system openssl.cnf; this mirrors how the Go
# engine adapter will invoke it.
export OPENSSL_CONF=/dev/null

fail() { echo "FAIL: $*" >&2; exit 1; }

version_line="$("${engine}" version)"
echo "    ${version_line}"
if [ -n "${expected_version}" ]; then
  case "${version_line}" in
    "OpenSSL ${expected_version} "*|"OpenSSL ${expected_version}") ;;
    *) fail "expected OpenSSL ${expected_version}, got: ${version_line}" ;;
  esac
fi

# no-shared build: the engine must not resolve libcrypto/libssl from the system.
if command -v otool >/dev/null 2>&1; then
  linkage="$(otool -L "${engine}" || true)"
elif command -v ldd >/dev/null 2>&1; then
  linkage="$(ldd "${engine}" 2>&1 || true)"
else
  linkage=""
fi
case "${linkage}" in
  *libcrypto*|*libssl*) fail "engine links a shared libcrypto/libssl; expected a no-shared build" ;;
esac

sig_algs="$("${engine}" list -signature-algorithms)"
for alg in ML-DSA-44 ML-DSA-65 ML-DSA-87 SLH-DSA-SHA2-256f; do
  case "${sig_algs}" in
    *"${alg}"*) ;;
    *) fail "signature algorithm ${alg} missing from the default provider" ;;
  esac
done

kem_algs="$("${engine}" list -kem-algorithms)"
for alg in ML-KEM-512 ML-KEM-768 ML-KEM-1024; do
  case "${kem_algs}" in
    *"${alg}"*) ;;
    *) fail "KEM algorithm ${alg} missing from the default provider" ;;
  esac
done

# End-to-end: a real ML-DSA-65 key, a self-signed cert, and a verify. This is
# the smallest thing that proves the engine can do the slice's job, not just
# that it advertises the algorithms.
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

"${engine}" genpkey -algorithm ML-DSA-65 -out "${work}/key.pem" >/dev/null 2>&1 \
  || fail "ML-DSA-65 key generation failed"
"${engine}" req -x509 -new -key "${work}/key.pem" -out "${work}/cert.pem" \
  -days 30 -subj "/CN=PQC-FIXTURES TEST ONLY engine smoke test" >/dev/null 2>&1 \
  || fail "ML-DSA-65 self-signed certificate generation failed"
"${engine}" verify -CAfile "${work}/cert.pem" "${work}/cert.pem" >/dev/null 2>&1 \
  || fail "generated certificate failed openssl verify"

# Seeded keygen (ADR-002): ML-DSA takes a 32-byte seed, ML-KEM a 64-byte one.
seed32="$(printf '00%.0s' $(seq 1 32))"
"${engine}" genpkey -algorithm ML-DSA-65 -pkeyopt "hexseed:${seed32}" \
  -out "${work}/seeded-a.pem" >/dev/null 2>&1 \
  || fail "seeded ML-DSA-65 key generation failed (ADR-002 depends on it)"
"${engine}" genpkey -algorithm ML-DSA-65 -pkeyopt "hexseed:${seed32}" \
  -out "${work}/seeded-b.pem" >/dev/null 2>&1 \
  || fail "seeded ML-DSA-65 key generation failed on the second run"
cmp -s "${work}/seeded-a.pem" "${work}/seeded-b.pem" \
  || fail "seeded ML-DSA-65 keys are not byte-identical across runs"

sig_size="$("${engine}" list -signature-algorithms | grep -c 'SLH-DSA' || true)"
[ "${sig_size}" -gt 0 ] || fail "no SLH-DSA parameter sets found"

echo "    engine verified: PQC algorithms present, ML-DSA chain + seeded keygen OK"
