#!/usr/bin/env bash
#
# Build the pinned, vendored OpenSSL engine required by ADR-001.
#
# Produces a self-contained `openssl` executable that pqc-fixtures invokes as a
# subprocess. The build is static (no-shared): the engine never depends on a
# system libcrypto, and the tool never depends on a system openssl.
#
# The engine MUST be built natively on the target platform (ADR-008) - OpenSSL's
# Configure needs a working toolchain for the target, unlike the Go core which
# cross-compiles.
#
# Usage:
#   scripts/build-openssl.sh [--out DIR] [--work DIR] [--jobs N]
#
#   --out   where the engine directory is written (default: dist/engine)
#   --work  scratch directory for download + build (default: a mktemp dir)
#   --jobs  make parallelism (default: detected core count)
#
# Output layout (consumed by src/engine and the release workflow):
#   <out>/openssl          the engine executable
#   <out>/ENGINE-VERSION   pinned version string, e.g. "3.5.7"
#   <out>/LICENSE.txt      OpenSSL's Apache-2.0 license, redistributed with it

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=./openssl-pin.env
source "${repo_root}/scripts/openssl-pin.env"

out_dir="${repo_root}/dist/engine"
work_dir=""
jobs=""

while [ $# -gt 0 ]; do
  case "$1" in
    --out) out_dir="$2"; shift 2 ;;
    --work) work_dir="$2"; shift 2 ;;
    --jobs) jobs="$2"; shift 2 ;;
    -h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "build-openssl.sh: unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -z "${work_dir}" ]; then
  work_dir="$(mktemp -d)"
  trap 'rm -rf "${work_dir}"' EXIT
fi
mkdir -p "${work_dir}" "${out_dir}"

if [ -z "${jobs}" ]; then
  jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
fi

tarball="${work_dir}/openssl-${OPENSSL_VERSION}.tar.gz"
url="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"

echo "==> Fetching OpenSSL ${OPENSSL_VERSION}"
if [ ! -f "${tarball}" ]; then
  curl -fsSL --retry 3 -o "${tarball}" "${url}"
fi

echo "==> Verifying SHA-256 against the pin"
actual="$(
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${tarball}" | cut -d' ' -f1
  else
    shasum -a 256 "${tarball}" | cut -d' ' -f1
  fi
)"
if [ "${actual}" != "${OPENSSL_SHA256}" ]; then
  echo "checksum mismatch for ${tarball}" >&2
  echo "  expected ${OPENSSL_SHA256}" >&2
  echo "  actual   ${actual}" >&2
  exit 1
fi
echo "    ok ${actual}"

src_dir="${work_dir}/openssl-${OPENSSL_VERSION}"
if [ ! -d "${src_dir}" ]; then
  echo "==> Extracting"
  tar -xzf "${tarball}" -C "${work_dir}"
fi

# Explicit Configure target rather than ./config's autodetection, so the release
# artifacts are reproducible and a misdetected host fails loudly instead of
# silently producing a differently-tuned build.
os="$(uname -s)"
arch="$(uname -m)"
case "${os}/${arch}" in
  Darwin/arm64)        target=darwin64-arm64-cc ;;
  Darwin/x86_64)       target=darwin64-x86_64-cc ;;
  Linux/x86_64)        target=linux-x86_64 ;;
  Linux/aarch64|Linux/arm64) target=linux-aarch64 ;;
  *)
    echo "build-openssl.sh: unsupported host ${os}/${arch}" >&2
    echo "ADR-003 targets darwin/arm64, linux/amd64, linux/arm64; ADR-004 defers Windows." >&2
    exit 1
    ;;
esac
echo "==> Configuring (${target})"

# no-shared   : static engine, no system libcrypto dependency at runtime
# no-docs     : skip pod2man/pod2html (not shipped, and drops a perl module need)
# no-tests    : we do not run OpenSSL's own suite here; we assert PQC behaviour
#               in tests/engine against the built binary
# no-legacy   : the legacy provider (MD4, RC4, ...) is dead weight for fixtures
# --openssldir: a path that intentionally does not exist on user machines, so
#               the engine never picks up a system openssl.cnf. The PQC
#               algorithms live in the built-in default provider, so no config
#               file and no loadable provider module is required.
(
  cd "${src_dir}"
  ./Configure "${target}" \
    no-shared \
    no-docs \
    no-tests \
    no-legacy \
    --prefix=/nonexistent/pqc-fixtures-engine \
    --openssldir=/nonexistent/pqc-fixtures-engine/ssl
  echo "==> Building with -j${jobs} (this takes several minutes)"
  make -j"${jobs}" build_sw
)

echo "==> Staging engine into ${out_dir}"
cp "${src_dir}/apps/openssl" "${out_dir}/openssl"
chmod 0755 "${out_dir}/openssl"
cp "${src_dir}/LICENSE.txt" "${out_dir}/LICENSE.txt"
printf '%s\n' "${OPENSSL_VERSION}" > "${out_dir}/ENGINE-VERSION"

echo "==> Smoke-testing the engine"
"${repo_root}/scripts/verify-openssl.sh" "${out_dir}/openssl" "${OPENSSL_VERSION}"

echo "==> Done: ${out_dir}/openssl"
