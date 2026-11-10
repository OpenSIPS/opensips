#!/bin/sh
# scripts/build/install_libnats.sh -- install the libnats C client SDK.
#
# The NATS modules in modules-contrib/ (nats, event_nats, cachedb_nats,
# cachedb_nats_fts, nats_consumer) depend on the libnats C client SDK.
# Used by the unit-test workflow (unittests.yml) on its native legs.
# Ubuntu < 22.04 does
# not ship libnats-dev in apt, and the package is universe-only on
# 22.04+, so rather than maintain split logic we always build from a
# pinned source tarball.  Output is staged at $LIBNATS_PREFIX (default
# /usr/local) so the in-tree Makefile.nats pkg-config probe finds it.
#
# Idempotent: if libnats is already installed (e.g. a CI cache hit
# restored /usr/local before this script ran), the build is skipped.
#
# Soft dep: the Makefiles gate themselves on libnats availability, so
# if this script fails the build still proceeds with the NATS modules
# silently absent.  We still 'set -e' so a real failure surfaces in
# CI logs rather than masquerading as a successful build with no
# NATS coverage.

set -e

# nats-io/nats.c release to build.  3.14 is the first release with the
# per-key KV TTL API cachedb_nats requires (kvConfig.LimitMarkerTTL and
# kvStore_*WithTTL).  A pinned tag (not 'main') keeps every CI leg building
# the SAME libnats.
LIBNATS_VERSION="${LIBNATS_VERSION:-v3.14.0}"
LIBNATS_PREFIX="${LIBNATS_PREFIX:-/usr/local}"
# TLS in the libnats build (-DNATS_BUILD_WITH_TLS).  Default OFF: the OpenSIPS
# NATS modules link libnats at runtime via dlopen and only need it to
# build/link, and slim/cross images lack a locatable OpenSSL.  The sanitizer
# and TLS-backend workflows set LIBNATS_TLS=ON for dev-env parity.
LIBNATS_TLS="${LIBNATS_TLS:-OFF}"

# Skip on cross-compile builds.  The multiarch CI uses *-cross
# compilers (gcc-mips64-cross, clang-arm32-qemu-cross, etc.) running
# inside an older Ubuntu 18.04 container with cmake 3.10, which
# can't build libnats >= 3.10 (CMake 3.13+ required).  Even if we
# upgraded cmake there, the resulting libnats would target the
# build host's architecture and link-fail against the cross-built
# OpenSIPS modules.  The Makefile gate in modules-contrib/nats/Makefile.nats
# handles the no-libnats case cleanly: NATS modules silently skip,
# the rest of the build proceeds.
case "${COMPILER:-}" in
    *cross*)
        echo "skipping libnats install: cross-compile build (COMPILER=${COMPILER})"
        exit 0
        ;;
esac

# Skip on uncommon architectures.  rtp.io's Docker buildx matrix runs
# native-in-QEMU on mips64le, ppc64le, s390x, riscv64, arm/v7 and 386,
# none of which match *cross* above.  libnats's CMake FindOpenSSL fails
# to locate libcrypto.so across multiarch sysroots there even with
# libssl-dev:<arch> installed, and these targets aren't a real NATS
# deployment surface.  The Makefile gate covers the absent-libnats case.
case "$(uname -m)" in
    x86_64|amd64|aarch64|arm64)
        ;;
    *)
        echo "skipping libnats install: uncommon arch $(uname -m)"
        exit 0
        ;;
esac

# Skip if a working install is already in place (cache hit, prior run,
# or a host-level libnats from apt).
if command -v pkg-config >/dev/null 2>&1 && \
   pkg-config --exists libnats 2>/dev/null; then
    installed=$(pkg-config --modversion libnats 2>/dev/null || echo unknown)
    echo "libnats already installed (version ${installed}); skipping build"
    exit 0
fi
if [ -f "${LIBNATS_PREFIX}/include/nats/nats.h" ] && \
   ls "${LIBNATS_PREFIX}/lib"/libnats.so* >/dev/null 2>&1; then
    echo "libnats present at ${LIBNATS_PREFIX}; skipping build"
    exit 0
fi

# Build deps.  cmake is not in apt_requirements.txt because it is
# only needed by this one optional dep -- install inline.
${SUDO} env DEBIAN_FRONTEND=noninteractive apt-get -y \
    --no-install-recommends install \
    cmake build-essential libssl-dev ca-certificates wget

tmp=$(mktemp -d)
cd "$tmp"

# archive/<ref> resolves branches, tags, and commit SHAs alike (the
# refs/heads/ form only accepts branches, which would break the pin).
wget -q "https://github.com/nats-io/nats.c/archive/${LIBNATS_VERSION}.tar.gz" \
    -O "nats.c-src.tar.gz"
tar xzf "nats.c-src.tar.gz"
cd nats.c-*/

mkdir build
cd build
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${LIBNATS_PREFIX}" \
    -DNATS_BUILD_STREAMING=OFF \
    -DNATS_BUILD_EXAMPLES=OFF \
    -DNATS_BUILD_USE_SODIUM=OFF \
    -DNATS_BUILD_WITH_TLS="${LIBNATS_TLS}"
# TLS defaults OFF on purpose: nats.c main's cmake does find_package(OpenSSL
# 1.1.1 REQUIRED) only under NATS_BUILD_WITH_TLS, and the OpenSIPS NATS modules
# link libnats at runtime via dlopen, so they only need it to build/link here.
# This avoids the missing-OPENSSL_CRYPTO_LIBRARY configure failure on slim/cross
# container images (e.g. debian_12-slim arm64). The sanitizer and TLS-backend
# workflows pass LIBNATS_TLS=ON.
make -j"$(nproc 2>/dev/null || echo 2)"
${SUDO} make install

# Refresh the dynamic linker cache so the freshly-installed
# libnats.so.<n> is reachable without a full env reset.
${SUDO} ldconfig 2>/dev/null || true

# Drop the build tree -- the cache only needs the install artefacts.
cd /
rm -rf "$tmp"

echo "libnats ${LIBNATS_VERSION} installed at ${LIBNATS_PREFIX}"
