#!/usr/bin/env bash
# Build yggdrasil-lite for a target profile.
#
#   scripts/build.sh <profile>
#
# Profiles:
#   host               std build + examples, native host
#   transit            std build with the transit (router) feature
#   nostd              no_std library only (for bare-metal / embedded targets)
#   android-arm64      Android arm64-v8a via cargo-ndk        (needs ANDROID_NDK_HOME)
#   openwrt-aarch64    OpenWrt aarch64 (musl)                 (needs OPENWRT_TOOLCHAIN_BIN)
#   openwrt-mipsel     OpenWrt mipsel (musl)                  (needs OPENWRT_TOOLCHAIN_BIN)
#   openwrt-x86_64     OpenWrt x86_64 (musl)                  (needs OPENWRT_TOOLCHAIN_BIN)
#
# OPENWRT_TOOLCHAIN_BIN is the bin/ directory of the OpenWrt SDK toolchain
# (e.g. .../toolchain-aarch64_generic_gcc-*/bin). The linker name is derived
# from the target triple: aarch64-openwrt-linux-musl-gcc, mipsel-openwrt-linux-musl-gcc,
# x86_64-openwrt-linux-musl-gcc.
#
# Output: target/<triple>/release/examples/tcp_node (or target/release/ for host builds).
set -euo pipefail

cd "$(dirname "$0")/.."

profile="${1:-}"
die() { echo "error: $*" >&2; exit 1; }

openwrt_build() {
    local triple="$1" linker_prefix="$2"
    [[ -n "${OPENWRT_TOOLCHAIN_BIN:-}" ]] || die "set OPENWRT_TOOLCHAIN_BIN to the SDK toolchain bin/ directory"
    local linker="$OPENWRT_TOOLCHAIN_BIN/${linker_prefix}-openwrt-linux-musl-gcc"
    [[ -x "$linker" ]] || die "linker not found: $linker"
    local env_var="CARGO_TARGET_$(echo "$triple" | tr 'a-z-' 'A-Z_')_LINKER"
    rustup target add "$triple"
    env "$env_var=$linker" cargo build --release --target "$triple" --example tcp_node
    "$OPENWRT_TOOLCHAIN_BIN/${linker_prefix}-openwrt-linux-musl-strip" \
        "target/$triple/release/examples/tcp_node" 2>/dev/null || true
    echo "built: target/$triple/release/examples/tcp_node"
}

case "$profile" in
    host)
        cargo build --release
        cargo build --release --examples
        ;;
    transit)
        cargo build --release --features transit
        ;;
    nostd)
        cargo build --release --lib --no-default-features
        ;;
    android-arm64)
        [[ -n "${ANDROID_NDK_HOME:-}" ]] || die "set ANDROID_NDK_HOME"
        command -v cargo-ndk >/dev/null || die "install with: cargo install cargo-ndk"
        rustup target add aarch64-linux-android
        cargo ndk -t arm64-v8a build --release --lib
        ;;
    openwrt-aarch64) openwrt_build aarch64-unknown-linux-musl aarch64 ;;
    openwrt-mipsel)  openwrt_build mipsel-unknown-linux-musl mipsel ;;
    openwrt-x86_64)  openwrt_build x86_64-unknown-linux-musl x86_64 ;;
    *)
        die "unknown profile '${profile}'. Use one of: host transit nostd android-arm64 openwrt-aarch64 openwrt-mipsel openwrt-x86_64"
        ;;
esac
