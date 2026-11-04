#!/usr/bin/env bash
# Build the four tcp_node variants.
#
#   scripts/build-variants.sh [--target TRIPLE] [--out DIR]
#
# Variants (all of them forward TCP and UDP over Yggdrasil):
#   tcp       TCP peers only: no TLS, no LAN peer discovery, no HTML server
#   tls       tcp + tls:// peers + yggdrasil-go LAN peer discovery   (--features upstream-tls)
#   html      tcp + HTML server on port 1080                         (--features html)
#   tls-html  tls + HTML server on port 1080                         (--features upstream-tls,html)
#
# Output: DIR/tcp_node-<variant> (default DIR: dist/<target or host>).
#
# Targets without a prebuilt standard library (mips*/mipsel musl) are built with nightly and
# -Z build-std=std,panic_abort. The tls variants compile a little C (ring), so point cc at the
# target's compiler, for example:
#   CC_mipsel_unknown_linux_musl=~/mipsel-linux-muslsf-cross/bin/mipsel-linux-muslsf-gcc \
#   AR_mipsel_unknown_linux_musl=~/mipsel-linux-muslsf-cross/bin/mipsel-linux-muslsf-ar \
#   scripts/build-variants.sh --target mipsel-unknown-linux-musl
set -euo pipefail
cd "$(dirname "$0")/.."

target=""
out=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) target="${2:?--target needs a triple}"; shift 2 ;;
        --out)    out="${2:?--out needs a directory}"; shift 2 ;;
        -h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
out="${out:-dist/${target:-host}}"
mkdir -p "$out"

cargo_cmd=(cargo)
extra=()
tdir="target"
if [[ -n "$target" ]]; then
    extra+=(--target "$target")
    tdir="target/$target"
    case "$target" in
        mips-*|mipsel-*|mips64*)
            cargo_cmd=(cargo +nightly)
            extra+=(-Z build-std=std,panic_abort)
            ;;
    esac
fi

build() {
    local name="$1" features="$2"
    echo "==> tcp_node-$name${features:+ (features: $features)}"
    "${cargo_cmd[@]}" build --release --bin tcp_node ${features:+--features "$features"} "${extra[@]}"
    cp "$tdir/release/tcp_node" "$out/tcp_node-$name"
}

build tcp ""
build tls "upstream-tls"
build html "html"
build tls-html "upstream-tls,html"

echo
ls -l "$out"/tcp_node-* | awk '{printf "%9d  %s\n", $5, $9}'
