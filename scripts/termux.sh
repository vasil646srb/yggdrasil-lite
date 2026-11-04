#!/data/data/com.termux/files/usr/bin/bash
# Build and run tcp_node natively in Termux (no cross-compilation needed).
#
#   bash scripts/termux.sh build          # install deps, build tcp_node (html build: dashboard)
#   bash scripts/termux.sh peers          # download the public peer list
#   bash scripts/termux.sh run            # start the node (dashboard on 127.0.0.1:1080)
#
# Extra flags can be passed to `run`, e.g.:
#   bash scripts/termux.sh run --listen 40001
#
# FEATURES picks the build variant (default: html, which serves the dashboard and /api/stats;
# the plain build has no dashboard). FEATURES=upstream-tls,html adds tls:// peers and LAN
# discovery (--lan-upstream); FEATURES= builds the plain TCP/UDP node.
set -euo pipefail

cd "$(dirname "$0")/.."
BIN=target/release/tcp_node
KEY="$HOME/ygg.key"
PEERS="$HOME/peers.json"
PEER_URL="https://publicpeers.neilalexander.dev/publicnodes.json"
FEATURES="${FEATURES-html}"

case "${1:-}" in
    build)
        pkg install -y rust git curl clang make
        cargo build --release --bin tcp_node ${FEATURES:+--features "$FEATURES"}
        echo "built: $BIN (features: ${FEATURES:-none})"
        ;;
    peers)
        curl -fsSL -o "$PEERS" "$PEER_URL"
        echo "saved: $PEERS"
        ;;
    run)
        shift
        [ -x "$BIN" ] || { echo "build first: bash scripts/termux.sh build" >&2; exit 1; }
        [ -f "$PEERS" ] || { echo "peer list missing: bash scripts/termux.sh peers" >&2; exit 1; }
        # Keep the CPU awake with the screen off if termux-wake-lock is available.
        command -v termux-wake-lock >/dev/null && termux-wake-lock || true
        exec "$BIN" --key "$KEY" --peers "$PEERS" --target 3 "$@"
        ;;
    *)
        echo "usage: bash scripts/termux.sh {build|peers|run [flags]}" >&2
        exit 2
        ;;
esac
