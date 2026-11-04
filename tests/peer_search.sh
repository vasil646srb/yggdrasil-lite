#!/usr/bin/env bash
#
# Automatic test of the peer search (src/search.rs) inside a real tcp_node, on loopback.
#
# Topology (transit hubs X and Y route between the nodes; A and C are plain leaves):
#
#      C --(proxy +DELAY ms each way)--> X --.
#      C --(proxy, +0 or +DELAY ms)----> Y --+--> A      C allows A and pings it every 10 s.
#
# C is the node under test, with one outbound slot and the allowed key of A. X is the only peer
# reachable when C starts, so C picks it; the slow link makes the round trip to A exceed the 150 ms
# limit. Then the proxy in front of Y comes up and the search must act:
#
#   helpful    Y's proxy adds no delay. C must replace X by Y, then judge the replacement
#              helpful, and make no further replacement.
#   unhelpful  Y's proxy is as slow as X's. C must replace once, judge it NOT helpful, and wait
#              before trying again instead of churning through peers.
#
# Needs: bash, python3, openssl. Builds the nodes unless NODE / HUB are set:
#   NODE   tcp_node under test (default: target/release/tcp_node, built without features)
#   HUB    tcp_node built with --features transit (default: target-transit/release/tcp_node)
# Usage: tests/peer_search.sh [helpful|unhelpful|all]   (default: all; about 3 minutes each)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DELAY_MS="${DELAY_MS:-100}"
SCENARIOS="${1:-all}"
[[ "$SCENARIOS" == all ]] && SCENARIOS="helpful unhelpful"

NODE="${NODE:-$ROOT/target/release/tcp_node}"
HUB="${HUB:-$ROOT/target-transit/release/tcp_node}"
if [[ ! -x "$NODE" ]]; then (cd "$ROOT" && cargo build --release --bin tcp_node) || exit 1; fi
if [[ ! -x "$HUB" ]]; then (cd "$ROOT" && CARGO_TARGET_DIR="$ROOT/target-transit" cargo build --release --bin tcp_node --features transit) || exit 1; fi

WORK="$(mktemp -d)"
PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null && wait "$p" 2>/dev/null; done
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; [[ -f "$WORK/C.log" ]] && { echo "--- C.log (tail)" >&2; tail -12 "$WORK/C.log" >&2; }; exit 1; }
ok()   { echo "  ok: $*"; }

# TCP proxy that delays every chunk by DELAY ms in both directions (order preserved).
cat > "$WORK/proxy.py" <<'PY'
import asyncio, sys
listen, target, delay = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]) / 1000.0
async def pump(r, w, loop):
    q = asyncio.Queue()
    async def sender():
        while True:
            t, data = await q.get()
            if data is None:
                break
            wait = t + delay - loop.time()
            if wait > 0:
                await asyncio.sleep(wait)
            w.write(data)
            await w.drain()
        w.close()
    task = asyncio.create_task(sender())
    try:
        while True:
            data = await r.read(65536)
            if not data:
                break
            q.put_nowait((loop.time(), data))
    except Exception:
        pass
    q.put_nowait((0, None))
    await task
async def handle(cr, cw):
    loop = asyncio.get_running_loop()
    try:
        tr, tw = await asyncio.open_connection("127.0.0.1", target)
    except Exception:
        cw.close(); return
    await asyncio.gather(pump(cr, tw, loop), pump(tr, cw, loop), return_exceptions=True)
async def main():
    srv = await asyncio.start_server(handle, "127.0.0.1", listen)
    async with srv:
        await srv.serve_forever()
asyncio.run(main())
PY

pub() { # BIN KEYFILE -> public key
    timeout 2 "$1" --key "$2" --no-public 2>&1 | awk '/^public key:/{print $3; exit}'
}
addr() {
    timeout 2 "$1" --key "$2" --no-public 2>&1 | awk '/^device address:/{print $3; exit}'
}
wait_log() { # FILE REGEX SECONDS -> 0 if the pattern shows up in time
    local f="$1" re="$2" max="$3" t=0
    while (( t < max )); do grep -Eq "$re" "$f" 2>/dev/null && return 0; sleep 1; t=$((t+1)); done
    return 1
}
count() { grep -Ec "$2" "$1" 2>/dev/null || true; }

run_scenario() {
    local name="$1" y_delay
    case "$name" in helpful) y_delay=0 ;; unhelpful) y_delay="$DELAY_MS" ;; *) fail "unknown scenario $name" ;; esac
    echo "== scenario: $name (X link +${DELAY_MS} ms each way, Y link +${y_delay} ms)"
    cd "$WORK" && rm -f ./*.log ./*.json ./k?

    for n in c a x y; do openssl rand -hex 32 > "k$n"; chmod 600 "k$n"; done
    local CPUB APUB XPUB YPUB AADDR
    CPUB=$(pub "$NODE" kc); APUB=$(pub "$NODE" ka); XPUB=$(pub "$HUB" kx); YPUB=$(pub "$HUB" ky)
    AADDR=$(addr "$NODE" ka)
    [[ ${#CPUB} = 64 && ${#APUB} = 64 && ${#XPUB} = 64 && ${#YPUB} = 64 ]] || fail "could not read public keys"

    # Hubs listen; A dials both hubs directly, C only through the proxies.
    "$HUB" --key kx --no-public --listen 40701 > X.log 2>&1 & PIDS+=($!)
    "$HUB" --key ky --no-public --listen 40702 > Y.log 2>&1 & PIDS+=($!)
    echo "[\"tcp://127.0.0.1:40701?key=$XPUB\", \"tcp://127.0.0.1:40702?key=$YPUB\"]" > peersA.json
    "$NODE" --key ka --no-public --peers peersA.json --target 2 --allow "$CPUB" > A.log 2>&1 & PIDS+=($!)
    python3 -I proxy.py 41001 40701 "$DELAY_MS" & local PX=$!; PIDS+=($PX)
    sleep 2
    # C knows both proxies, but only X's is up, so X is the peer it picks.
    echo "[\"tcp://127.0.0.1:41001?key=$XPUB\", \"tcp://127.0.0.1:41002?key=$YPUB\"]" > peersC.json
    "$NODE" --key kc --no-public --peers peersC.json --target 1 --allow "$APUB" > C.log 2>&1 & local CPID=$!; PIDS+=($CPID)
    # C decides within a second or two (the probe of an unreachable candidate fails at once), so
    # by the time Y's proxy comes up it already holds X and the first metric is still ~20 s away.
    sleep 4
    python3 -I proxy.py 41002 40702 "$y_delay" & PIDS+=($!)
    local t0=$SECONDS
    wait_log C.log 'peers: 1  sockets: 1' 30 || fail "C never linked to X"
    grep -Eq '^  out tcp://127.0.0.1:41001' C.log || fail "C did not pick X first"

    # 1. The slow client path triggers one replacement of the peer X.
    wait_log C.log 'клиент [0-9]+ ms > 150 ms: заменён пир' 150 || fail "no replacement although the path to the allowed key is slow"
    local swap_line swap_s=$((SECONDS - t0))
    swap_line=$(grep -E 'клиент [0-9]+ ms > 150 ms: заменён пир' C.log | head -1)
    ok "replacement after ${swap_s}s: $swap_line"
    [[ "$swap_line" == *"${XPUB:0:8}"* ]] || fail "the replaced peer is not X (${XPUB:0:8})"
    ok "the slow peer X was the one replaced"

    # 2. The replacement is judged (about 60 s later) ...
    wait_log C.log 'замена (не )?помогла' 150 || fail "the replacement was never judged"
    local verdict; verdict=$(grep -E 'замена (не )?помогла' C.log | head -1)
    ok "verdict after $((SECONDS - t0))s: $verdict"
    case "$name" in
    helpful)
        [[ "$verdict" == *"замена помогла"* ]] || fail "expected a helpful verdict"
        local after; after=$(sed -E 's/.*-> ([0-9]+) ms.*/\1/' <<< "$verdict")
        (( after < 150 )) || fail "path still slow after a helpful replacement: ${after} ms"
        ok "path to the allowed key is now ${after} ms (limit 150)"
        grep -Eq '^  out tcp://127.0.0.1:41002' C.log || fail "C is not connected through Y's proxy"
        ok "C is connected through Y"
        ;;
    unhelpful)
        [[ "$verdict" == *"замена не помогла"* ]] || fail "expected an unhelpful verdict"
        [[ "$verdict" == *"60 с"* ]] || fail "the wait did not double to 60 s: $verdict"
        ok "backoff announced: next replacement not before 60 s"
        ;;
    esac

    # 3. No churn: still exactly one replacement shortly after the verdict.
    sleep 40
    local swaps; swaps=$(count C.log 'заменён пир')
    [[ "$swaps" == 1 ]] || fail "expected exactly 1 replacement, got $swaps"
    ok "exactly one replacement, no churn"
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; done; PIDS=()
    echo "== $name: passed ($((SECONDS - t0))s)"
}

for s in $SCENARIOS; do run_scenario "$s"; done
echo "peer search: all scenarios passed"
