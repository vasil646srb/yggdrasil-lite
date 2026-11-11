# yggdrasil-lite

## Fork

This repository is a personal fork of
[cleverfox/yggdrasil-lite](https://github.com/cleverfox/yggdrasil-lite)
(the original project; MPL-2.0). It may contain local changes, experiments
and fixes that are not part of the upstream.

- Upstream: https://github.com/cleverfox/yggdrasil-lite.git
- Origin:   https://github.com/vasil646srb/yggdrasil-lite.git

---

## tcp_node — a ready-made node for Unix hosts

`tcp_node` (`src/bin/tcp_node.rs`) is an executable yggdrasil-lite node for
**Termux, Linux and OpenWrt**. It connects to public TCP peers, works as a
leaf node, measures latency to candidates and replaces slow peers itself
and forwards TCP and UDP ports over Yggdrasil. The plain build depends only
on `rand`, `heapless` and `libc` — no TLS, no C libraries, a compact static
binary. TLS with LAN peer discovery and the HTML status server are optional
build variants (see below).

### Build variants

Four variants are built from two optional features. Every variant forwards TCP
and UDP (`--forward`, `--connect`, `--forward-udp`):

| Variant | Features | Adds |
|---------|----------|------|
| `tcp_node-tcp` | none | Nothing: TCP peers only, no TLS, no LAN discovery, no HTML server. |
| `tcp_node-tls` | `upstream-tls` | `tls://` peers and yggdrasil-go LAN peer discovery (`--lan-upstream`). |
| `tcp_node-html` | `html` | HTML server on port 1080 (dashboard + JSON API, overlay status page). |
| `tcp_node-tls-html` | `upstream-tls,html` | Both. |

```sh
scripts/build-variants.sh                                    # all four, into dist/host/
scripts/build-variants.sh --target mipsel-unknown-linux-musl   # router: nightly + build-std
```

Sizes on x86_64: 0.95 MB, 2.1 MB, 0.98 MB, 2.1 MB. A flag of a feature that is
not built in is refused at start. The TLS variants use rustls (no OpenSSL).

### Flags

| Flag | Description |
|------|-------------|
| `--key FILE` | Key file (64 hex). Created on first run with mode 600; defines the node address — keep it secret. Default: `./ygg.key` if present, else `~/ygg.key`. With no options at all the node downloads the public peer list in the background and connects |
| `--peers FILE` | JSON list of public peers (`publicnodes.json`) |
| `--target N` | Number of outgoing slots (1..32, default 3) |
| `--allow KEY` | Allowed public key (repeatable). Datagrams from other keys are dropped |
| `--api ADDR\|off` | `html` build. HTTP status server (dashboard + JSON), default `127.0.0.1:<html-port>`. Loopback only |
| `--html FILE` | `html` build. Custom HTML page for the node page |
| `--html-port PORT` | `html` build. Overlay port of the page and port of the local dashboard (default 1080) |
| `--forward PORTS` | TCP port forwarding (up to 16) |
| `--open PORTS` | Forwarded ports (and ping) open to any key, not only `--allow` |
| `--rtt-limit MS` | Replace peers while the latency to `--allow` keys or `--connect` servers exceeds this (default 150) |
| `--connect LPORT:[ADDR]:PORT` | Carry connections to 127.0.0.1:LPORT to `[ADDR]:PORT` over Yggdrasil |
| `--forward-udp PORTS` | UDP port forwarding (up to 16) |
| `--no-public` | Do not download the public peer list; use `--peers` and LAN discovery only |
| `--listen PORT` | Accept incoming TCP peers (up to 16 on top of `--target`) |
| `--lan-upstream` | `upstream-tls` build. Find yggdrasil-go peers on the LAN from their IPv6 link-local beacons (`ff02::114`, port 9001) and dial them over TLS |
| `--lan-target N` | `upstream-tls` build. Outbound slots reserved for LAN peers (default: `--target`) |
| `--quality-interval SECS` | Network quality check interval (default 300, minimum 10) |
| `--ping IPV6` | Measure RTT to a node |
| `--send IPV6 MSG` | Send a single datagram |
| `--send-udp IPV6 PORT MSG` | Test UDP datagram every 5 s |

### Basic setup (Termux)

```sh
pkg install rust git curl
bash scripts/termux.sh build     # builds tcp_node with the html feature (dashboard)
bash scripts/termux.sh peers     # downloads the public peers list to ~/peers.json
bash scripts/termux.sh run       # runs the node with the dashboard on 127.0.0.1:1080
bash scripts/termux.sh run --listen 40001   # extra flags are passed as-is
FEATURES=upstream-tls,html bash scripts/termux.sh build   # tls:// peers and LAN discovery too
```

The same manually:

```sh
git clone https://github.com/vasil646srb/yggdrasil-lite && cd yggdrasil-lite
cargo build --release --bin tcp_node --features html

curl -fsSL -o ~/peers.json https://publicpeers.neilalexander.dev/publicnodes.json
./target/release/tcp_node --key ~/ygg.key --peers ~/peers.json \
    --target 3
```

Dashboard (`html` build): `http://127.0.0.1:1080/` · statistics:
`curl http://127.0.0.1:1080/api/stats`. The API listens on 127.0.0.1 only and has no
authentication — do not expose it on 0.0.0.0. The plain build has no dashboard.

The key file is created with mode `600`; if it happens to be readable by other
users, the node prints a warning. To keep the node alive with the screen off:
`termux-wake-lock` and disable battery optimization for Termux.

### Local network and incoming peers

`--listen PORT` opens the node for incoming plain-TCP peers (at most 16 on top of
`--target`), so two nodes can be linked directly without public peers.

In an `upstream-tls` build `--lan-upstream` finds **yggdrasil-go** nodes on the local
network: it listens (never sends) for their multicast beacons on `ff02::114`, port 9001,
shares that port with a yggdrasil-go running on the same host, and dials the senders over
TLS on the interface the beacon came from. See the full description in the README
(`README.md`, "LAN peers of yggdrasil-go").

### Automatic peer selection and slow-peer replacement

The node selects peers in two stages so slots are not wasted on unreachable
addresses:

1. **Probe before dialing.** All candidates from `--peers` (and those found
   by LAN discovery) are checked with a plain TCP connect, in parallel with 8
   workers, 2 s timeout per address. The result goes into a moving average
   (`record_probe`); an unreachable candidate gets a 5000 ms penalty and
   moves to the end of the queue. While the first round is running, dialing
   is held back (`set_dial_enabled(false)`), but at most for 60 s. The round
   repeats every 600 s.
2. **Replacement by quality.** The node measures RTT with echo requests: to
   every connected peer and to every `--allow` client address every 10 s, and
   to the global root every `--quality-interval` (every 30 s while the root is
   the slow metric). **Allowed keys have priority:** while at least one of
   them has a fresh measurement, the worst smoothed RTT among them decides and
   the root is ignored; the root decides only when no allowed key answers (a
   silent client may just be offline, so it is not treated as slow). The first echo of a run
   is thrown away (it pays for path discovery and the session handshake and
   can take seconds), a value counts after a second one, and it expires after 45 s. If the deciding RTT is above its limit (**150 ms**
   for allowed clients, **200 ms** for the root), the outgoing peer with the
   highest latency is disconnected and replaced with the best candidate; it
   is not re-dialed for 15 minutes, and an allowed key that is connected
   directly is never the one dropped. After 60 s the replacement is judged: if
   the deciding RTT did not fall by at least 10%, the next replacement waits
   twice as long (30 s, 60 s, ... up to 10 min), so a client that is simply
   far away does not make the node churn through every public peer. The
   decision logic lives in `src/search.rs` (unit tests); `tests/peer_search.sh` runs it
   end to end on loopback with a delayed link (helpful and unhelpful replacement).

### Node page on port 1080 and API (`html` build)

The node always answers ICMPv6 echo from allowed keys. The `html` build also serves a
status page on the overlay TCP port 1080 (`--html-port`; unless that port is taken by a
forwarded port) and a local dashboard with `/api/stats` on `127.0.0.1:1080`. Open the
overlay page from a node whose key is in `--allow`, via a yggstack SOCKS proxy:

```sh
curl -x socks5h://127.0.0.1:1080 http://[<device-address>]:1080/
```

The page refreshes every second and shows:

- for each `--target` slot: peer address, RTT, root status ("main root" /
  "foreign root" / "waiting"), connection time;
- root summary: measured RTT and the list of keys grouped by root;
- a table of allowed clients (`--allow`) with their addresses and RTT;
- a log of recent peer replacements and a **speed test** button.

The speed test requests `GET /speed` — the node replies with 256 KB of zeroes
(`Content-Type: application/octet-stream`), the page computes Mbit/s and
prints volume and duration. Useful as a quick check of forwarding throughput.

## TCP port forwarding (SSH to a router or phone)

`tcp_node --forward` makes TCP ports of this host reachable over Yggdrasil.
Ports are set at startup. Only keys from `--allow` can connect, and only the
listed ports are open.

### `--forward` format

`--forward` takes a comma-separated list of ports (up to 16); the flag can be
repeated. Two element formats are supported:

- `PORT` — the overlay port equals the local one. Example: `--forward 22`
  opens port 22 in the overlay and maps it to 127.0.0.1:22;
- `OVERLAY:LOCAL` — explicit mapping: overlay port `OVERLAY` points to local
  port `LOCAL`. Example: `--forward 2222:22` opens overlay port 2222 →
  127.0.0.1:22.

Both formats can be mixed in one list:

```sh
tcp_node --key ~/ygg.key --peers ~/peers.json \
    --allow <client-public-key> --forward 22,8080,9000:9001
```

This opens:

- `22` — overlay 22 → 127.0.0.1:22 (matching number);
- `8080` — overlay 8080 → 127.0.0.1:8080 (matching number);
- `9000:9001` — overlay 9000 → 127.0.0.1:9001 (explicit mapping).

A local connection that cannot be opened (timeout 2 s) is reset towards the
client. The client must run a full Yggdrasil stack (yggdrasil-ng with TUN or
yggstack with a SOCKS proxy) and use an allowed key. With yggstack's SOCKS
proxy on 127.0.0.1:1080:

```sh
ssh -o ProxyCommand="nc -X 5 -x 127.0.0.1:1080 %h %p" -p 22 root@<device-address>
```

### The built-in TCP

`src/tcp_stack.rs` is a full TCP: RFC 9293 states with TIME-WAIT and half-close,
MSS and window scaling, flow control, delayed ACKs, out-of-order reassembly,
RFC 6298 RTO, NewReno congestion control, keepalive, RFC 5961 checks. No SACK
or timestamps. When the HTML port is forwarded, the node's status page is disabled.

## UDP port forwarding (`--forward-udp`)

`--forward-udp` follows the same rules as `--forward`: the same `PORT[:LOCAL]`
format, a list of up to 16 ports, the same restrictions on `--allow` keys.
The difference is the transport: the node accepts UDP datagrams from allowed
clients (IPv6 + UDP, the checksum is mandatory and verified) and relays them
to the local service on 127.0.0.1, returning replies over the overlay.

```sh
# overlay UDP 5353 → local 53, overlay 51820 → local 51820
# (TCP part of the example is omitted for brevity)
tcp_node --key ~/ygg.key --peers ~/peers.json \
    --allow <client-public-key> --forward-udp 5353:53,51820
```

Sessions are tracked by the triple (client key, client port, overlay port):

- up to **64** concurrent sessions;
- a session is removed after **60 s** without traffic;
- the maximum payload of one datagram is **1232 bytes** (the minimum IPv6 MTU
  1280 minus IPv6 and UDP headers); larger datagrams are dropped;
- a new client beyond the session limit is not served until a slot frees up.

To check the channel there is `--send-udp IPV6 PORT MSG`: the node sends this
datagram to the overlay address every 5 s and prints the replies.

## Network checks

```sh
tcp_node --key ~/ygg.key --peers ~/peers.json --ping <ipv6>            # RTT
tcp_node --key ~/ygg.key --peers ~/peers.json --send <ipv6> hello      # datagram
tcp_node --key ~/ygg.key --peers ~/peers.json \
    --send-udp <ipv6> 5353 hello                                       # UDP every 5 s
```

## Building for a router (OpenWrt)

Build for the router's CPU, preferably musl-static: the binary needs no libc
on the device. Check the target triple with `uname -m` on the router.

```sh
# example: aarch64 router (adjust for your device)
rustup target add aarch64-unknown-linux-musl
cargo build --release --bin tcp_node --target aarch64-unknown-linux-musl
scp target/aarch64-unknown-linux-musl/release/tcp_node root@192.168.1.1:/usr/bin/
```

`scripts/build.sh` does the same, picking the OpenWrt toolchain via
`OPENWRT_TOOLCHAIN_BIN`. `tcp_node` only depends on `rand` and `heapless`
(no TLS, no C libraries), so cross-compilation needs no extra system
libraries, and release builds are stripped. Installing the service —
`openwrt/tcp_node.init` (see comments in the file).

## Tests

```sh
cargo test --features transit                       # library, TCP stack, peer search, transit
cargo test --features upstream-tls,html --bin tcp_node # also the TLS/LAN and HTML parts
tests/peer_search.sh                                # peer search end to end on loopback (~4 min)
```

`tests/peer_search.sh` starts real nodes on loopback (two transit hubs, a leaf with the allowed
key, and the node under test), delays the first peer's link by 100 ms each way and checks that the
node replaces that peer once, judges the replacement (helpful when the other peer is fast, not
helpful with a backoff when it is just as slow), and does not churn.
