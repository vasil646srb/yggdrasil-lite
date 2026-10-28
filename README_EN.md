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
leaf node, measures latency to candidates and replaces slow peers itself,
serves status over HTTP and forwards TCP and UDP ports over Yggdrasil. It
only depends on `rand` and `heapless` — no TLS, no C libraries, a compact
static binary.

### Flags

| Flag | Description |
|------|-------------|
| `--key FILE` | Key file (64 hex). Created on first run with mode 600; defines the node address — keep it secret |
| `--peers FILE` | JSON list of public peers (`publicnodes.json`) |
| `--target N` | Number of outgoing slots (1..32, default 3) |
| `--allow KEY` | Allowed public key (repeatable). Datagrams from other keys are dropped |
| `--api ADDR` | HTTP status server (dashboard + JSON). Listens on loopback only |
| `--html FILE` | Custom HTML page for the node page |
| `--forward PORTS` | TCP port forwarding (up to 16) |
| `--forward-udp PORTS` | UDP port forwarding (up to 16) |
| `--listen PORT` | Accept incoming TCP peers (up to 16 on top of `--target`); the port is announced in LAN beacons |
| `--lan` | Find peers on the local network via multicast beacons |
| `--quality-interval SECS` | Network quality check interval (default 300, minimum 10) |
| `--ping IPV6` | Measure RTT to a node |
| `--send IPV6 MSG` | Send a single datagram |
| `--send-udp IPV6 PORT MSG` | Test UDP datagram every 5 s |

### Basic setup (Termux)

```sh
pkg install rust git curl
bash scripts/termux.sh build     # builds tcp_node
bash scripts/termux.sh peers     # downloads the public peers list to ~/peers.json
bash scripts/termux.sh run       # runs the node with the dashboard on 127.0.0.1:8080
bash scripts/termux.sh run --lan --listen 40001   # extra flags are passed as-is
```

The same manually:

```sh
git clone https://github.com/vasil646srb/yggdrasil-lite && cd yggdrasil-lite
cargo build --release --bin tcp_node

curl -fsSL -o ~/peers.json https://publicpeers.neilalexander.dev/publicnodes.json
./target/release/tcp_node --key ~/ygg.key --peers ~/peers.json \
    --target 3 --api 127.0.0.1:8080
```

Dashboard: `http://127.0.0.1:8080/` · statistics: `curl http://127.0.0.1:8080/api/stats`.
The API listens on 127.0.0.1 only and has no authentication — do not expose it
on 0.0.0.0.

The key file is created with mode `600`; if it happens to be readable by other
users, the node prints a warning. To keep the node alive with the screen off:
`termux-wake-lock` and disable battery optimization for Termux.

### Local network and incoming peers

`--lan` enables neighbor discovery on the local network: the node sends
multicast beacons (magic `YGGL`) to `239.255.42.7:9001` every 3 s and adds the
found nodes to the candidate list. `--listen PORT` opens the node for incoming
TCP peers and announces this port in the beacons — so two nodes on the same
network find each other without public peers. At most 16 incoming connections
are accepted on top of `--target`.

### Automatic peer selection and slow-peer replacement

The node selects peers in two stages so slots are not wasted on unreachable
addresses:

1. **Probe before dialing.** All candidates from `--peers` (and those found
   via `--lan`) are checked with a plain TCP connect, in parallel with 8
   workers, 2 s timeout per address. The result goes into a moving average
   (`record_probe`); an unreachable candidate gets a 5000 ms penalty and
   moves to the end of the queue. While the first round is running, dialing
   is held back (`set_dial_enabled(false)`), but at most for 60 s. The round
   repeats every 600 s.
2. **Replacement by quality.** Every `--quality-interval` (and every 30 s
   while the root is slow) the node measures RTT with echo requests: to every
   connected peer and to the global root every 10 s, to `--allow` client
   addresses every 10 s. If the RTT to the root is > **200 ms** or to an
   allowed client is > **150 ms**, the slowest outgoing peer is disconnected
   (at most once per 30 s) and replaced with the best candidate; the
   disconnected peer is not re-dialed for 15 minutes.

### Node page on port 80 and API

The node answers ICMPv6 echo from allowed keys and serves a status page on the
overlay TCP port 80 (unless port 80 is taken by a forwarded port). Open it
from a node whose key is in `--allow`, via a yggstack SOCKS proxy:

```sh
curl -x socks5h://127.0.0.1:1080 http://[<device-address>]/
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

### Limitations of the built-in TCP

For interactive sessions (SSH), not bulk transfers: one connection per client
port, no congestion control, no TIME_WAIT; when port 80 is forwarded, the
node's status page is disabled.

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
