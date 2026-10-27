# yggdrasil-lite

Minimal [Yggdrasil](https://yggdrasil-network.github.io/) client for embedded devices.

Implements the Yggdrasil/Ironwood protocol subset needed to operate as a **leaf node**: connect to peers, join the spanning tree, discover paths via bloom filters, and exchange end-to-end encrypted packets with any node in the network. No TUN interface, no admin API.

By default there is no transit routing. The optional `transit` Cargo feature turns the node into a router: it merges peer bloom filters into its advertisements, forwards path discovery, and forwards traffic between peers. Individual peers can be excluded with `set_peer_no_redistribute(peer_id, true)` — their keys are never redistributed to other peers (no bloom merge, no lookup forwarding toward them), while the marked peer can still use the node as an uplink. Marking **all** peers makes a multi-homed stub that never carries third-party traffic.

Designed for `no_std` + `alloc` environments (ESP32 with Embassy), but also builds with `std` for desktop testing.

## Features

- Spanning tree participation (announce, SigReq/SigRes, parent selection)
- Bloom filter routing (advertise own key, respond to PathLookup)
- Path discovery (PathLookup / PathNotify / PathBroken)
- Optional transit routing (`transit` feature) with per-peer `no_redistribute` policy
- End-to-end encrypted sessions (XSalsa20-Poly1305 with key ratcheting)
- Metadata handshake compatible with yggdrasil-go and yggdrasil-ng
- IPv6 address derivation from Ed25519 public key (`200::/7`)
- Poll-based, synchronous API — no async runtime dependency
- ~2500 lines of Rust, 73 unit tests

## Architecture

```
Application
    │
    ▼
YggdrasilLite          ◄── poll-based node coordinator
├── tree.rs            ◄── spanning tree CRDT (parent selection, announces)
├── bloom.rs           ◄── bloom filter exchange (key advertisement)
├── pathfinder.rs      ◄── path cache (PathLookup/PathNotify/PathBroken)
├── session.rs         ◄── encrypted sessions (Init/Ack/Traffic + ratcheting)
├── wire.rs            ◄── frame encoding/decoding (uvarint, TLV, paths)
├── meta.rs            ◄── metadata handshake (version, key, BLAKE2b sig)
├── crypto.rs          ◄── Ed25519, X25519, XSalsa20-Poly1305
├── address.rs         ◄── IPv6 address derivation from ed25519 key
└── peer.rs            ◄── per-peer connection state
```

## Usage

```rust
use yggdrasil_lite::{YggdrasilLite, LiteConfig, NodeEvent};

// Create a node with an Ed25519 seed
let config = LiteConfig::new(my_ed25519_seed);
let mut node = YggdrasilLite::new(config);

// After TCP+TLS connection and metadata handshake with a peer:
let peer_id = node.add_peer(peer_public_key, 0);
node.mark_handshake_done(peer_id);

// Main loop
loop {
    // Feed incoming data from the peer's TLS stream
    let events = node.handle_peer_data(peer_id, &incoming_bytes, now_ms, &mut rng);
    handle_events(&events, &mut tls_writer);

    // Periodic maintenance (~every 100ms)
    let events = node.poll(now_ms, &mut rng);
    handle_events(&events, &mut tls_writer);

    // Send encrypted data to a remote Yggdrasil node
    let events = node.send(&dest_public_key, b"hello", now_ms, &mut rng);
    handle_events(&events, &mut tls_writer);
}

fn handle_events(events: &[NodeEvent], writer: &mut impl std::io::Write) {
    for event in events {
        match event {
            NodeEvent::SendToPeer { data, .. } => {
                writer.write_all(data).unwrap();
            }
            NodeEvent::Deliver { source, data } => {
                // Decrypted application data from a remote node
                println!("Received {} bytes from {:?}", data.len(), &source[..4]);
            }
        }
    }
}
```

## API Overview

### `LiteConfig`

| Field | Type | Description |
|-------|------|-------------|
| `private_key` | `[u8; 32]` | Ed25519 signing key seed |
| `password` | `Option<Vec<u8>>` | Peering password (if peers require one) |
| `max_sessions` | `usize` | Max concurrent encrypted sessions (default: 16) |
| `max_paths` | `usize` | Max cached path entries (default: 16) |

### `YggdrasilLite`

| Method | Description |
|--------|-------------|
| `new(config)` | Create a new node |
| `public_key()` | Our Ed25519 public key |
| `address()` | Our Yggdrasil IPv6 address (`200::/7`) |
| `subnet()` | Our `/64` subnet (`300::/7`) |
| `coords()` | Current tree coordinates |
| `add_peer(key, priority)` | Register a peer after TLS+metadata handshake |
| `remove_peer(peer_id)` | Remove a disconnected peer |
| `mark_handshake_done(peer_id)` | Mark peer as fully connected |
| `handle_peer_data(peer_id, data, now_ms, rng)` | Process incoming wire data from a peer |
| `poll(now_ms, rng)` | Periodic maintenance (tree, bloom, keepalive, cleanup) |
| `send(dest_key, data, now_ms, rng)` | Send encrypted data to a destination |

### `NodeEvent`

| Variant | Description |
|---------|-------------|
| `SendToPeer { peer_id, data }` | Write `data` to the peer's TLS stream |
| `Deliver { source, data }` | Decrypted application data from `source` |

### Metadata Handshake

The caller is responsible for TCP+TLS connection setup. After TLS, exchange metadata using `meta::Metadata`:

```rust
use yggdrasil_lite::meta::Metadata;

// Encode and send our metadata
let meta = Metadata::new(node.public_key().clone(), 0);
let encoded = meta.encode(&signing_key, password);
tls_writer.write_all(&encoded)?;

// Read and decode peer metadata
let (peer_meta, consumed) = Metadata::decode(&received_bytes, password)?;
assert!(peer_meta.check()); // verify protocol compatibility
```

## Transport

yggdrasil-lite is transport-agnostic. It operates on framed byte streams — the caller provides TCP+TLS and feeds raw bytes in/out. This makes it usable with:

- **Desktop**: `std::net::TcpStream` + `rustls`
- **Embassy**: `embassy-net::TcpSocket` + `embedded-tls`
- **Any other runtime** that provides a byte stream

## Examples

### Desktop: `lite_node`

A complete desktop integration test node with TLS, metadata handshake, and a userspace TCP/HTTP server running on the Yggdrasil overlay.

```sh
# 1. Start a yggdrasil-ng node
cargo run -p yggdrasil -- --config yggdrasil.conf --loglevel debug
# Note the TLS listen address (e.g. tls://0.0.0.0:2020)

# 2. Run the lite node
cargo run --example lite_node -p yggdrasil-lite -- 127.0.0.1:2020

# 3. Test from the yggdrasil-ng host
curl -6 --max-time 30 "http://[<lite_ipv6>]:80/hello"
```

### Desktop: `tun` bridge (Linux / macOS)

Bridges the overlay to a real kernel **TUN interface**, so the host's own stack
can reach the mesh (`ping6`, `curl -6`, `ssh`, …) — not just a single userspace
HTTP endpoint. Needs root to create the device and add a route.

```sh
# Connect to a yggdrasil-ng / yggstack TLS peer and bring up the bridge
sudo cargo run --release -p yggdrasil-tun -- 127.0.0.1:2020

# From this host, reach any node on the mesh:
ping6 <a-yggdrasil-address>
```

See [`examples/tun/`](examples/tun/) for details. It uses two small APIs for
address-initiated traffic: `YggdrasilLite::lookup()` (start path discovery from
a partial key derived from an IPv6 address) and `YggdrasilLite::resolve()`
(map a learned address back to a full public key).

### ESP32: Yggdrasil TCP-UART Bridge

A firmware for ESP32 (C6 and and 32D) that bridges TCP connections over the Yggdrasil mesh to a hardware UART. The device connects to WiFi, establishes a TLS connection to Yggdrasil peers, and listens for TCP and ICMPv6 on its overlay IPv6 address. Target chip is selected via Cargo features.

See [`examples/esp32/`](examples/esp32/) for the full project. Quick start:

```sh
cd examples/esp32

# Edit .cargo/config.toml with your WiFi and peer settings
# Then build and flash:

# ESP32-C6 (RISC-V)
cargo run --release --target riscv32imac-unknown-none-elf --features esp32c6

# ESP32 (Xtensa) — requires esp toolchain
cargo +esp run --release --target xtensa-esp32-none-elf --features esp32 --no-default-features
```

On boot the device prints its Yggdrasil IPv6 address. You can then connect to it from anywhere on the mesh:

```sh
# Ping over Yggdrasil (via yggstack SOCKS5 proxy)
ping6 -x 127.0.0.1:1080 <esp-ipv6>

# TCP to UART bridge
nc -X 5 -x 127.0.0.1:1080 <esp-ipv6> 2000
```

A web UI is available at `http://192.168.4.1` (connect to the `YggBridge` AP) for configuring WiFi credentials and Yggdrasil peer addresses.

## End-to-End Test

An automated E2E test verifies the full stack: yggstack → yggdrasil-ng → lite_node → HTTP.

```sh
YGGSTACK_BIN=/path/to/yggstack bash tests/e2e.sh
```

The test starts a yggstack node with a SOCKS5 proxy, connects a lite_node to it, and verifies HTTP reachability over the Yggdrasil overlay via curl.

## Building

```sh
# Desktop (std) — tests and examples
cargo test
cargo run --example lite_node -- 127.0.0.1:12345

# ESP32-C6 (no_std) — requires nightly toolchain
cd examples/esp32
cargo build --release --target riscv32imac-unknown-none-elf --features esp32c6

# ESP32 (no_std) — requires esp toolchain
cargo +esp build --release --target xtensa-esp32-none-elf --features esp32 --no-default-features
```

## License

MPL-2.0

## Running on Android (Termux)

`tcp_node` (`src/bin/tcp_node.rs`) is the Unix build of the same node, for Termux
and OpenWrt routers: it dials out to public TCP peers and can serve the status API
and TCP port forwarding.

```sh
pkg install rust git curl
git clone <repo> yggdrasil-lite   # or unzip the archive
cd yggdrasil-lite
cargo build --release --bin tcp_node

curl -fsSL -o ~/peers.json https://publicpeers.neilalexander.dev/publicnodes.json
./target/release/tcp_node --key ~/ygg.key --peers ~/peers.json \
    --target 3 --api 127.0.0.1:8080
```

Open `http://127.0.0.1:8080/` in the phone browser for the dashboard, or query
`http://127.0.0.1:8080/api/stats` in Termux. The key file is created on first run.
Keep it private: it determines the node's address.

Keep the node running with the screen off: `termux-wake-lock` (and disable battery
optimisation for Termux in Android settings).

The API listens on 127.0.0.1 only and has no authentication. Do not bind it to
0.0.0.0 on a shared network.


## TCP port forwarding (SSH to a router or phone)

`tcp_node --forward` makes TCP ports on this host reachable over Yggdrasil.
Pass the ports at startup. Only keys given with `--allow` can connect, and only
the listed ports are open.

```sh
# OpenWrt router: dropbear SSH listens on 22
tcp_node --key /root/ygg.key --peers /root/peers.json \
    --allow <client-public-key> --forward 22

# Android (Termux): sshd listens on 8022
tcp_node --key ~/ygg.key --peers ~/peers.json \
    --allow <client-public-key> --forward 8022
```

`--forward` takes a comma-separated list, and can be repeated:

- `--forward 22` maps overlay port 22 to 127.0.0.1:22;
- `--forward 2222:22` maps overlay port 2222 to 127.0.0.1:22;
- `--forward 22,8080,9000:9001` opens three ports.

Up to 16 ports. A local connection that cannot be opened is reset towards the
client.

The client must run a full Yggdrasil stack (yggdrasil-ng with TUN, or yggstack
with its SOCKS proxy) and use an allowed key. For example, with yggstack's SOCKS
proxy on 127.0.0.1:1080:

```sh
ssh -o ProxyCommand="nc -X 5 -x 127.0.0.1:1080 %h %p" -p 22 root@<device-address>
```

Limits of the built-in TCP: one connection per client port, no congestion
control, no TIME_WAIT, and overlay port 80 is taken over when forwarded (this
disables the status page). It is meant for interactive sessions such as SSH, not
bulk transfers.

## Building for a router (OpenWrt)

Build for the router's CPU. Use the musl target for a static binary that needs no
libc on the router. Find the target with `uname -m` on the router and the
OpenWrt target list.

```sh
# example: aarch64 router (check your device)
rustup target add aarch64-unknown-linux-musl
cargo build --release --bin tcp_node --target aarch64-unknown-linux-musl
scp target/aarch64-unknown-linux-musl/release/tcp_node root@192.168.1.1:/usr/bin/
```

`tcp_node` depends only on `rand` and `heapless` (no TLS, no C libraries), so cross
building needs no extra system libraries. Release builds are stripped to keep the
binary small.

Install the service with `openwrt/tcp_node.init` (see the comments in that file).

