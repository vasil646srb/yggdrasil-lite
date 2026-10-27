# yggdrasil-lite

## Fork

This repository is a personal fork of
[cleverfox/yggdrasil-lite](https://github.com/cleverfox/yggdrasil-lite)
(the original project; MPL-2.0). It may contain local modifications,
experiments or fixes that are not part of the upstream codebase.

- Upstream: https://github.com/cleverfox/yggdrasil-lite.git
- Origin:   https://github.com/vasil646srb/yggdrasil-lite.git

---

## tcp_node — ready-made node for Unix hosts

`tcp_node` (`src/bin/tcp_node.rs`) is an executable yggdrasil-lite node for
**Termux, Linux and OpenWrt**. It connects to public TCP peers, acts as a
leaf node, exposes status via HTTP and can forward TCP ports over Yggdrasil.
Depends only on `rand` and `heapless` — no TLS, no C libraries. A compact
static binary.

### Flags

| Flag | Description |
|------|-------------|
| `--key FILE` | Key file (64 hex chars). Created on first run; determines the node address — keep it secret |
| `--peers FILE` | JSON peer list (`publicnodes.json`) |
| `--target N` | Number of outgoing slots (1..32, default 3) |
| `--allow KEY` | Allowed public key (repeatable). All other datagrams are dropped |
| `--api ADDR` | HTTP status server (dashboard + JSON) |
| `--html FILE` | Custom HTML template for the status page |
| `--forward PORTS` | TCP port forwarding (up to 16) |
| `--quality-interval SECS` | Peer quality measurement interval (default 300) |
| `--ping IPV6` | RTT measurement to a node |
| `--send IPV6 MSG` | Send a single datagram |

### Basic usage (Termux)

```sh
pkg install rust git curl
git clone https://github.com/vasil646srb/yggdrasil-lite && cd yggdrasil-lite
cargo build --release --bin tcp_node

curl -fsSL -o ~/peers.json https://publicpeers.neilalexander.dev/publicnodes.json
./target/release/tcp_node --key ~/ygg.key --peers ~/peers.json \
    --target 3 --api 127.0.0.1:8080
```

Dashboard: `http://127.0.0.1:8080/` · Stats: `curl http://127.0.0.1:8080/api/stats`.
The API listens on 127.0.0.1 only, no authentication — do not expose on 0.0.0.0.

Keep the node alive with the screen off: `termux-wake-lock` and disable battery
optimisation for Termux.

## TCP port forwarding (SSH to a router or phone)

`tcp_node --forward` makes TCP ports on this host reachable over Yggdrasil.
Pass the ports at startup. Only keys given with `--allow` can connect, and only
the listed ports are open.

### `--forward` format

`--forward` accepts a comma-separated list of ports (up to 16), and the flag
can be repeated. Two item formats are supported:

- `PORT` — overlay port matches the local one. Example: `--forward 22`
  opens overlay port 22 and maps it to 127.0.0.1:22;
- `OVERLAY:LOCAL` — explicit mapping: overlay port `OVERLAY` points to
  local port `LOCAL`. Example: `--forward 2222:22` opens overlay port
  2222 → 127.0.0.1:22.

Both formats can be mixed in one list. Example:

```sh
tcp_node --key ~/ygg.key --peers ~/peers.json \
    --allow <client-public-key> --forward 22,8080,9000:9001
```

This opens:

- `22` — overlay 22 → 127.0.0.1:22 (matching number);
- `8080` — overlay 8080 → 127.0.0.1:8080 (matching number);
- `9000:9001` — overlay 9000 → 127.0.0.1:9001 (explicit mapping).

`--forward` can be specified multiple times; ports from all occurrences are
merged. Up to 16 ports total.

### Role examples

```sh
# OpenWrt router: dropbear SSH listens on port 22
tcp_node --key /root/ygg.key --peers /root/peers.json \
    --allow <client-public-key> --forward 22

# Android (Termux): sshd listens on port 8022
tcp_node --key ~/ygg.key --peers ~/peers.json \
    --allow <client-public-key> --forward 8022
```

A local connection that cannot be opened is reset towards the client. The
client must run a full Yggdrasil stack (yggdrasil-ng with TUN, or yggstack
with its SOCKS proxy) and use an allowed key. For example, with yggstack's
SOCKS proxy on 127.0.0.1:1080:

```sh
ssh -o ProxyCommand="nc -X 5 -x 127.0.0.1:1080 %h %p" -p 22 root@<device-address>
```

### Built-in TCP limitations

For interactive sessions (SSH), not for bulk transfers: one connection per
client port, no congestion control, no TIME_WAIT; forwarding overlay port 80
disables the built-in status page.

### Network checks

```sh
tcp_node --key ~/ygg.key --peers ~/peers.json --ping <ipv6>       # RTT
tcp_node --key ~/ygg.key --peers ~/peers.json --send <ipv6> hello # test datagram
```

### Building for a router (musl-static)

```sh
rustup target add aarch64-unknown-linux-musl
cargo build --release --bin tcp_node --target aarch64-unknown-linux-musl
scp target/aarch64-unknown-linux-musl/release/tcp_node root@192.168.1.1:/usr/bin/
```

Service: `openwrt/tcp_node.init`.

---

## ESP32 (no_std)

Firmwares that connect Yggdrasil directly to hardware without a Unix host.
Requires nightly (ESP32-C6, RISC-V) or esp (Xtensa) toolchain.

### Yggdrasil TCP-UART Bridge (`examples/esp32`)

Bridges TCP connections over Yggdrasil to a hardware UART. Connects to WiFi,
establishes TLS to peers, listens for TCP/ICMPv6 on the overlay IPv6.

```sh
cd examples/esp32
# ESP32-C6 (RISC-V)
cargo run --release --target riscv32imac-unknown-none-elf --features esp32c6
# ESP32 (Xtensa)
cargo +esp run --release --target xtensa-esp32-none-elf --features esp32 --no-default-features
```

On startup it prints its IPv6; WiFi/peer settings are configured via the web-UI
at `http://192.168.4.1` (AP `YggBridge`). Access from the mesh:

```sh
ping6 -x 127.0.0.1:1080 <esp-ipv6>          # via yggstack SOCKS5
nc -X 5 -x 127.0.0.1:1080 <esp-ipv6> 2000   # TCP→UART
```

### ESP32-Lite and ESP32-C6-IOT

The repository also includes `esp32-lite` (minimal node) and `esp32c6-iot`
(IoT firmware for C6). Build them similarly: select the target firmware via
Cargo features and the corresponding nightly/esp toolchain.

---

## About the library (brief)

`yggdrasil-lite` is a minimal yggdrasil/Ironwood client for embedded: leaf node
(peer connections, spanning tree, bloom routing, end-to-end encryption with
XSalsa20-Poly1305), no TUN or admin API. Designed for `no_std`+`alloc` (ESP32),
also works with `std`. An optional `transit` feature turns the node into a
router. Detailed API docs (modules `tree`, `bloom`, `pathfinder`, `session`,
`wire`, `meta`, `crypto`, `address`, `peer`) and library usage examples are in
the original [project](https://github.com/cleverfox/yggdrasil-lite).

## License

MPL-2.0
