# YggLite: light ESP32 Yggdrasil node

A smaller ESP32 firmware. It keeps what is needed to be a node, a status page
and send/receive by IPv6, and drops the rest.

| Feature | `examples/esp32` (full) | `examples/esp32-lite` |
|---|---|---|
| Peers | `tls://` (TLS) | `tcp://` only (plain TCP) |
| Overlay TCP | TCP-UART bridge, HTTP page | status page (port 80) |
| Local web UI | config forms, status | status, send form, inbox JSON |
| Send / receive by IPv6 | no | yes (`/send`, `/inbox`) |
| Configuration | flash (web UI) | `.cargo/config.toml` at build time |
| UART | yes | no |

## Build and flash

Same toolchain and ESP-HAL paths as `examples/esp32`. Edit the paths in `Cargo.toml`
if your checkout is elsewhere.

```sh
cd examples/esp32-lite
# ESP32-C6 (RISC-V)
cargo run --release --target riscv32imac-unknown-none-elf --features esp32c6
# ESP32 (Xtensa)
cargo +esp run --release --target xtensa-esp32-none-elf --features esp32 --no-default-features
```

## Configure

Edit `.cargo/config.toml`, `[env]` section:

- `WIFI_SSID`, `WIFI_PASSWORD`: the Wi-Fi network the device joins.
- `YGG_PEER1..3`: peers as `host:port`, IPv4 addresses only (`1.2.3.4:1514`).
  Use a `tcp://` peer (plain TCP), not `tls://`.
- `YGG_SEED`: optional, 64 hex characters. Keeps the device address across
  reboots. Create one with `tcp_node --key ygg.key` (the file holds 64 hex
  characters) and paste it in. Without it, the address changes on every boot.

## Use

- The device opens its own AP `YggLite` (192.168.4.1) and joins your Wi-Fi.
  The address on your network is printed in the log as `Got STA IP`.
- Local status page: `http://<device-ip>/` or `http://192.168.4.1/`.
  It has a send form and the live status.
- Send a message: `http://192.168.4.1/send?to=<yggdrasil-ipv6>&msg=hello`.
- Received messages (last 8): `http://192.168.4.1/inbox` (JSON).
- Status over Yggdrasil: the device's overlay page on port 80. Open it with a
  full Yggdrasil stack (yggstack SOCKS, or yggdrasil-ng).
- The status JSON is at `/api/stats` (same format as the full firmware).

The device accepts messages from any node that reaches it over Yggdrasil. The
local pages have no password, and the AP is open unless you add a password in
`AccessPointConfig`.

## Limits

- IPv4 peers only (no DNS names).
- One message per `/send` request; messages are text, at most 120 bytes kept in `/inbox`.
- No ping from the web UI.
- No TCP port forwarding (that is in `tcp_node --forward`, not in this build).
