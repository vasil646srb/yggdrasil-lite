# yggdrasil-lite

[English](#english) · [Русский](#русский)

---

## English

Minimal [Yggdrasil](https://yggdrasil-network.github.io/) client for embedded and
small Unix devices, written in Rust.

It implements the Yggdrasil/Ironwood subset needed to run as a **leaf node**: connect to
peers, join the spanning tree, discover paths through bloom filters, and exchange
end-to-end encrypted packets with any node in the network. There is no TUN interface
and no admin API in the library itself.

The `tcp_node` binary (`src/bin/tcp_node.rs`) is a runnable device built on the library,
for Termux (Android), Linux and OpenWrt routers.

### Features

- Spanning tree participation, bloom filter routing, PathLookup/PathNotify/PathBroken.
- End-to-end encrypted sessions (XSalsa20-Poly1305 with key ratcheting).
- Metadata handshake compatible with yggdrasil-go and yggdrasil-ng.
- IPv6 address derivation from the Ed25519 key (`200::/7`).
- Optional transit routing (`transit` feature), with per-peer `no_redistribute` policy.
- `no_std` + `alloc` library build for ESP32 (Embassy). Desktop builds use `std`.
- `tcp_node`: public peer list, peer search by latency (allowed keys first, root second),
  TCP and UDP forwarding, ICMPv6 echo. Optional builds add an HTML status server (`html`)
  and `tls://` peers with LAN discovery (`upstream-tls`).
- LAN discovery of **yggdrasil-go** peers via their IPv6 link-local beacons
  (`--lan-upstream`), dialled over TLS (optional `upstream-tls` feature).

### Repository layout

- `src/` — the library (`YggdrasilLite`, wire format, meta handshake, sessions).
- `src/search.rs` — the peer search policy (when and which peer to replace), unit tested.
- `src/bin/tcp_node.rs` — the device binary; `src/bin/tcp_node/` holds its optional parts
  (`html`, `discovery`).
- `examples/` — `lite_node`, `tun`, and the ESP32 firmware projects.
- `tests/` — transit tests, `peer_search.sh` (end-to-end peer search) and the yggstack scripts.
- `scripts/` — `build-variants.sh` (the four builds), `termux.sh`, `build.sh`, `fetch-peers.sh`.
- `openwrt/tcp_node.init` — OpenWrt service script.

### Build variants

`tcp_node` is built in four variants from two optional features. Every variant forwards TCP
and UDP over Yggdrasil (`--forward`, `--connect`, `--forward-udp`); the features only add parts:

| Variant | Features | Adds |
|---------|----------|------|
| `tcp_node-tcp` | none | Nothing: TCP peers only, no TLS, no LAN discovery, no HTML server. |
| `tcp_node-tls` | `upstream-tls` | `tls://` peers and yggdrasil-go LAN peer discovery (`--lan-upstream`). |
| `tcp_node-html` | `html` | HTML server on port 1080 (dashboard + JSON API, overlay status page). |
| `tcp_node-tls-html` | `upstream-tls,html` | Both. |

```sh
scripts/build-variants.sh                                   # all four, into dist/host/
scripts/build-variants.sh --target mipsel-unknown-linux-musl  # for a router (see below)
cargo build --release --bin tcp_node --features upstream-tls,html   # one variant by hand
```

Sizes on x86_64: 0.95 MB, 2.1 MB, 0.98 MB, 2.1 MB. A flag of a feature that is not built in is
refused at start (for example `--api needs a build with --features html`).

The HTML server (`html` builds) uses one port, `--html-port` (default **1080**): the status
page is served on that overlay TCP port to allowed keys, and the dashboard with `/api/stats`
on `127.0.0.1:1080` (loopback only, no authentication; `--api ADDR` changes the address and
`--api off` disables it). If the default local port is taken the dashboard is skipped with a
warning; an explicit `--api` that cannot bind is an error. Earlier builds served the overlay
page on port 80: use `--html-port 80` for that.

### Building `tcp_node`

Plain build (no TLS, no C libraries; depends only on `rand` and `heapless`):

```sh
cargo build --release --bin tcp_node
```

With TLS for `tls://` peers and yggdrasil-go LAN peers (rustls with the `ring` provider: no
OpenSSL and no system libraries, so nothing to install on Termux or for a router cross-build):

```sh
cargo build --release --features upstream-tls --bin tcp_node
```

The `upstream-tls` feature is off by default, so the `no_std` library build never pulls
in TLS. The TLS build is roughly twice the size of the plain one (about 2.1 MB against
1.0 MB on x86_64, 2.3 MB against 1.4 MB for mipsel); compare with `ls -l target/release/tcp_node`.
Certificates are accepted unverified, as yggdrasil-go does: a peer's identity comes from the
signed handshake that follows the TLS session. Dialing runs on worker threads, so a slow or
unreachable peer no longer stalls the node.

Tests:

```sh
cargo test --features transit                       # library, TCP stack, peer search, transit
cargo test --features upstream-tls,html --bin tcp_node # also the TLS/LAN and HTML parts of tcp_node
tests/peer_search.sh                                # peer search end to end on loopback (~4 min)
```

`tests/peer_search.sh` starts real nodes, delays one peer's link by 100 ms each way and checks
that the node replaces that peer once, judges the replacement, and does not churn when the
alternative is just as slow.

### Running `tcp_node`

Simplest run, no options:

```sh
./tcp_node
```

The node loads or creates its key (`./ygg.key` if present, otherwise `~/ygg.key`),
downloads the public peer list in the background (curl, wget or OpenWrt's
`uclient-fetch`), probes the candidates and connects. The list is cached as
`peers-cache.json` next to the key and used at the next start right away; a failed
download is retried every minute, a successful one is refreshed every 6 hours.

With options:

```sh
./target/release/tcp_node --key ~/ygg.key --target 3
```

Use a local peer list instead of downloading one:

```sh
./target/release/tcp_node --key ~/ygg.key --peers ~/peers.json --target 3
```

The key file is created on first run (64 hex characters). It determines the device's
address, so keep it private.

#### Options

| Option | Meaning |
|--------|---------|
| `--key FILE` | Identity file, created on first run. Default: `./ygg.key` if it exists, else `~/ygg.key`. |
| `--peers FILE` | Use a local peer list instead of downloading the public one. |
| `--no-public` | Do not download the public peer list. Use `--peers` and LAN only. |
| `--target N` | Outbound peers to keep connected (1..=32, default 3). |
| `--allow KEY` | Allow an overlay key to use forwards, ping and the page. Repeatable. |
| `--forward PORTS` | Expose local TCP ports over Yggdrasil, e.g. `22,2222:22`. Up to 16 ports. |
| `--open PORTS` | Let any overlay key use these `--forward` ports and ping the node (a public service), e.g. `1080`. The page stays `--allow`-only. |
| `--swap-interval SECS` | At least this long between two peer replacements (default 30; doubles after a useless one, up to 10 min). |
| `--swap-settle SECS` | How long a new peer is measured before the replacement is judged (default 60). |
| `--rtt-limit MS` | Replace peers while the latency to the `--allow` keys or the `--connect` servers is above this (default 150). A client with `--connect` searches for peers that give the lowest ping to its server. |
| `--connect LPORT:[ADDR]:PORT` | Listen on 127.0.0.1:LPORT and carry each connection to `[ADDR]:PORT` over Yggdrasil. Repeatable. |
| `--api ADDR\|off` | `html` build. Local dashboard and `/api/stats`, default `127.0.0.1:<html-port>`. No authentication: loopback only. |
| `--html FILE` | `html` build. Replace the default page on the overlay HTML port. |
| `--html-port PORT` | `html` build. Overlay port of the page and port of the local dashboard (default 1080). |
| `--ping ADDR` | Send one echo request per second and print round-trip times. |
| `--quality-interval SECS` | How often the global network is rechecked (default 300). |
| `--lan-upstream` | `upstream-tls` build. LAN discovery of yggdrasil-go peers over IPv6 link-local (`ff02::114:9001`), dialled over TLS. |
| `--lan-target N` | `upstream-tls` build. Outbound slots reserved for LAN peers (default: `--target`). |
| `--listen PORT` | Accept plain TCP inbound peers on this port. |


#### LAN peers of yggdrasil-go

Run with LAN discovery only, no internet peers:

```sh
./target/release/tcp_node --key ~/ygg.key --lan-upstream --no-public --target 1
```

What happens:

1. The node joins `ff02::114` on every interface it can find and listens for beacons on
   UDP port 9001. It never sends beacons, and it does not open an inbound TLS listener.
2. A beacon is accepted only when its version is 0.5, its hash is the BLAKE2b-512 of the
   key (passwordless networks only), and it comes from a link-local address.
3. The node dials the beacon's port over TLS on the exact interface the beacon came
   from, then runs the normal metadata handshake.

Interface discovery uses `/sys/class/net`. On Android this is often denied, so the node
then tries interface indices 1 to 64 and joins on those that exist. The log line
`lan upstream: joined … on ifindex […]` shows which ones succeeded.

Limits:

- The TLS layer does not verify the peer's certificate, as yggdrasil-go does not. Peer
  identity comes from the signed metadata handshake that follows.
- Passwordless networks only.
- TLS is rustls, built in: nothing depends on the device's OpenSSL. The TLS build only dials
  out; it does not listen.

#### Diagnostics

When a connection drops, the log shows why:

- `peer slot N: closed by remote (EOF) at … ms`
- `peer slot N: read error at … ms: <error> (<kind>)`
- `write to slot N failed: …`
- `lan: TLS to <addr>: <error>` and `lan: dial <addr> failed`

### Running on Android (Termux)

```sh
pkg install rust git curl
git clone <repo> yggdrasil-lite   # or unzip the archive
cd yggdrasil-lite
cargo build --release --bin tcp_node
```

Keep the node running with the screen off: `termux-wake-lock`, and disable battery
optimisation for Termux in Android settings.

In an `html` build (`cargo build --release --bin tcp_node --features html`, or
`bash scripts/termux.sh build`) open `http://127.0.0.1:1080/` in the phone browser for the
dashboard, or query `http://127.0.0.1:1080/api/stats` in Termux. The API has no
authentication and is loopback only; do not move it to `0.0.0.0` on a shared network.

### TCP port forwarding (SSH to a router or phone)

```sh
# OpenWrt router: dropbear SSH on 22
tcp_node --key /root/ygg.key --peers /root/peers.json \
    --allow <client-public-key> --forward 22

# Android (Termux): sshd on 8022
tcp_node --key ~/ygg.key --peers ~/peers.json \
    --allow <client-public-key> --forward 8022
```

The client needs a full Yggdrasil stack (yggdrasil-ng with TUN, or yggstack with its SOCKS
proxy) and an allowed key:

```sh
ssh -o ProxyCommand="nc -X 5 -x 127.0.0.1:1080 %h %p" -p 22 root@<device-address>
```

Outgoing direction: `--connect 2222:[<device-address>]:22` lets `ssh -p 2222 root@127.0.0.1`
reach the device from a host that runs `tcp_node` only (no TUN, no yggstack).

The built-in TCP (`src/tcp_stack.rs`) is a full implementation: RFC 9293 state machine
with TIME-WAIT and half-close, MSS and window scaling (up to 256 KiB windows), flow
control with zero-window probing, delayed ACKs, out-of-order reassembly, RTO per RFC 6298,
NewReno congestion control (slow start, fast retransmit/recovery), keepalive, keyed
initial sequence numbers and RST/SYN checks per RFC 5961. Not implemented: SACK and
timestamps. Over a direct link between two nodes an 8 MB transfer runs at ~18 MB/s.
Forwarding the HTML port (1080 by default) disables the status page.

### Building for a router (OpenWrt)

Use the musl target for a static binary that needs no libc on the router. Find the CPU
with `uname -m` on the router.

```sh
rustup target add aarch64-unknown-linux-musl
cargo build --release --bin tcp_node --target aarch64-unknown-linux-musl
scp target/aarch64-unknown-linux-musl/release/tcp_node root@192.168.1.1:/usr/bin/
```

Install the service with `openwrt/tcp_node.init`. The TLS build (`--features upstream-tls`)
cross-compiles the same way; `ring` contains a little C, so point `cc` at the router toolchain,
for example `CC_mipsel_unknown_linux_musl=.../mipsel-linux-muslsf-gcc`. For the mipsel
musl targets, which have no prebuilt standard library, use nightly with
`-Z build-std=std,panic_abort`.

### Library usage

```rust
use yggdrasil_lite::{YggdrasilLite, LiteConfig, NodeEvent};

let config = LiteConfig::new(my_ed25519_seed);
let mut node = YggdrasilLite::new(config);

// After TCP+TLS connection and metadata handshake with a peer:
let peer_id = node.add_peer(peer_public_key, 0);
node.mark_handshake_done(peer_id);

loop {
    let events = node.handle_peer_data(peer_id, &incoming_bytes, now_ms, &mut rng);
    handle_events(&events, &mut tls_writer);

    let events = node.poll(now_ms, &mut rng);      // ~every 100 ms
    handle_events(&events, &mut tls_writer);

    let events = node.send(&dest_public_key, b"hello", now_ms, &mut rng);
    handle_events(&events, &mut tls_writer);
}
```

The library is transport-agnostic: the caller provides TCP+TLS and feeds bytes in and out.
See `examples/lite_node.rs` for a complete desktop node.

### End-to-end test

```sh
YGGSTACK_BIN=/path/to/yggstack bash tests/e2e.sh
```

### Status

- Verified: the library and `tcp_node` build on Termux; LAN connections to a yggdrasil-go
  peer work, and stay up while internet peers are connected. These results were obtained
  with an earlier rustls-based TLS. The current rustls build was tested against a local TLS
  terminator (10 MiB through the tunnel) and, on an OpenWrt 24.10 router (MT7628, mipsel,
  no FPU), connected to live `tls://` peers running yggdrasil-go. LAN beacon discovery has
  not been run against a real yggdrasil-go beacon.
- Open: a LAN-only connection (no internet peers) was reported to drop after 2–3 seconds.
  Cause not yet confirmed.
- Not verified: TLS 1.2 negotiation with yggdrasil-go; the announce feature was removed.

### License

MPL-2.0

---

## Русский

Минимальный клиент [Yggdrasil](https://yggdrasil-network.github.io/) для встраиваемых
и небольших Unix-устройств, на Rust.

Реализована часть протокола Yggdrasil/Ironwood, нужная для работы в роли **листового
узла**: подключение к пирам, участие в остовном дереве, поиск путей через bloom-фильтры
и обмен зашифрованными сквозными пакетами с любым узлом сети. В самой библиотеке нет
TUN-интерфейса и административного API.

Бинарник `tcp_node` (`src/bin/tcp_node.rs`) — готовое устройство на этой библиотеке для
Termux (Android), Linux и роутеров OpenWrt.

### Возможности

- Участие в остовном дереве, маршрутизация через bloom-фильтры, PathLookup/PathNotify/PathBroken.
- Сквозное шифрование сессий (XSalsa20-Poly1305 с ratchet-ключами).
- Метаданные рукопожатия, совместимые с yggdrasil-go и yggdrasil-ng.
- IPv6-адрес выводится из ключа Ed25519 (`200::/7`).
- Транзитная маршрутизация по флагу `transit`, с политикой `no_redistribute` для каждого пира.
- Сборка библиотеки `no_std` + `alloc` для ESP32 (Embassy). Для ПК используется `std`.
- `tcp_node`: публичный список пиров, поиск пиров по задержке (сначала разрешённые ключи,
  потом корень), проброс TCP и UDP, ICMPv6 echo. Необязательные сборки добавляют HTML-сервер
  статуса (`html`) и пиры `tls://` с поиском в LAN (`upstream-tls`).
- Поиск пиров **yggdrasil-go** в локальной сети по их беаконам IPv6 link-local
  (`--lan-upstream`), подключение по TLS (необязательная feature `upstream-tls`).

### Варианты сборки

`tcp_node` собирается в четырёх вариантах из двух необязательных feature. Во всех вариантах
работает проброс TCP и UDP через Yggdrasil (`--forward`, `--connect`, `--forward-udp`),
feature лишь добавляют части:

| Вариант | Features | Добавляет |
|---------|----------|-----------|
| `tcp_node-tcp` | нет | Ничего: только TCP-пиры, без TLS, без поиска в LAN, без HTML-сервера. |
| `tcp_node-tls` | `upstream-tls` | Пиры `tls://` и поиск пиров yggdrasil-go в LAN (`--lan-upstream`). |
| `tcp_node-html` | `html` | HTML-сервер на порту 1080 (панель + JSON API, страница по оверлею). |
| `tcp_node-tls-html` | `upstream-tls,html` | И то и другое. |

```sh
scripts/build-variants.sh                                   # все четыре в dist/host/
scripts/build-variants.sh --target mipsel-unknown-linux-musl  # для роутера (см. ниже)
cargo build --release --bin tcp_node --features upstream-tls,html   # один вариант вручную
```

Размеры на x86_64: 0,95 МБ, 2,1 МБ, 0,98 МБ, 2,1 МБ. Флаг отсутствующей в сборке feature
отвергается при запуске (например, `--api needs a build with --features html`).

HTML-сервер (сборки `html`) использует один порт, `--html-port` (по умолчанию **1080**):
страница статуса отдаётся на этом TCP-порту оверлея разрешённым ключам, а панель с
`/api/stats` на `127.0.0.1:1080` (только loopback, без аутентификации; `--api ADDR` меняет
адрес, `--api off` отключает). Если порт по умолчанию занят, панель пропускается с
предупреждением; явный `--api`, который нельзя занять, считается ошибкой. Раньше страница
по оверлею отдавалась на порту 80: для этого используйте `--html-port 80`.

### Структура репозитория

- `src/` — библиотека (`YggdrasilLite`, формат пакетов, метаданные, сессии).
- `src/search.rs` — политика поиска пиров (когда и какой пир заменить), покрыта модульными тестами.
- `src/bin/tcp_node.rs` — бинарник устройства; необязательные части лежат в
  `src/bin/tcp_node/` (`html`, `discovery`).
- `examples/` — `lite_node`, `tun` и прошивки ESP32.
- `tests/` — тесты транзита, `peer_search.sh` (поиск пиров от начала до конца) и скрипты yggstack.
- `scripts/` — `build-variants.sh` (четыре сборки), `termux.sh`, `build.sh`, `fetch-peers.sh`.
- `openwrt/tcp_node.init` — скрипт службы для OpenWrt.

### Сборка `tcp_node`

Обычная сборка (без TLS и без C-библиотек; зависит только от `rand` и `heapless`):

```sh
cargo build --release --bin tcp_node
```

С TLS для пиров `tls://` и пиров yggdrasil-go в LAN (rustls с провайдером `ring`: без OpenSSL и
системных библиотек, поэтому в Termux ничего устанавливать не нужно, а кросс-сборка под роутер
проще):

```sh
cargo build --release --features upstream-tls --bin tcp_node
```

Feature `upstream-tls` выключена по умолчанию, поэтому сборка библиотеки `no_std` никогда
не тянет TLS. Сборка с TLS примерно вдвое больше обычной (около 2,1 МБ против 1,0 МБ на
x86_64, 2,3 МБ против 1,4 МБ для mipsel); сравните командой `ls -l target/release/tcp_node`.
Сертификаты принимаются без проверки, как в yggdrasil-go: личность пира подтверждает подписанное
рукопожатие после TLS-сессии. Подключение выполняется в рабочих потоках, поэтому медленный или
недоступный пир больше не останавливает узел.

Тесты:

```sh
cargo test --features transit                       # библиотека, TCP-стек, поиск пиров, транзит
cargo test --features upstream-tls,html --bin tcp_node # плюс TLS/LAN и HTML-части tcp_node
tests/peer_search.sh                                # поиск пиров целиком на loopback (~4 мин)
```

`tests/peer_search.sh` запускает настоящие узлы, задерживает канал одного пира на 100 мс в
каждую сторону и проверяет, что узел заменяет этого пира один раз, оценивает замену и не
метается, если альтернатива так же медленна.

### Запуск `tcp_node`

Самый простой запуск, без параметров:

```sh
./tcp_node
```

Узел загружает или создаёт ключ (`./ygg.key`, если он есть, иначе `~/ygg.key`), в фоне
скачивает публичный список пиров (curl, wget или `uclient-fetch` на OpenWrt), проверяет
кандидатов и подключается. Список сохраняется в `peers-cache.json` рядом с ключом и при
следующем старте используется сразу; неудачная загрузка повторяется раз в минуту,
удачная обновляется раз в 6 часов.

С параметрами:

```sh
./target/release/tcp_node --key ~/ygg.key --target 3
```

Свой список пиров вместо загрузки:

```sh
./target/release/tcp_node --key ~/ygg.key --peers ~/peers.json --target 3
```

Файл ключа создаётся при первом запуске (64 hex-символа). От него зависит адрес
устройства, поэтому храните его в тайне.

#### Опции

| Опция | Назначение |
|-------|------------|
| `--key FILE` | Файл идентичности, создаётся при первом запуске. По умолчанию `./ygg.key`, если есть, иначе `~/ygg.key`. |
| `--peers FILE` | Использовать локальный список пиров вместо публичного. |
| `--no-public` | Не загружать публичный список пиров. Только `--peers` и LAN. |
| `--target N` | Сколько исходящих пиров держать (1..=32, по умолчанию 3). |
| `--allow KEY` | Разрешить ключу оверлея пользоваться проброской, ping и страницей. Можно несколько раз. |
| `--forward PORTS` | Открыть локальные TCP-порты через Yggdrasil, например `22,2222:22`. До 16 портов. |
| `--open PORTS` | Пустить к этим портам `--forward` и к ping любой ключ оверлея (публичный сервис), например `1080`. Страница — только `--allow`. |
| `--swap-interval SECS` | Не чаще одной замены пира за это время (по умолчанию 30; после бесполезной замены вдвое дольше, до 10 мин). |
| `--swap-settle SECS` | Сколько мерить нового пира, прежде чем решить, помогла ли замена (по умолчанию 60). |
| `--rtt-limit MS` | Менять пиров, пока пинг до ключей `--allow` или серверов `--connect` выше этого (по умолчанию 150). Клиент с `--connect` ищет пиров с наименьшим пингом до сервера. |
| `--connect LPORT:[ADDR]:PORT` | Слушать 127.0.0.1:LPORT и передавать каждое соединение на `[ADDR]:PORT` через Yggdrasil. Можно повторять. |
| `--api ADDR\|off` | Сборка `html`. Локальная панель и `/api/stats`, по умолчанию `127.0.0.1:<html-port>`. Без аутентификации: только loopback. |
| `--html FILE` | Сборка `html`. Заменить страницу по умолчанию на HTML-порту оверлея. |
| `--html-port PORT` | Сборка `html`. Порт оверлея для страницы и порт локальной панели (по умолчанию 1080). |
| `--ping ADDR` | Раз в секунду посылать echo-запрос и печатать время ответа. |
| `--quality-interval SECS` | Как часто перепроверять глобальную сеть (по умолчанию 300). |
| `--lan-upstream` | Сборка `upstream-tls`. Поиск пиров yggdrasil-go в LAN через IPv6 link-local (`ff02::114:9001`), подключение по TLS. |
| `--lan-target N` | Сборка `upstream-tls`. Исходящие слоты, отведённые под пиров из LAN (по умолчанию `--target`). |
| `--listen PORT` | Принимать входящие пиры по обычному TCP на этом порту. |


#### Пиры yggdrasil-go в LAN

Запуск только с поиском в LAN, без интернет-пиров:

```sh
./target/release/tcp_node --key ~/ygg.key --lan-upstream --no-public --target 1
```

Что происходит:

1. Узел подписывается на `ff02::114` на каждом интерфейсе, который найдёт, и слушает беаконы
   на UDP-порту 9001. Беаконы он не отправляет и не открывает входящий TLS-listener.
2. Беакон принимается, только если его версия 0.5, хеш совпадает с BLAKE2b-512 от ключа
   (только сети без пароля) и адрес отправителя link-local.
3. Узел подключается по TLS к порту из беакона, на том же интерфейсе, с которого пришёл
   беакон, и затем выполняет обычное рукопожатие метаданных.

Список интерфейсов берётся из `/sys/class/net`. На Android это часто запрещено, поэтому
узел пробует индексы интерфейсов от 1 до 64 и подписывается на существующие. Строка
`lan upstream: joined … on ifindex […]` показывает, на каких интерфейсах это получилось.

Ограничения:

- TLS не проверяет сертификат пира, как и yggdrasil-go. Идентичность пира подтверждается
  подписанным рукопожатием метаданных, которое идёт дальше.
- Только сети без пароля.
- TLS встроен (rustls): ничего не зависит от OpenSSL на устройстве. Сборка с TLS только
  подключается к пирам и ничего не слушает.

#### Диагностика

Когда соединение падает, в логе видно причину:

- `peer slot N: closed by remote (EOF) at … ms`
- `peer slot N: read error at … ms: <ошибка> (<тип>)`
- `write to slot N failed: …`
- `lan: TLS to <адрес>: <ошибка>` и `lan: dial <адрес> failed`

### Запуск на Android (Termux)

```sh
pkg install rust git curl
git clone <repo> yggdrasil-lite   # или распакуйте архив
cd yggdrasil-lite
cargo build --release --bin tcp_node
```

Чтобы узел работал при выключенном экране: `termux-wake-lock`, и отключите оптимизацию
батареи для Termux в настройках Android.

В сборке `html` (`cargo build --release --bin tcp_node --features html` или
`bash scripts/termux.sh build`) дашборд открывается в браузере телефона по адресу
`http://127.0.0.1:1080/`, данные в Termux — по `http://127.0.0.1:1080/api/stats`. У API нет
аутентификации, он слушает только loopback; не переносите его на `0.0.0.0` в общей сети.

### Проброс TCP-портов (SSH к роутеру или телефону)

```sh
# Роутер OpenWrt: dropbear на 22
tcp_node --key /root/ygg.key --peers /root/peers.json \
    --allow <публичный-ключ-клиента> --forward 22

# Android (Termux): sshd на 8022
tcp_node --key ~/ygg.key --peers ~/peers.json \
    --allow <публичный-ключ-клиента> --forward 8022
```

Клиенту нужен полный стек Yggdrasil (yggdrasil-ng с TUN или yggstack с SOCKS-прокси) и
разрешённый ключ:

```sh
ssh -o ProxyCommand="nc -X 5 -x 127.0.0.1:1080 %h %p" -p 22 root@<адрес-устройства>
```

Обратное направление: `--connect 2222:[<адрес-устройства>]:22` позволяет выполнить
`ssh -p 2222 root@127.0.0.1` с машины, где запущен только `tcp_node` (без TUN и yggstack).

Встроенный TCP (`src/tcp_stack.rs`) полноценный: машина состояний RFC 9293 с TIME-WAIT и
полузакрытием, опции MSS и масштабирования окна (окна до 256 КиБ), управление потоком с
пробами нулевого окна, отложенные ACK, сборка сегментов не по порядку, RTO по RFC 6298,
управление перегрузкой NewReno (медленный старт, быстрый повтор и восстановление),
keepalive, ISN по ключевому хешу и проверки RST/SYN по RFC 5961. Не реализованы SACK и
метки времени. По прямому соединению двух узлов 8 МБ передаются со скоростью ~18 МБ/с.
Проброс порта 80 оверлея отключает страницу статуса.

### Сборка для роутера (OpenWrt)

Используйте musl-цель, чтобы получить статический бинарник без libc на роутере. Архитектуру
процессора узнайте командой `uname -m` на роутере.

```sh
rustup target add aarch64-unknown-linux-musl
cargo build --release --bin tcp_node --target aarch64-unknown-linux-musl
scp target/aarch64-unknown-linux-musl/release/tcp_node root@192.168.1.1:/usr/bin/
```

Службу устанавливайте через `openwrt/tcp_node.init`. Сборка с TLS (`--features upstream-tls`)
кросс-компилируется так же; `ring` содержит немного C, поэтому укажите `cc` компилятор
роутера, например `CC_mipsel_unknown_linux_musl=.../mipsel-linux-muslsf-gcc`. Для целей mipsel
musl без готовой стандартной библиотеки используйте nightly и `-Z build-std=std,panic_abort`.

### Использование библиотеки

```rust
use yggdrasil_lite::{YggdrasilLite, LiteConfig, NodeEvent};

let config = LiteConfig::new(my_ed25519_seed);
let mut node = YggdrasilLite::new(config);

// После TCP+TLS соединения и рукопожатия метаданных с пиром:
let peer_id = node.add_peer(peer_public_key, 0);
node.mark_handshake_done(peer_id);

loop {
    let events = node.handle_peer_data(peer_id, &incoming_bytes, now_ms, &mut rng);
    handle_events(&events, &mut tls_writer);

    let events = node.poll(now_ms, &mut rng);      // примерно каждые 100 мс
    handle_events(&events, &mut tls_writer);

    let events = node.send(&dest_public_key, b"hello", now_ms, &mut rng);
    handle_events(&events, &mut tls_writer);
}
```

Библиотека не зависит от транспорта: вызывающий код предоставляет TCP+TLS и передаёт байты
туда и обратно. Полный десктопный пример — `examples/lite_node.rs`.

### End-to-end тест

```sh
YGGSTACK_BIN=/path/to/yggstack bash tests/e2e.sh
```

### Статус

- Проверено: библиотека и `tcp_node` собираются в Termux; LAN-соединения с пиром yggdrasil-go
  работают и держатся, пока подключены интернет-пиры. Эти результаты получены на прежней
  TLS-реализации на rustls. Текущая сборка на rustls проверена с локальным TLS-терминатором
  (10 МиБ через туннель) и на роутере с OpenWrt 24.10 (MT7628, mipsel, без FPU), где
  подключилась к настоящим `tls://`-пирам на yggdrasil-go. Поиск пиров по маякам в LAN с
  настоящим маяком yggdrasil-go не проверялся.
- Открыто: соединение только с LAN-пирами (без интернет-пиров) сообщалось как падающее через
  2–3 секунды. Причина пока не подтверждена.
- Не проверено: согласование TLS 1.2 с yggdrasil-go. Режим анонса удалён из кода.

### Лицензия

MPL-2.0
