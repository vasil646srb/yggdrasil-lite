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
- `tcp_node`: public peer discovery, `--forward` TCP port forwarding, status API and
  dashboard, ICMPv6 echo, and LAN discovery.
- LAN discovery of **yggdrasil-go** peers via their IPv6 link-local beacons
  (`--lan-upstream`), dialled over TLS (optional `upstream-tls` feature).

### Repository layout

- `src/` — the library (`YggdrasilLite`, wire format, meta handshake, sessions).
- `src/bin/tcp_node.rs` — the device binary.
- `examples/` — `lite_node`, `tun`, and the ESP32 firmware projects.
- `tests/` — end-to-end scripts and transit tests.
- `openwrt/tcp_node.init` — OpenWrt service script.

### Building `tcp_node`

Plain build (no TLS, no C libraries; depends only on `rand` and `heapless`):

```sh
cargo build --release --bin tcp_node
```

With TLS for yggdrasil-go LAN peers (uses the system OpenSSL through `native-tls`; on Termux
install it first with `pkg install openssl`):

```sh
cargo build --release --features upstream-tls --bin tcp_node
```

The `upstream-tls` feature is off by default, so the `no_std` library build never pulls
in TLS. The TLS build depends on the OpenSSL headers and library available at build time
(`pkg install openssl` on Termux). Compare binary sizes with `ls -l target/release/tcp_node`
for both builds.

Tests:

```sh
cargo test
cargo test --features upstream-tls --bin tcp_node upstream_beacon
```

### Running `tcp_node`

Basic run with the public peer list (downloaded on start):

```sh
./target/release/tcp_node --key ~/ygg.key --target 3 --api 127.0.0.1:8080
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
| `--key FILE` | Identity file, created on first run. |
| `--peers FILE` | Use a local peer list instead of downloading the public one. |
| `--no-public` | Do not download the public peer list. Use `--peers` and LAN only. |
| `--target N` | Outbound peers to keep connected (1..=32, default 3). |
| `--allow KEY` | Allow an overlay key to use forwards, ping and the page. Repeatable. |
| `--forward PORTS` | Expose local TCP ports over Yggdrasil, e.g. `22,2222:22`. Up to 16 ports. |
| `--api ADDR` | Status server with dashboard and `/api/stats`. No authentication: bind to 127.0.0.1. |
| `--html FILE` | Replace the default page on overlay port 80. |
| `--ping ADDR` | Send one echo request per second and print round-trip times. |
| `--quality-interval SECS` | How often the global network is rechecked (default 300). |
| `--lan-upstream` | LAN discovery of yggdrasil-go peers over IPv6 link-local (`ff02::114:9001`), dialled over TLS. Needs the `upstream-tls` build. |
| `--lan-target N` | Outbound slots reserved for LAN peers (default: `--target`). |
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
- TLS comes from the system OpenSSL, so the device's OpenSSL version matters. The TLS build
  only dials out; it does not listen.

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

Open `http://127.0.0.1:8080/` in the phone browser for the dashboard, or query
`http://127.0.0.1:8080/api/stats` in Termux. The API has no authentication and must not
be bound to `0.0.0.0` on a shared network.

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

Limits of the built-in TCP: one connection per client port, no congestion control, no
TIME_WAIT. Meant for interactive sessions, not bulk transfers. Forwarding overlay port 80
disables the status page.

### Building for a router (OpenWrt)

Use the musl target for a static binary that needs no libc on the router. Find the CPU
with `uname -m` on the router.

```sh
rustup target add aarch64-unknown-linux-musl
cargo build --release --bin tcp_node --target aarch64-unknown-linux-musl
scp target/aarch64-unknown-linux-musl/release/tcp_node root@192.168.1.1:/usr/bin/
```

Install the service with `openwrt/tcp_node.init`. The TLS build (`--features
upstream-tls`) needs OpenSSL built for the router's target, so cross-compiling it takes
extra setup. The plain build needs none.

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
  with the earlier rustls-based TLS; the native-tls build has not been tested yet.
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
- `tcp_node`: поиск публичных пиров, проброс TCP-портов `--forward`, сервер статуса и
  дашборд, ICMPv6 echo, поиск пиров в LAN.
- Поиск пиров **yggdrasil-go** в локальной сети по их беаконам IPv6 link-local
  (`--lan-upstream`), подключение по TLS (необязательная feature `upstream-tls`).

### Структура репозитория

- `src/` — библиотека (`YggdrasilLite`, формат пакетов, метаданные, сессии).
- `src/bin/tcp_node.rs` — бинарник устройства.
- `examples/` — `lite_node`, `tun` и прошивки ESP32.
- `tests/` — end-to-end скрипты и тесты транзита.
- `openwrt/tcp_node.init` — скрипт службы для OpenWrt.

### Сборка `tcp_node`

Обычная сборка (без TLS и без C-библиотек; зависит только от `rand` и `heapless`):

```sh
cargo build --release --bin tcp_node
```

С TLS для пиров yggdrasil-go в LAN (используется системный OpenSSL через `native-tls`; в Termux
сначала установите его командой `pkg install openssl`):

```sh
cargo build --release --features upstream-tls --bin tcp_node
```

Feature `upstream-tls` выключена по умолчанию, поэтому сборка библиотеки `no_std` никогда
не тянет TLS. Для сборки с TLS нужны заголовки и библиотека OpenSSL (в Termux: `pkg install
openssl`). Размеры бинарников сравните командой `ls -l target/release/tcp_node` для обеих сборок.

Тесты:

```sh
cargo test
cargo test --features upstream-tls --bin tcp_node upstream_beacon
```

### Запуск `tcp_node`

Простой запуск с публичным списком пиров (загружается при старте):

```sh
./target/release/tcp_node --key ~/ygg.key --target 3 --api 127.0.0.1:8080
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
| `--key FILE` | Файл идентичности, создаётся при первом запуске. |
| `--peers FILE` | Использовать локальный список пиров вместо публичного. |
| `--no-public` | Не загружать публичный список пиров. Только `--peers` и LAN. |
| `--target N` | Сколько исходящих пиров держать (1..=32, по умолчанию 3). |
| `--allow KEY` | Разрешить ключу оверлея пользоваться проброской, ping и страницей. Можно несколько раз. |
| `--forward PORTS` | Открыть локальные TCP-порты через Yggdrasil, например `22,2222:22`. До 16 портов. |
| `--api ADDR` | Сервер статуса с дашбордом и `/api/stats`. Без аутентификации: привязывайте к 127.0.0.1. |
| `--html FILE` | Заменить страницу по умолчанию на порту оверлея 80. |
| `--ping ADDR` | Раз в секунду посылать echo-запрос и печатать время ответа. |
| `--quality-interval SECS` | Как часто перепроверять глобальную сеть (по умолчанию 300). |
| `--lan-upstream` | Поиск пиров yggdrasil-go в LAN через IPv6 link-local (`ff02::114:9001`), подключение по TLS. Нужна сборка с `upstream-tls`. |
| `--lan-target N` | Исходящие слоты, отведённые под пиров из LAN (по умолчанию `--target`). |
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
- TLS берётся из системного OpenSSL, поэтому важна версия OpenSSL на устройстве. Сборка с TLS
  только подключается к пирам и ничего не слушает.

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

Дашборд открывается в браузере телефона по адресу `http://127.0.0.1:8080/`, данные в
Termux — по `http://127.0.0.1:8080/api/stats`. У API нет аутентификации, его нельзя
привязывать к `0.0.0.0` в общей сети.

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

Ограничения встроенного TCP: одно соединение на порт клиента, нет управления перегрузкой,
нет TIME_WAIT. Подходит для интерактивных сессий, а не для больших передач. Проброс порта
80 оверлея отключает страницу статуса.

### Сборка для роутера (OpenWrt)

Используйте musl-цель, чтобы получить статический бинарник без libc на роутере. Архитектуру
процессора узнайте командой `uname -m` на роутере.

```sh
rustup target add aarch64-unknown-linux-musl
cargo build --release --bin tcp_node --target aarch64-unknown-linux-musl
scp target/aarch64-unknown-linux-musl/release/tcp_node root@192.168.1.1:/usr/bin/
```

Службу устанавливайте через `openwrt/tcp_node.init`. Сборка с TLS (`--features
upstream-tls`) требует OpenSSL, собранный под архитектуру роутера, поэтому кросс-сборка
потребует дополнительной настройки. Обычная сборка ничего не требует.

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
  TLS-реализации на rustls; сборка на native-tls ещё не проверялась.
- Открыто: соединение только с LAN-пирами (без интернет-пиров) сообщалось как падающее через
  2–3 секунды. Причина пока не подтверждена.
- Не проверено: согласование TLS 1.2 с yggdrasil-go. Режим анонса удалён из кода.

### Лицензия

MPL-2.0
