# yggdrasil-lite

## Форк

Этот репозиторий — личный форк
[cleverfox/yggdrasil-lite](https://github.com/cleverfox/yggdrasil-lite)
(оригинальный проект; MPL-2.0). Может содержать локальные изменения,
эксперименты и исправления, которых нет в апстриме.

- Апстрим: https://github.com/cleverfox/yggdrasil-lite.git
- Ориджин: https://github.com/vasil646srb/yggdrasil-lite.git

---

## tcp_node — готовый узел для Unix-хостов

`tcp_node` (`src/bin/tcp_node.rs`) — исполняемый yggdrasil-lite-узел для
**Termux, Linux и OpenWrt**. Подключается к публичным TCP-пирам, работает как
leaf-узел, отдаёт статус через HTTP и умеет пробрасывать TCP-порты для доступа
по Yggdrasil. Зависит только от `rand` и `heapless` — без TLS и C-библиотек,
компактный статический бинарник.

### Флаги

| Флаг | Описание |
|------|----------|
| `--key FILE` | Файл ключа (64 hex). Создаётся при первом запуске; определяет адрес узла — держите в секрете |
| `--peers FILE` | JSON-список публичных пиров (`publicnodes.json`) |
| `--target N` | Число исходящих слотов (1..32, по умолчанию 3) |
| `--allow KEY` | Разрешённый публичный ключ (повторяемый). Прочие датаграммы отбрасываются |
| `--api ADDR` | HTTP-статус-сервер (дашборд + JSON) |
| `--html FILE` | Своя HTML-разметка статусной страницы |
| `--forward PORTS` | Проброс TCP-портов (до 16) |
| `--quality-interval SECS` | Интервал замера качества пиров (по умолчанию 300) |
| `--ping IPV6` | Замер RTT до узла |
| `--send IPV6 MSG` | Разовая отправка датаграммы |

### Базовый запуск (Termux)

```sh
pkg install rust git curl
git clone https://github.com/vasil646srb/yggdrasil-lite && cd yggdrasil-lite
cargo build --release --bin tcp_node

curl -fsSL -o ~/peers.json https://publicpeers.neilalexander.dev/publicnodes.json
./target/release/tcp_node --key ~/ygg.key --peers ~/peers.json \
    --target 3 --api 127.0.0.1:8080
```

Дашборд: `http://127.0.0.1:8080/` · статистика: `curl http://127.0.0.1:8080/api/stats`.
API слушает только 127.0.0.1 без аутентификации — не выносите на 0.0.0.0.

Держать узел живым с погасшим экраном: `termux-wake-lock` и отключите оптимизацию
батареи для Termux.

## Проброс TCP-портов (SSH к роутеру или телефону)

`tcp_node --forward` делает TCP-порты этого хоста доступными по Yggdrasil. Порт
указывается на старте. Подключиться могут только ключи из `--allow`, и открыты
только перечисленные порты.

### Формат `--forward`

`--forward` принимает разделённый запятыми список портов (до 16), флаг можно
повторять. Поддерживаются два формата элемента:

- `PORT` — оверлейный порт совпадает с локальным. Пример: `--forward 22`
  открывает порт 22 в оверлее и маппит его на 127.0.0.1:22;
- `OVERLAY:LOCAL` — явный маппинг: оверлейный порт `OVERLAY` ведёт на
  локальный порт `LOCAL`. Пример: `--forward 2222:22` открывает оверлейный
  порт 2222 → 127.0.0.1:22.

Оба формата можно смешивать в одном списке. Пример:

```sh
tcp_node --key ~/ygg.key --peers ~/peers.json \
    --allow <client-public-key> --forward 22,8080,9000:9001
```

Что это открывает:

- `22` — оверлейный 22 → 127.0.0.1:22 (совпадающий номер);
- `8080` — оверлейный 8080 → 127.0.0.1:8080 (совпадающий номер);
- `9000:9001` — оверлейный 9000 → 127.0.0.1:9001 (явный маппинг).

`--forward` можно указывать несколько раз; порты из всех вхождений объединяются.
Поддерживается до 16 портов суммарно.

### Примеры по ролям

```sh
# OpenWrt router: dropbear SSH слушает порт 22
tcp_node --key /root/ygg.key --peers /root/peers.json \
    --allow <client-public-key> --forward 22

# Android (Termux): sshd слушает порт 8022
tcp_node --key ~/ygg.key --peers ~/peers.json \
    --allow <client-public-key> --forward 8022
```

Локальное соединение, которое не удалось открыть, сбрасывается в сторону клиента.
Клиент должен запускать полный стек Yggdrasil (yggdrasil-ng с TUN или yggstack
с SOCKS-прокси) и использовать разрешённый ключ. Например, с SOCKS-прокси
yggstack на 127.0.0.1:1080:

```sh
ssh -o ProxyCommand="nc -X 5 -x 127.0.0.1:1080 %h %p" -p 22 root@<device-address>
```

### Ограничения встроенного TCP

Для интерактивных сессий (SSH), не для больших передач: одно соединение на
клиентский порт, без congestion control и TIME_WAIT; при пробросе порта 80
статусная страница узла отключается.

### Проверка сети

```sh
tcp_node --key ~/ygg.key --peers ~/peers.json --ping <ipv6>       # RTT
tcp_node --key ~/ygg.key --peers ~/peers.json --send <ipv6> hello # тестовая датаграмма
```

### Сборка для роутера (мусл-статик)

```sh
rustup target add aarch64-unknown-linux-musl
cargo build --release --bin tcp_node --target aarch64-unknown-linux-musl
scp target/aarch64-unknown-linux-musl/release/tcp_node root@192.168.1.1:/usr/bin/
```

Сервис: `openwrt/tcp_node.init`.

---

## ESP32 (no_std)

Прошивки, соединяющие Yggdrasil с железом напрямую, без Unix-хоста. Требуют ночной
(ESP32-C6, RISC-V) или esp (Xtensa) тулчейн.

### Yggdrasil TCP-UART Bridge (`examples/esp32`)

Мостит TCP-соединения по Yggdrasil к аппаратному UART. Подключается к WiFi,
устанавливает TLS к пирам, слушает TCP/ICMPv6 на оверлейном IPv6.

```sh
cd examples/esp32
# ESP32-C6 (RISC-V)
cargo run --release --target riscv32imac-unknown-none-elf --features esp32c6
# ESP32 (Xtensa)
cargo +esp run --release --target xtensa-esp32-none-elf --features esp32 --no-default-features
```

При старте печатает свой IPv6; настройки WiFi/пиров — через web-UI на `http://192.168.4.1`
(AP `YggBridge`). Доступ с меша:

```sh
ping6 -x 127.0.0.1:1080 <esp-ipv6>          # через yggstack SOCKS5
nc -X 5 -x 127.0.0.1:1080 <esp-ipv6> 2000   # TCP→UART
```

### ESP32-Lite и ESP32-C6-IOT

В репозитории также присутствуют примеры `esp32-lite` (минимальный узел) и
`esp32c6-iot` (IoT-прошивка на C6). Собираются аналогично: выбор целевой прошивки
через Cargo feature и соответствующий nightly/esp тулчейн.

---

## О библиотеке (кратко)

`yggdrasil-lite` — минимальный yggdrasil/Ironwood-клиент для embedded: leaf-узел
(подключение к пирам, spanning tree, bloom-маршрутизация, сквозное шифрование
XSalsa20-Poly1305), без TUN и админ-API. Дизайн для `no_std`+`alloc` (ESP32),
работает и со `std`. Опциональная фича `transit` превращает узел в роутер.
Подробный API (модули `tree`, `bloom`, `pathfinder`, `session`, `wire`, `meta`,
`crypto`, `address`, `peer`) и примеры использования библиотеки — в исходном
[проекте](https://github.com/cleverfox/yggdrasil-lite).

## Лицензия

MPL-2.0
