# Zenith-TG

Прозрачный модуль доступа к Telegram для инфраструктуры z2r_autobench —
без ручной настройки MTProto-прокси в приложении, без модифицированных
клиентов, без десинка пакетов (не сработал в этом случае — см. ниже).

## Происхождение

Основан на [`Flowseal/tg-ws-proxy`](https://github.com/Flowseal/tg-ws-proxy)
(MIT). `relay/vendor/` — прямая копия его релейного слоя (пул
WebSocket-соединений к Telegram, Cloudflare-фронтинг/worker fallback,
балансировка доменов) без изменений, см.
`relay/vendor/LICENSE.tg-ws-proxy`. Не оформлено как формальный GitHub
fork (создавался независимо, не через кнопку Fork — задним числом эта
связь на GitHub не переключается) — вместо оригинального клиентского
"коннектора" `tg-ws-proxy` (требует MTProxy-секрет от клиента, см.
ниже) здесь используется собственный `relay/transparent_relay.py`,
плюс весь остальной модуль (`prober/`, `cidr/`, `zapret2/`, тесты) —
код этого репозитория, не из `tg-ws-proxy`.

## Итог расследования (коротко)

На реальном сервере (NETH-4) прямой доступ к Telegram оказался
заблокирован не по протоколу/сигнатуре (значит, `zapret2`/`nfqws2`
десинк не поможет в принципе — испробовано, подтверждено), а по
IP-блэклисту: несколько конкретных, широко известных IP Telegram-DC
(`149.154.175.50`, `149.154.167.51`, `149.154.175.100`, `149.154.167.91`,
`149.154.171.5`, `149.154.167.99`) заблокированы целиком на уровне
аплинка, а другой, менее известный IP той же подсети —
**`149.154.167.220`** — работает штатно. Голый TCP до него отвечает за
~0.2с.

[`Flowseal/tg-ws-proxy`](https://github.com/Flowseal/tg-ws-proxy) как
раз по умолчанию использует именно этот IP (плюс запасной путь через
Cloudflare-домены на случай, если и он окажется заблокирован) — поэтому
он и "просто работал", когда его протестировали как обычный
MTProto-прокси.

Проблема с исходным `tg-ws-proxy` — не связность, а то, что MTProxy как
протокол **обязывает клиента знать секрет** (секрет вшит в формулу
вывода ключа шифрования, `SHA256(prekey + secret)` — это не галочка
доступа, которую можно выключить, а часть математики). Значит ручная
настройка прокси в каждом приложении неизбежна, если использовать
`tg-ws-proxy` "как есть".

## Решение: `relay/transparent_relay.py`

Взяли у `tg-ws-proxy` (MIT, см. `relay/vendor/LICENSE.tg-ws-proxy`)
рабочую **релейную** часть как есть (пул WebSocket-соединений к
`.220`, Cloudflare-фронтинг/worker fallback — всё, что реально умеет
достучаться до Telegram) и заменили только **коннектор** — приёмный
слой, декодирующий входящий пакет клиента. Вместо
`SHA256(prekey + secret)` используется формула **настоящего прямого
клиента Telegram** (сырой ключ без секрета, тот же код, что и в
`prober/proto.py`). Результат: клиенту (обычному, немодифицированному
Telegram Desktop/mobile) вообще не нужно ничего настраивать — реле
принимает его как будто оно и есть Telegram, декодирует DC из
init-пакета и уже само решает, как реально до Telegram достучаться.

Прозрачность достигается `iptables REDIRECT`: исходящий TCP:443-трафик
к официальным подсетям Telegram молча заворачивается на локальный порт
релея — работает как для процессов на самом сервере, так и для
клиентов, туннелирующих трафик через этот сервер (Xray/VLESS-outbound
делает обычный локальный `connect()`, значит подпадает под ту же
`OUTPUT`-цепочку — проверено вживую).

Подтверждено сквозным тестом (`tests/test_transparent_relay_e2e.py`):
симулированный "прямой" клиент получает настоящий `resPQ` от Telegram
через релей — не только для DC, на которые указывает дефолтный
`.220`-редирект (DC2/DC4), но и для любого другого DC — релейная часть
сама подхватывает недостающие через Cloudflare-fallback.

## Состав

```
prober/
  proto.py            -- независимая реализация init-пакета
                          obfuscated-транспорта MTProto
  mtproto_probe.py     -- CLI-зонд DPI/IP-блокировки (baseline-диагностика)
cidr/
  fetch_telegram_cidr.sh  -- официальный список подсетей Telegram
  telegram_ipv4.txt       -- снапшот
relay/
  transparent_relay.py    -- прозрачный коннектор (без секрета)
  vendor/                 -- вендоренная relay-машинерия tg-ws-proxy (MIT)
  tg-transparent-relay.service -- systemd unit
  setup_redirect.sh        -- iptables REDIRECT apply/remove/status
zapret2/
  TG_MTPROTO.block.conf   -- ЧЕРНОВИК десинк-профиля -- НЕ СРАБОТАЛ на
                             реальном IP-блэклисте (см. strategies.md),
                             оставлен для случаев, когда блокировка
                             именно сигнатурная, а не по IP
  strategies.md
tests/
  test_proto.py                  -- юнит-тесты пакета (без сети)
  test_transparent_relay_e2e.py  -- сквозной тест (нужна сеть)
```

## Быстрый старт

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# Обновить список подсетей Telegram
bash cidr/fetch_telegram_cidr.sh

# Тесты
.venv/bin/python3 tests/test_proto.py
.venv/bin/python3 tests/test_transparent_relay_e2e.py   # нужна сеть

# Запуск релея вручную (для проверки перед systemd)
.venv/bin/python3 relay/transparent_relay.py --host 127.0.0.1 --port 8447 -v
```

## Развёртывание на сервере

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin tgrelay
chown -R tgrelay:tgrelay /opt/Zenith-TG

cp relay/tg-transparent-relay.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now tg-transparent-relay

# Прозрачный REDIRECT (нужен root, меняет iptables)
sudo bash relay/setup_redirect.sh apply
sudo bash relay/setup_redirect.sh status   # проверить, что правила встали
```

Откат: `sudo bash relay/setup_redirect.sh remove` + `systemctl disable --now tg-transparent-relay`.

**Слушать `transparent_relay.py` ТОЛЬКО на `127.0.0.1`** — без секрета
нет контроля доступа, трафик должен приходить исключительно через
локальный `REDIRECT`, не выставлять порт наружу напрямую.

## Что требует внимания при эксплуатации

- `149.154.167.220` (или найденный аналог) может сам попасть в
  блэклист в будущем — тогда `dc_redirects` в `transparent_relay.py`
  нужно будет обновить на новый рабочий IP; Cloudflare-fallback
  внутри `relay/vendor/` при этом продолжит работать как запасной путь.
- `cidr/telegram_ipv4.txt` устаревает — периодически перезапускать
  `fetch_telegram_cidr.sh` и переприменять `setup_redirect.sh apply`
  (идемпотентно добавит новые записи; для чистоты сначала `remove`,
  потом `apply`, если список сильно изменился).
- `zapret2/TG_MTPROTO.block.conf` — рабочий десинк-профиль ТАК И НЕ
  найден (блокировка на тестовом сервере оказалась IP-based, не
  сигнатурной) — черновик оставлен на случай, если у другого
  провайдера/сервера блокировка будет именно DPI-сигнатурной, тогда он
  может пригодиться после живой проверки синтаксиса операторов.
- **`setup_redirect.sh` ОБЯЗАН исключать собственный исходящий трафик
  relay** (`-m owner --uid-owner tgrelay -j RETURN` перед REDIRECT-
  правилами, уже в скрипте) — без этого relay заворачивает СВОИ ЖЕ
  попытки достучаться до Telegram сам на себя (self-loop через
  localhost). Живой случай на NETH-4: это давало ложное впечатление
  "IP доступен" (loopback всегда быстрый/надёжный), маскируя реальный
  таймаут — несколько часов отладки ушло, пока не сравнили `curl` с
  REDIRECT и без него напрямую. Если меняете `--user`/переименовываете
  системного пользователя relay — обязательно обновите и это правило.
- **`web.telegram.org` (браузерная версия) на NETH-4 не работает** —
  его реальный IP (`149.154.167.99`, тот же, что у `kws2.web.telegram.org`
  из `dc_redirects`) заблокирован так же, как исходные "боевые" IP
  Telegram-DC, и, в отличие от MTProto-пути, эквивалента `.220` для
  него не нашли (это не MTProto-релей с гибким выбором сервера, а
  прямой сайт — заменить не на что). `_passthrough_plain_tcp` честно
  пытается достучаться и получает таймаут. Приложение Telegram
  (Desktop/mobile) при этом работает нормально — обходной путь есть
  только для него.

## Лицензия

MIT. `relay/vendor/` содержит код Flowseal/tg-ws-proxy (тоже MIT, см.
`relay/vendor/LICENSE.tg-ws-proxy`), использован по условиям лицензии.
