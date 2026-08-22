#!/usr/bin/env python3
"""transparent_relay.py -- прозрачный MTProto-релей БЕЗ секрета.

Идея (предложена в ходе разбора): tg-ws-proxy не важно, к какому IP
СЧИТАЕТ, что подключается клиент -- важно только то, что декодируется из
64-байтного init-пакета (proto_tag/dc_idx), а дальше вся релейная
машинерия (пул WebSocket-соединений к рабочему `149.154.167.220`,
Cloudflare-фронтинг/worker fallback -- см. `relay/vendor/`, скопировано
из Flowseal/tg-ws-proxy, MIT) сама разбирается, как реально достучаться
до Telegram, независимо от того, какой конкретно IP/DC клиент имел в
виду. Единственное, что у оригинала ЖЁСТКО завязано на ручную настройку
клиента -- "коннектор" верхнего уровня: расшифровка клиентского init
требует MTProxy-секрет (`SHA256(prekey + secret)`, см.
`tg_ws_proxy.py::_try_handshake`/`_build_crypto_ctx`), и клиент обязан
знать этот секрет заранее.

Этот файл меняет ТОЛЬКО коннектор: он декодирует входящий init как
СТАНДАРТНЫЙ obfuscated2 БЕЗ секрета -- сырой ключ прямо из тела пакета
(`prekey`/`iv`), ровно ту же семантику, что использует настоящий,
НЕпроксированный клиент Telegram при прямом подключении (идентична
`prober/proto.py::build_obfuscated_init` в этом же репозитории, только в
обратную сторону -- декодирование, не конструирование). Вся остальная
relay-логика (`ws_pool`, `do_fallback`, `bridge_ws_reencrypt`) -- БЕЗ
изменений, взята из `relay/vendor/`.

Результат: клиенту (настоящему, немодифицированному Telegram Desktop/
mobile) вообще не нужно ничего знать о существовании этого релея --
достаточно, чтобы iptables REDIRECT прозрачно перехватил его исходящее
соединение к известным IP Telegram (порт 443) и подсунул сюда. См.
README.md "Прозрачный релей" за инструкцией по REDIRECT-правилам.

ВАЖНО: раз секрета нет -- нет и контроля доступа. Слушать этот процесс
следует ТОЛЬКО на loopback/внутреннем интерфейсе, куда трафик приходит
исключительно через iptables REDIRECT с самого NETH-4 (или из
VLESS-туннеля, уже терминированного на этой же машине) -- не выставлять
наружу напрямую.
"""
from __future__ import annotations

import asyncio
import logging
import os
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Set

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))                  # relay/vendor/*
sys.path.insert(0, str(_HERE.parent / 'prober'))  # proto.py

from vendor.utils import (  # noqa: E402
    HANDSHAKE_LEN, SKIP_LEN, PREKEY_LEN, KEY_LEN, IV_LEN, ZERO_64,
    PROTO_TAG_POS, DC_IDX_POS,
    PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE,
    PROTO_ABRIDGED_INT, PROTO_INTERMEDIATE_INT, PROTO_PADDED_INTERMEDIATE_INT,
)
from vendor.stats import stats  # noqa: E402
from vendor.config import proxy_config  # noqa: E402
from vendor.bridge import (  # noqa: E402
    CryptoCtx, MsgSplitter, do_fallback, bridge_ws_reencrypt,
)
from vendor.raw_websocket import RawWebSocket, WsHandshakeError, set_sock_opts  # noqa: E402
from vendor.pool import ws_pool  # noqa: E402
from vendor.utils import ws_domains  # noqa: E402
from vendor._aes import Cipher, algorithms, modes  # noqa: E402
from proto import build_obfuscated_init  # noqa: E402  (собственный код этого репо)

log = logging.getLogger('tg-transparent-relay')

IP_FAIL_COOLDOWN = 3600.0
DC_FAIL_COOLDOWN = 60.0
WS_FAIL_TIMEOUT = 2.0
ws_blacklist: Set[str] = set()
dc_fail_until: Dict[str, float] = {}
ip_fail_until: Dict[str, float] = {}

# Живой случай на NETH-4: браузер (или несколько устройств за одним
# VLESS-туннелем -- отсюда всё видно как один и тот же клиентский IP,
# не различить) открыл ~20 000 passthrough-соединений к
# web.telegram.org МЕНЬШЕ ЧЕМ ЗА МИНУТУ -- похоже на цикл
# переподключений без backoff, возможно раскрученный самой низкой
# задержкой локального релея (обычный round-trip до Telegram занял бы
# заметно дольше, чем локальный passthrough). Причину со стороны чужого
# JS-клиента диагностировать нечем -- вместо этого защищаем сам релей:
# жёсткий потолок одновременных passthrough-соединений (жди своей
# очереди/новые лишние сразу закрываются) + таймаут на простаивающие
# без данных. Не влияет на MTProto-путь (он использует пул tg-ws-proxy,
# отдельный лимит там уже есть).
PASSTHROUGH_MAX_CONCURRENT = 800
PASSTHROUGH_IDLE_TIMEOUT = 90.0
_passthrough_semaphore = asyncio.Semaphore(PASSTHROUGH_MAX_CONCURRENT)

# Живой случай на NETH-4: web.telegram.org (149.154.167.99) заблокирован
# на границе сети целиком на уровне SYN (null-route) -- эмпирически
# подтверждено (curl без REDIRECT: полный таймаут, тот же итог, что и у
# самого релея при прямом подключении). Никакой --lua-desync=/сплит
# ClientHello тут не поможет -- манглить нечего, пакет наружу не уходит.
# Единственный найденный обходной путь: открыть TCP до настоящего IP
# Telegram НЕ с самого NETH-4, а из сети Cloudflare (свой исходящий
# маршрут, вероятно с ней у Telegram связность чистая) -- см.
# cf_worker/worker.js, использует `cloudflare:sockets`. NETH-4 достаёт
# до Worker обычным WebSocket через Cloudflare edge (не заблокирован --
# домен *.workers.dev на облаке Cloudflare, тот же принцип, что и
# cfproxy_worker_domains у оригинального tg-ws-proxy для MTProto-пути).
# Опционально: если не настроено (пусто) -- поведение как раньше,
# passthrough просто не удаётся и разрывается.
CF_WORKER_HOST = os.environ.get('ZTG_CF_WORKER_HOST', '')
CF_WORKER_SECRET = os.environ.get('ZTG_CF_WORKER_SECRET', '')
CF_WORKER_TIMEOUT = 8.0


def _decode_direct_client_init(handshake: bytes):
    """Декодирует 64-байтный init КАК НАСТОЯЩИЙ прямой клиент -- ключ
    сырой (без SHA256+secret), позиции те же, что у
    `prober/proto.py::build_obfuscated_init` (независимо сверено с
    оригиналом при разборе -- см. докстринг файла). Возвращает
    (dc_id, is_media, proto_tag, client_dec_prekey_iv) или None, если
    пакет не похож на валидный obfuscated2 init (proto_tag не
    распознан) -- НЕ "неверный секрет", секрета тут нет в принципе."""
    dec_prekey_and_iv = handshake[SKIP_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN]
    dec_key = dec_prekey_and_iv[:PREKEY_LEN]
    dec_iv = dec_prekey_and_iv[PREKEY_LEN:]

    decryptor = Cipher(algorithms.AES(dec_key), modes.CTR(dec_iv)).encryptor()
    decrypted = decryptor.update(handshake)

    proto_tag = decrypted[PROTO_TAG_POS:PROTO_TAG_POS + 4]
    if proto_tag not in (PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE):
        return None

    dc_idx = int.from_bytes(decrypted[DC_IDX_POS:DC_IDX_POS + 2], 'little', signed=True)
    dc_id = abs(dc_idx)
    is_media = dc_idx < 0
    return dc_id, is_media, proto_tag, dec_prekey_and_iv


SO_ORIGINAL_DST = 80  # linux/netfilter_ipv4.h -- получить РЕАЛЬНЫЙ адрес
                       # назначения на сокете, перехваченном iptables
                       # REDIRECT (ядро помнит его в conntrack)


def _get_original_dst(writer: asyncio.StreamWriter):
    """Реальный адрес назначения соединения ДО REDIRECT -- нужен для
    прозрачного passthrough не-MTProto трафика (см.
    `_passthrough_plain_tcp`). Возвращает (ip, port) или None, если
    сокет не был перехвачен REDIRECT (например, при прямом подключении
    к порту релея вручную для отладки)."""
    sock = writer.get_extra_info('socket')
    if sock is None:
        return None
    try:
        raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    except OSError:
        return None
    port, = struct.unpack('!H', raw[2:4])
    ip = socket.inet_ntoa(raw[4:8])
    return ip, port


async def _passthrough_plain_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                  already_read: bytes, label: str) -> None:
    """Трафик, не похожий на obfuscated2 MTProto -- скорее всего
    настоящий браузерный HTTPS (например, к web.telegram.org или любому
    другому сайту, чей IP попал в тот же CIDR, что и MTProto-DC --
    так и оказалось на практике: браузер до web.telegram.org ловил
    REDIRECT и обрывался релеем, который умел разбирать только
    MTProto). Восстанавливаем ОРИГИНАЛЬНЫЙ адрес назначения (до
    REDIRECT, через SO_ORIGINAL_DST) и прозрачно проксируем как есть,
    байт в байт, без какой-либо расшифровки -- реле тут просто дырка в
    проводе для всего, что не MTProto."""
    dst = _get_original_dst(writer)
    if dst is None:
        log.warning("[%s] не похоже на MTProto и не удалось узнать оригинальный "
                    "адрес назначения -- закрываю", label)
        return

    dst_ip, dst_port = dst

    # Потолок на ОБЩЕЕ число одновременных passthrough-соединений --
    # см. комментарий у PASSTHROUGH_MAX_CONCURRENT выше. non-blocking
    # acquire: если лимит уже выбран, не ставим в очередь (клиент и так
    # в цикле переподключений -- очередь только продлит его), а сразу
    # закрываем, чтобы клиент немедленно получил явный отказ вместо
    # зависшего соединения.
    if _passthrough_semaphore.locked():
        log.warning("[%s] passthrough к %s:%d отклонён -- лимит одновременных "
                    "соединений (%d) исчерпан", label, dst_ip, dst_port,
                    PASSTHROUGH_MAX_CONCURRENT)
        return

    async with _passthrough_semaphore:
        log.info("[%s] не MTProto -- прозрачный TCP passthrough к %s:%d "
                 "(настоящий адрес назначения до REDIRECT)", label, dst_ip, dst_port)

        try:
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection(dst_ip, dst_port), timeout=8)
        except Exception as exc:
            log.warning("[%s] passthrough к %s:%d не удался: %s", label, dst_ip, dst_port, exc)
            ws = await _connect_via_cf_worker(dst_ip, dst_port, label)
            if ws is None:
                return
            try:
                await _relay_over_cf_worker(reader, writer, ws, already_read, label)
            finally:
                try:
                    await ws.close()
                except Exception:
                    pass
                try:
                    writer.close()
                except Exception:
                    pass
            return

        try:
            # Живой случай на NETH-4: curl честно прошёл TCP до
            # 149.154.167.99, отправил настоящий TLS ClientHello (SNI
            # web.telegram.org) -- и тут же обрыв, ни байта в ответ. Не
            # IP-блокировка (голый TCP без TLS проходит) -- SNI-based
            # DPI, тот же класс блокировки, что уже успешно обходит
            # RKN_TLS профиль zapret2 через разбиение ClientHello на
            # несколько TCP-сегментов (multisplit/hostfakesplit).
            # Проблема именно в том, что мой REDIRECT (nat OUTPUT)
            # перехватывает пакет РАНЬШЕ, чем zapret2 успевает его
            # сманглить (mangle POSTROUTING идёт позже в netfilter для
            # локально созданных пакетов) -- значит для TLS-трафика
            # нужно применить ту же идею здесь самим: не слать
            # ClientHello одним TCP-сегментом.
            sock = up_writer.get_extra_info('socket')
            if sock is not None:
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass

            if already_read[:1] == b'\x16' and len(already_read) > 3:
                # TLS handshake record -- шлём первые байты отдельными
                # TCP-сегментами (TCP_NODELAY уже выставлен, иначе
                # Nagle склеит их обратно в один пакет). Позиции условны
                # (нет разбора TLS/поиска реального смещения SNI, в
                # отличие от zapret2's pos=sniext+N) -- просто ломаем
                # DPI, ожидающую ClientHello целиком в одном пакете.
                for chunk in (already_read[:1], already_read[1:3], already_read[3:]):
                    up_writer.write(chunk)
                    await up_writer.drain()
            else:
                up_writer.write(already_read)
                await up_writer.drain()

            async def _pipe(src, dst_w):
                try:
                    while True:
                        chunk = await asyncio.wait_for(
                            src.read(65536), timeout=PASSTHROUGH_IDLE_TIMEOUT)
                        if not chunk:
                            break
                        dst_w.write(chunk)
                        await dst_w.drain()
                except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError,
                        OSError, asyncio.TimeoutError):
                    pass

            # asyncio.wait(FIRST_COMPLETED), не gather -- если ждать ОБЕ
            # стороны до конца, полуоткрытое соединение (одна сторона
            # молча перестала слать данные, не закрывая TCP) держит оба
            # сокета открытыми НАВСЕГДА. Как только закрылась (или
            # простояла PASSTHROUGH_IDLE_TIMEOUT без данных) любая
            # сторона -- рвём вторую сами, не дожидаясь.
            up_task = asyncio.ensure_future(_pipe(reader, up_writer))
            down_task = asyncio.ensure_future(_pipe(up_reader, writer))
            try:
                await asyncio.wait(
                    {up_task, down_task}, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for t in (up_task, down_task):
                    if not t.done():
                        t.cancel()
                await asyncio.gather(up_task, down_task, return_exceptions=True)
        finally:
            for w in (up_writer, writer):
                try:
                    w.close()
                except Exception:
                    pass


async def _connect_via_cf_worker(dst_ip: str, dst_port: int, label: str) -> Optional[RawWebSocket]:
    """Открыть туннель до dst_ip:dst_port через Cloudflare Worker (см.
    cf_worker/worker.js) вместо прямого TCP с самого NETH-4 -- см.
    комментарий у CF_WORKER_HOST выше. Возвращает None, если фича не
    настроена (пустой host/secret) или сам Worker недоступен/отказал --
    вызывающий код в этом случае просто закрывает клиентское соединение,
    как и раньше без этой фичи."""
    if not CF_WORKER_HOST or not CF_WORKER_SECRET:
        return None
    path = f"/?dst={dst_ip}&port={dst_port}&secret={CF_WORKER_SECRET}"
    try:
        ws = await RawWebSocket.connect(
            CF_WORKER_HOST, CF_WORKER_HOST, timeout=CF_WORKER_TIMEOUT, path=path)
    except Exception as exc:
        log.warning("[%s] Cloudflare Worker fallback к %s:%d тоже не удался: %s",
                    label, dst_ip, dst_port, exc)
        return None
    log.info("[%s] прямой TCP к %s:%d не удался -- ушли через Cloudflare Worker %s",
              label, dst_ip, dst_port, CF_WORKER_HOST)
    return ws


async def _relay_over_cf_worker(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                 ws: RawWebSocket, already_read: bytes, label: str) -> None:
    """Та же передача байт в обе стороны, что в `_passthrough_plain_tcp`,
    только "вверх" -- не сырой TCP-сокет, а WS-туннель до Worker'а
    (фреймы вместо голых байт, содержимое кадров не трогаем -- Worker
    сам открывает настоящий TCP до Telegram и просто гоняет байты через
    WebSocket, см. worker.js). Разбиение ClientHello тут не нужно: путь
    NETH-4->Cloudflare идёт внутри TLS до самого Worker'а, а
    Cloudflare->Telegram -- отдельный, необлачный DPI сегмент вообще не
    видит."""
    try:
        await ws.send(already_read)
    except Exception as exc:
        log.warning("[%s] CF Worker: не удалось отправить первый чанк: %s", label, exc)
        return

    async def _up():
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=PASSTHROUGH_IDLE_TIMEOUT)
                if not chunk:
                    break
                await ws.send(chunk)
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError,
                OSError, asyncio.TimeoutError, ConnectionError):
            pass

    async def _down():
        try:
            while True:
                chunk = await asyncio.wait_for(ws.recv(), timeout=PASSTHROUGH_IDLE_TIMEOUT)
                if chunk is None:
                    break
                writer.write(chunk)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, OSError, asyncio.TimeoutError, ConnectionError):
            pass

    # Тот же приём, что в _passthrough_plain_tcp: ждать FIRST_COMPLETED,
    # не gather -- иначе полуоткрытая сторона держит обе задачи вечно.
    up_task = asyncio.ensure_future(_up())
    down_task = asyncio.ensure_future(_down())
    try:
        await asyncio.wait({up_task, down_task}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in (up_task, down_task):
            if not t.done():
                t.cancel()
        await asyncio.gather(up_task, down_task, return_exceptions=True)


def _build_crypto_ctx_direct(client_dec_prekey_iv: bytes, relay_init: bytes) -> CryptoCtx:
    """То же самое, что `tg_ws_proxy.py::_build_crypto_ctx`, но без
    подмешивания секрета в ключи клиентского направления -- см.
    докстринг файла. Релейная (к Telegram) сторона и так была без
    секрета в оригинале ("standard obfuscation, no secret hash, raw
    key") -- тут та же формула применена и к клиентской стороне."""
    clt_dec_key = client_dec_prekey_iv[:PREKEY_LEN]
    clt_dec_iv = client_dec_prekey_iv[PREKEY_LEN:]

    clt_enc_prekey_iv = client_dec_prekey_iv[::-1]
    clt_enc_key = clt_enc_prekey_iv[:PREKEY_LEN]
    clt_enc_iv = clt_enc_prekey_iv[PREKEY_LEN:]

    clt_decryptor = Cipher(algorithms.AES(clt_dec_key), modes.CTR(clt_dec_iv)).encryptor()
    clt_encryptor = Cipher(algorithms.AES(clt_enc_key), modes.CTR(clt_enc_iv)).encryptor()
    clt_decryptor.update(ZERO_64)  # прокрутить состояние мимо самого init-пакета

    relay_enc_key = relay_init[SKIP_LEN:SKIP_LEN + PREKEY_LEN]
    relay_enc_iv = relay_init[SKIP_LEN + PREKEY_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN]
    relay_dec_prekey_iv = relay_init[SKIP_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN][::-1]
    relay_dec_key = relay_dec_prekey_iv[:KEY_LEN]
    relay_dec_iv = relay_dec_prekey_iv[KEY_LEN:]

    tg_encryptor = Cipher(algorithms.AES(relay_enc_key), modes.CTR(relay_enc_iv)).encryptor()
    tg_decryptor = Cipher(algorithms.AES(relay_dec_key), modes.CTR(relay_dec_iv)).encryptor()
    tg_encryptor.update(ZERO_64)

    return CryptoCtx(clt_decryptor, clt_encryptor, tg_encryptor, tg_decryptor)


async def _handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    stats.connections_total += 1
    stats.connections_active += 1
    peer = writer.get_extra_info('peername')
    label = f"{peer[0]}:{peer[1]}" if peer else "?"

    set_sock_opts(writer.transport, proxy_config.buffer_size)

    try:
        try:
            handshake = await asyncio.wait_for(reader.readexactly(HANDSHAKE_LEN), timeout=10)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            log.debug("[%s] disconnected before handshake", label)
            return

        result = _decode_direct_client_init(handshake)
        if result is None:
            stats.connections_bad += 1
            await _passthrough_plain_tcp(reader, writer, handshake, label)
            return

        dc, is_media, proto_tag, client_dec_prekey_iv = result

        is_test_dc = proxy_config.force_test_dc or dc >= 10000
        if dc >= 10000:
            log.info("[%s] test DC%d -> DC%d", label, dc, dc - 10000)
            dc -= 10000

        if proto_tag == PROTO_TAG_ABRIDGED:
            proto_int = PROTO_ABRIDGED_INT
        elif proto_tag == PROTO_TAG_INTERMEDIATE:
            proto_int = PROTO_INTERMEDIATE_INT
        else:
            proto_int = PROTO_PADDED_INTERMEDIATE_INT

        dc_idx = -dc if is_media else dc
        log.info("[%s] прямой клиент: DC%d%s proto=0x%08X (без секрета)",
                  label, dc, ' media' if is_media else '', proto_int)

        relay_init = build_obfuscated_init(dc_idx, proto_tag)
        ctx = _build_crypto_ctx_direct(client_dec_prekey_iv, relay_init)

        dc_key = f'{dc}{"t" if is_test_dc else ""}{"m" if is_media else ""}'
        media_tag = " media" if is_media else ""
        now = time.monotonic()
        target = proxy_config.dc_redirects.get(dc)
        is_any_cf_fallback = proxy_config.fallback_cfproxy or proxy_config.cfproxy_worker_domains

        if (dc not in proxy_config.dc_redirects
                or dc_key in ws_blacklist
                or (now < ip_fail_until.get(target, 0) and is_any_cf_fallback)):
            splitter = None
            try:
                splitter = MsgSplitter(relay_init, proto_int)
            except Exception:
                pass
            ok = await do_fallback(
                reader, writer, relay_init, label,
                dc, is_test_dc, is_media, media_tag,
                ctx, splitter=splitter)
            if not ok:
                log.warning("[%s] DC%d%s no fallback available", label, dc, media_tag)
            return

        ws_timeout = WS_FAIL_TIMEOUT if now < dc_fail_until.get(dc_key, 0) else 5.0
        domains = ws_domains(dc, is_media)
        ws = None
        ws_failed_redirect = False
        ws_timed_out = False
        all_redirects = True

        allow_pool_refill = now >= ip_fail_until.get(target, 0)
        ws = await ws_pool.get(dc, is_media, target, domains,
                                allow_refill=allow_pool_refill) if not is_test_dc else None
        if ws:
            log.info("[%s] DC%d%s -> pool hit via %s", label, dc, media_tag, target)
        else:
            for domain in domains:
                try:
                    ws = await RawWebSocket.connect(target, domain, timeout=ws_timeout, path='/apiws')
                    all_redirects = False
                    break
                except WsHandshakeError as exc:
                    stats.ws_errors += 1
                    if exc.is_redirect:
                        ws_failed_redirect = True
                        continue
                    all_redirects = False
                except asyncio.TimeoutError:
                    stats.ws_errors += 1
                    ws_timed_out = True
                    break
                except Exception:
                    stats.ws_errors += 1
                    all_redirects = False

        if ws is None:
            if ws_timed_out:
                ip_fail_until[target] = now + IP_FAIL_COOLDOWN
            if ws_failed_redirect and all_redirects:
                ws_blacklist.add(dc_key)
            else:
                dc_fail_until[dc_key] = now + DC_FAIL_COOLDOWN

            splitter_fb = None
            try:
                splitter_fb = MsgSplitter(relay_init, proto_int)
            except Exception:
                pass
            ok = await do_fallback(reader, writer, relay_init, label,
                                    dc, is_test_dc, is_media, media_tag,
                                    ctx, splitter=splitter_fb)
            if ok:
                log.info("[%s] DC%d%s fallback closed", label, dc, media_tag)
            return

        dc_fail_until.pop(dc_key, None)
        ip_fail_until.pop(target, None)
        ws_pool.report_success(dc, is_media)
        stats.connections_ws += 1

        splitter = None
        try:
            splitter = MsgSplitter(relay_init, proto_int)
        except Exception:
            pass

        await ws.send(relay_init)
        await bridge_ws_reencrypt(reader, writer, ws, label, ctx,
                                   dc=dc, is_media=is_media, splitter=splitter)

    except asyncio.CancelledError:
        raise
    except (ConnectionResetError, asyncio.IncompleteReadError):
        log.debug("[%s] client disconnected", label)
    except Exception as exc:
        log.error("[%s] unexpected: %s", label, exc, exc_info=True)
    finally:
        stats.connections_active -= 1
        try:
            writer.close()
        except Exception:
            pass


async def main_async(host: str, port: int, dc_ip: Dict[int, str]) -> None:
    from vendor.config import start_cfproxy_domain_refresh

    proxy_config.dc_redirects = dc_ip
    proxy_config.fallback_cfproxy = True
    proxy_config.secret = os.urandom(16).hex()  # не используется как секрет клиента -- только релейной стороне нужен любой валидный hex

    start_cfproxy_domain_refresh()
    await ws_pool.warmup() if hasattr(ws_pool, 'warmup') else None

    server = await asyncio.start_server(_handle_client, host, port)
    addrs = ', '.join(str(s.getsockname()) for s in server.sockets)
    log.info("Прозрачный релей (без секрета) слушает на %s", addrs)
    log.info("Ожидает трафик, перенаправленный iptables REDIRECT -- см. README.md")
    async with server:
        await server.serve_forever()


# Живой случай на NETH-4, 2026-08-22: только DC 2/4 имели прямой быстрый
# путь по умолчанию -- любой другой DC (клиент попадает на DC по номеру
# СВОЕГО аккаунта при регистрации, не зависит от платформы/устройства)
# проваливался в do_fallback -> CF proxy fallback -> все 20 доменов из
# Flowseal/tg-ws-proxy (vendor/config.py) резолвились в
# "No address associated with hostname" (gaierror -5, домены есть в DNS,
# но без A/AAAA -- сами домены умерли у апстрима, не наша DNS-проблема).
# Наблюдалось как "на iPhone работает, на Android нет" -- совпадение: у
# конкретных Android-аккаунтов DC оказался не 2/4. 149.154.167.220 --
# это официальный WebSocket-шлюз Telegram, ОДИН И ТОТ ЖЕ IP для любого
# DC (разница только в Host-домене, см. ws_domains() в vendor/utils.py),
# так что расширение на все 5 настоящих DC ничего не удорожает и убирает
# саму нужду в fallback для любого нормального (не "мусорного" test-DC,
# см. декодер в _decode_direct_client_init) соединения.
DEFAULT_DC_IP = {dc: '149.154.167.220' for dc in (1, 2, 3, 4, 5)}


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--host', default='127.0.0.1', help='Слушать здесь (default 127.0.0.1 -- см. предупреждение в докстринге)')
    ap.add_argument('--port', type=int, default=8447)
    ap.add_argument('--dc-ip', action='append', default=None, metavar='DC:IP',
                     help='Переопределить быстрый путь для DC (default: все 5 DC через '
                          '149.154.167.220 -- см. комментарий у DEFAULT_DC_IP)')
    ap.add_argument('--cf-worker-host', default=None, metavar='HOST',
                     help='Домен задеплоенного cf_worker/worker.js (например, '
                          'zenith-tg-relay.<subdomain>.workers.dev) -- fallback для '
                          'passthrough-трафика (web.telegram.org и т.п.), когда прямой '
                          'TCP с этой машины заблокирован. По умолчанию берётся из '
                          'ZTG_CF_WORKER_HOST, пусто = фича выключена.')
    ap.add_argument('--cf-worker-secret', default=None, metavar='SECRET',
                     help='Секрет, заданный в Worker через `wrangler secret put RELAY_SECRET` '
                          '-- по умолчанию берётся из ZTG_CF_WORKER_SECRET.')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s  %(levelname)-5s  %(message)s')

    if args.cf_worker_host:
        global CF_WORKER_HOST
        CF_WORKER_HOST = args.cf_worker_host
    if args.cf_worker_secret:
        global CF_WORKER_SECRET
        CF_WORKER_SECRET = args.cf_worker_secret
    if CF_WORKER_HOST and CF_WORKER_SECRET:
        log.info("Cloudflare Worker fallback включён: %s", CF_WORKER_HOST)

    if args.dc_ip:
        from vendor.config import parse_dc_ip_list
        dc_ip = parse_dc_ip_list(args.dc_ip)
    else:
        dc_ip = dict(DEFAULT_DC_IP)

    try:
        asyncio.run(main_async(args.host, args.port, dc_ip))
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
