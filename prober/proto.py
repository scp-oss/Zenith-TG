"""Конструирование init-пакета "obfuscated"-транспорта MTProto -- того
самого 64-байтного заголовка, который реальный клиент Telegram (Desktop,
без MTProxy) шлёт первым при установке TCP-соединения к DC, ЕСЛИ не
используется устаревший plaintext-abridged режим (`\\xef` + open-текст,
давно тривиально фингерпринтится и уже заблокирован DPI сам по себе --
тестировать его смысла нет).

Протокол публичный, независимо реализован в десятках open-source
проектов (python-telethon, mtprotoproxy, оригинальный MTProxy, и т.д.).
Байтовая раскладка и правила избегания зарезервированных значений ниже
СВЕРЕНЫ с рабочей, продовой реализацией Flowseal/tg-ws-proxy (MIT,
proxy/utils.py + proxy/tg_ws_proxy.py::_generate_relay_init) -- то есть
кодом, который прямо сейчас реально ретранслирует живые MTProto-сессии
через настоящие DC Telegram, а значит эти байты гарантированно валидны
для реального сервера. Реализация здесь независимая (другая задача --
не ретрансляция чужой сессии, а разовый зонд DPI-выживаемости), но число
в число совпадает по смыслу с проверенным источником.

zapret2/nfqws2 матчит эту связку (--filter-tcp=443,80 --ipset=<CIDR
Telegram> --payload=unknown) и применяет --lua-desync= к ИМЕННО такому
пакету -- см. zapret2/TG_MTPROTO.block.conf.
"""
from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HANDSHAKE_LEN = 64
SKIP_LEN = 8
PREKEY_LEN = 32
IV_LEN = 16
PROTO_TAG_POS = 56
DC_IDX_POS = 60

PROTO_TAG_ABRIDGED = b'\xef\xef\xef\xef'
PROTO_TAG_INTERMEDIATE = b'\xee\xee\xee\xee'
PROTO_TAG_PADDED_INTERMEDIATE = b'\xdd\xdd\xdd\xdd'

# rnd[0] не должен быть 0xEF -- это первый байт plaintext-abridged
# режима, сервер (и DPI) могут разобрать пакет как ЕГО, а не как
# obfuscated init.
RESERVED_FIRST_BYTES = frozenset({0xEF})

# Первые 4 байта случайного префикса не должны совпадать с сигнатурами
# других протоколов, которые могли бы прилететь на тот же порт (HTTP-
# методы -- вдруг что-то интерпретирует этот трафик как HTTP; уже занятые
# proto-теги обычной MTProto; начало TLS-хендшейка).
RESERVED_STARTS = frozenset({
    b'HEAD', b'POST', b'GET ',
    PROTO_TAG_INTERMEDIATE, PROTO_TAG_PADDED_INTERMEDIATE,
    b'\x16\x03\x01\x02',
})

# Байты 4-8 не должны быть все нулевыми -- зарезервированное значение в
# протоколе (означало бы "нет obfuscation", отдельный кейс).
RESERVED_CONTINUE = b'\x00\x00\x00\x00'


def build_obfuscated_init(dc_idx: int, proto_tag: bytes = PROTO_TAG_INTERMEDIATE) -> bytes:
    """64 байта: [0:56) случайный префикс (использован он же как
    материал для AES-256-CTR ключа/IV самого потока), [56:64) --
    proto_tag (4 байта) + dc_idx (2 байта, little-endian signed) + 2
    случайных байта, ЗАШИФРОВАННЫЕ тем же потоком, что и остальной
    obfuscated-трафик (иначе тег/DC были бы видны в открытую -- ровно
    то, что должна прятать "маскировка").

    Приём: шифруем ВЕСЬ 64-байтный rnd тем же AES-CTR (ключ/IV взяты из
    самого rnd), затем восстанавливаем keystream в позициях [56:64) как
    (encrypted XOR plaintext) и применяем его к РЕАЛЬНОМУ tail_plain --
    получаем корректно зашифрованный хвост без повторного вызова
    шифра с других позиций потока. Тот же приём независимо
    воспроизведён (не скопирован) по методичке из tg-ws-proxy.
    """
    while True:
        rnd = bytearray(os.urandom(HANDSHAKE_LEN))
        if rnd[0] in RESERVED_FIRST_BYTES:
            continue
        if bytes(rnd[:4]) in RESERVED_STARTS:
            continue
        if rnd[4:8] == RESERVED_CONTINUE:
            continue
        break

    rnd_bytes = bytes(rnd)
    enc_key = rnd_bytes[SKIP_LEN:SKIP_LEN + PREKEY_LEN]
    enc_iv = rnd_bytes[SKIP_LEN + PREKEY_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN]

    encryptor = Cipher(algorithms.AES(enc_key), modes.CTR(enc_iv)).encryptor()
    dc_bytes = struct.pack('<h', dc_idx)
    tail_plain = proto_tag + dc_bytes + os.urandom(2)

    encrypted_full = encryptor.update(rnd_bytes)
    keystream_tail = bytes(
        encrypted_full[i] ^ rnd_bytes[i] for i in range(PROTO_TAG_POS, HANDSHAKE_LEN))
    encrypted_tail = bytes(
        tail_plain[i] ^ keystream_tail[i] for i in range(HANDSHAKE_LEN - PROTO_TAG_POS))

    result = bytearray(rnd_bytes)
    result[PROTO_TAG_POS:HANDSHAKE_LEN] = encrypted_tail
    return bytes(result)


# Публично известные дефолтные IP основных Telegram DC (не тестовых) --
# опубликованы во множестве независимых источников (MTProxy, mtprotoproxy,
# tg-ws-proxy), сверено с tg-ws-proxy/proxy/utils.py::DC_DEFAULT_IPS.
# is_media/тестовые DC тут не нужны -- для DPI-зонда важен только сам
# факт "пакет с такой сигнатурой к такому IP:порту доходит или нет",
# не то, к какому именно поддомену/сервису DC он адресован.
DC_DEFAULT_IPS = {
    1: '149.154.175.50',
    2: '149.154.167.51',
    3: '149.154.175.100',
    4: '149.154.167.91',
    5: '149.154.171.5',
}
