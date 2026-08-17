"""Детерминированные тесты build_obfuscated_init() -- без сети, без
живого Telegram. Главное свойство, которое тут реально важно проверить:
пакет ДОЛЖЕН расшифровываться на стороне получателя (тем же способом,
каким это делает реальный сервер MTProto) обратно в переданные
proto_tag/dc_idx -- если это не так, пакет синтаксически похож на
настоящий, но семантически мусорный, и живой DC его либо мгновенно
отбросит, либо результат зонда будет врать о причине разрыва (спутает
"сервер отверг некорректный пакет" с "DPI зарезала соединение")."""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'prober'))

from proto import (
    build_obfuscated_init, DC_IDX_POS, HANDSHAKE_LEN, IV_LEN, PREKEY_LEN,
    PROTO_TAG_INTERMEDIATE, PROTO_TAG_PADDED_INTERMEDIATE, PROTO_TAG_POS,
    RESERVED_CONTINUE, RESERVED_FIRST_BYTES, RESERVED_STARTS, SKIP_LEN,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _server_side_decode(packet: bytes):
    """Воспроизводит то, что делает РЕАЛЬНЫЙ сервер: ключ/IV из
    префикса, расшифровать весь пакет тем же AES-CTR, прочитать
    proto_tag/dc_idx из расшифрованного хвоста. Независимая от
    build_obfuscated_init реализация (тот же метод, что и
    _try_handshake в tg-ws-proxy) -- если она сходится с тем, что мы
    передали, значит пакет реально валиден для получателя."""
    key = packet[SKIP_LEN:SKIP_LEN + PREKEY_LEN]
    iv = packet[SKIP_LEN + PREKEY_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN]
    decryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    decrypted = decryptor.update(packet)
    proto_tag = decrypted[PROTO_TAG_POS:PROTO_TAG_POS + 4]
    dc_idx = struct.unpack('<h', decrypted[DC_IDX_POS:DC_IDX_POS + 2])[0]
    return proto_tag, dc_idx


def test_roundtrip_recovers_proto_tag_and_dc_idx():
    for dc in (1, 2, 3, 4, 5, -2, 10002):
        packet = build_obfuscated_init(dc, PROTO_TAG_INTERMEDIATE)
        proto_tag, dc_idx = _server_side_decode(packet)
        assert proto_tag == PROTO_TAG_INTERMEDIATE, f"dc={dc}: proto_tag mismatch {proto_tag!r}"
        assert dc_idx == dc, f"dc={dc}: dc_idx mismatch, got {dc_idx}"


def test_roundtrip_padded_intermediate_tag():
    packet = build_obfuscated_init(2, PROTO_TAG_PADDED_INTERMEDIATE)
    proto_tag, dc_idx = _server_side_decode(packet)
    assert proto_tag == PROTO_TAG_PADDED_INTERMEDIATE
    assert dc_idx == 2


def test_packet_length():
    packet = build_obfuscated_init(2)
    assert len(packet) == HANDSHAKE_LEN


def test_never_starts_with_reserved_first_byte():
    for _ in range(200):
        packet = build_obfuscated_init(2)
        assert packet[0] not in RESERVED_FIRST_BYTES


def test_never_starts_with_reserved_4byte_signature():
    for _ in range(200):
        packet = build_obfuscated_init(2)
        assert packet[:4] not in RESERVED_STARTS


def test_never_has_reserved_continue_bytes():
    for _ in range(200):
        packet = build_obfuscated_init(2)
        assert packet[4:8] != RESERVED_CONTINUE


def test_packets_are_random_not_fixed():
    packets = {build_obfuscated_init(2) for _ in range(20)}
    assert len(packets) == 20, "должны быть разные пакеты на каждый вызов (иначе тривиально фингерпринтится)"


if __name__ == '__main__':
    failures = 0
    for name, fn in list(globals().items()):
        if name.startswith('test_') and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {name}: {e}")
    print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}")
    raise SystemExit(1 if failures else 0)
