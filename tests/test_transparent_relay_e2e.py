"""Сквозной тест transparent_relay.py -- ТРЕБУЕТ живой сети (реальное
соединение с боевым Telegram через 149.154.167.220), в отличие от
test_proto.py. Пропускается автоматически, если сеть недоступна --
это не баг теста, а честное отражение того, что тестируется: сама
СВЯЗНОСТЬ, не только формат пакетов.

Поднимает сервер `relay.transparent_relay` в этом же процессе (не
отдельным subprocess -- переиспользуемее, без гонки по PID/портам между
прогонами), затем симулирует настоящего "прямого" клиента Telegram (без
секрета, ровно та же семантика, что в prober/proto.py) и проверяет, что
через релей приходит настоящий `resPQ` (constructor 0x05162463) от
Telegram -- то есть весь путь: декодирование без секрета -> релейный
хендшейк к .220 -> бридж байт в обе стороны -> реальный ответ Telegram,
работает целиком, не только на бумаге."""
import asyncio
import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'prober'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'relay'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'relay', 'vendor'))

from proto import build_obfuscated_init, PROTO_TAG_INTERMEDIATE, SKIP_LEN, PREKEY_LEN, IV_LEN  # noqa: E402
from _aes import Cipher, algorithms, modes  # noqa: E402

TEST_PORT = 18447
ZERO_64 = b'\x00' * 64


def _run_server_in_thread():
    import transparent_relay as tr

    loop = asyncio.new_event_loop()

    def _runner():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(
            tr.main_async('127.0.0.1', TEST_PORT,
                           {2: '149.154.167.220', 4: '149.154.167.220'}))

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    return thread


def _simulate_direct_client_req_pq(port: int, timeout: float = 15.0) -> int:
    """Возвращает MTProto constructor из ответа (0x05162463 = resPQ при
    успехе) или бросает исключение при таймауте/обрыве."""
    packet = build_obfuscated_init(2, PROTO_TAG_INTERMEDIATE)
    prekey_and_iv = packet[SKIP_LEN:SKIP_LEN + PREKEY_LEN + IV_LEN]

    enc_key = prekey_and_iv[:PREKEY_LEN]
    enc_iv = prekey_and_iv[PREKEY_LEN:]
    client_encryptor = Cipher(algorithms.AES(enc_key), modes.CTR(enc_iv)).encryptor()
    client_encryptor.update(ZERO_64)

    dec_prekey_iv = prekey_and_iv[::-1]
    dec_key = dec_prekey_iv[:PREKEY_LEN]
    dec_iv = dec_prekey_iv[PREKEY_LEN:]
    client_decryptor = Cipher(algorithms.AES(dec_key), modes.CTR(dec_iv)).encryptor()

    nonce = os.urandom(16)
    req_pq_body = struct.pack('<I', 0xbe7e8ef1) + nonce
    msg = (b'\x00' * 8 + os.urandom(7) + b'\x00'
           + struct.pack('<I', len(req_pq_body)) + req_pq_body)
    frame = struct.pack('<I', len(msg)) + msg
    enc_frame = client_encryptor.update(frame)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(('127.0.0.1', port))
    sock.sendall(packet + enc_frame)
    resp = sock.recv(4096)
    sock.close()
    if not resp:
        raise ConnectionError("пустой ответ от релея")

    dec = client_decryptor.update(resp)
    frame_len = struct.unpack('<I', dec[:4])[0]
    body = dec[4:4 + frame_len]
    return struct.unpack('<I', body[20:24])[0]


def test_transparent_relay_reaches_real_telegram():
    try:
        socket.create_connection(('149.154.167.220', 443), timeout=5).close()
    except OSError:
        import pytest
        pytest.skip("нет сети до 149.154.167.220 -- см. докстринг файла")

    _run_server_in_thread()
    time.sleep(2)  # дать серверу подняться + прогреть WS pool

    constructor = _simulate_direct_client_req_pq(TEST_PORT)
    assert constructor == 0x05162463, (
        f"ожидался resPQ (0x05162463), получен 0x{constructor:08x}")


if __name__ == '__main__':
    test_transparent_relay_reaches_real_telegram()
    print("PASS")
