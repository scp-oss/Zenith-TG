#!/usr/bin/env python3
"""Зонд DPI-выживаемости MTProto obfuscated-транспорта против реального
Telegram DC IP:port -- НЕ полноценный MTProto-клиент (не проходит
Diffie-Hellman, не авторизуется ни в каком аккаунте): строит валидно
выглядящий 64-байтный init-пакет (см. proto.py), открывает TCP до
реального DC, отправляет init и следит, оборвётся ли соединение СРАЗУ
после этого.

Почему "оборвётся ли сразу", а не "пришёл ли осмысленный ответ": реальный
сервер Telegram, получив синтаксически валидный obfuscated init со
случайным (не привязанным ни к какому реальному аккаунту) ключом, не
может провалидировать сессию дальше уровня протокольной рамки -- он либо
молчит и ждёт (штатное поведение, соединение живёт секунды/десятки
секунд до серверного таймаута), либо в редких случаях отвечает чем-то
(тоже нормально, тоже значит "дошло"). DPI же, которая детектит именно
эту сигнатуру (внезапный высокоэнтропийный TCP-пейлоад к известному
диапазону Telegram на 443/80), обычно рвёт TCP RST'ом в течение
миллисекунд после этого пакета -- признак "не дошло" здесь про ВРЕМЯ
разрыва, не про содержимое (или отсутствие) ответа.

Использование:
  - "до" (baseline, БЕЗ активной --lua-desync= стратегии профиля
    TG_MTPROTO в zapret2/nfqws2) -- если рвётся уже тут, DPI блокирует
    безусловно и без обхода, ни одна стратегия сама по себе не поможет,
    пока пакет вообще не изменится на пути через nfqws2.
  - "после" (С активной стратегией) -- разница между двумя прогонами и
    есть сигнал "эта стратегия реально помогает выжить конкретно этому
    пакету", ровно та же логика, что у rank_strategies.sh для остальных
    профилей z2r_autobench (см. z2r_autobench/README.md "Профили").

Прогон обязан выполняться НА ТОЙ ЖЕ машине, где стоит zapret2/nfqws2 (не
удалённо) -- перехват идёт прозрачно на уровне NFQUEUE, приложению
(этому скрипту) ничего специально настраивать не нужно, достаточно
обычного socket.connect()."""
from __future__ import annotations

import argparse
import dataclasses
import os
import socket
import sys
import time
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from proto import DC_DEFAULT_IPS, PROTO_TAG_INTERMEDIATE, build_obfuscated_init

DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_ALIVE_WINDOW = 3.0


@dataclasses.dataclass
class ProbeResult:
    host: str
    port: int
    connected: bool
    survived: bool
    elapsed_ms: float
    detail: Optional[str]

    def summary(self) -> str:
        if not self.connected:
            return f"{self.host}:{self.port}: TCP connect не удался -- {self.detail}"
        if self.survived:
            return f"{self.host}:{self.port}: OK -- живо {self.elapsed_ms:.0f}ms после init-пакета ({self.detail})"
        return f"{self.host}:{self.port}: FAIL -- разорвано через {self.elapsed_ms:.0f}ms ({self.detail})"


def probe(host: str, port: int = 443, dc_idx: int = 2,
          connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
          alive_window: float = DEFAULT_ALIVE_WINDOW) -> ProbeResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(connect_timeout)
    try:
        sock.connect((host, port))
    except OSError as e:
        sock.close()
        return ProbeResult(host, port, False, False, 0.0, repr(e))

    init_packet = build_obfuscated_init(dc_idx, PROTO_TAG_INTERMEDIATE)
    t0 = time.monotonic()
    try:
        sock.sendall(init_packet)
    except OSError as e:
        elapsed = (time.monotonic() - t0) * 1000
        sock.close()
        return ProbeResult(host, port, True, False, elapsed, f"send failed: {e!r}")

    sock.settimeout(alive_window)
    try:
        data = sock.recv(4096)
        elapsed = (time.monotonic() - t0) * 1000
        sock.close()
        if data == b'':
            # Аккуратный FIN сразу после init -- тоже не похоже на
            # штатное поведение "сервер молча ждёт валидных данных",
            # считаем как разрыв, не как "живо".
            return ProbeResult(host, port, True, False, elapsed,
                                "соединение закрыто (FIN) сразу после init")
        return ProbeResult(host, port, True, True, elapsed,
                            f"сервер ответил {len(data)} байт")
    except socket.timeout:
        # Ни ответа, ни разрыва за alive_window -- ИМЕННО ожидаемое
        # поведение настоящего Telegram DC на мусорный (не привязанный
        # к реальному аккаунту) ключ: тихо держит соединение открытым.
        # Считаем "выжило".
        sock.close()
        return ProbeResult(host, port, True, True, alive_window * 1000,
                            "нет ответа/разрыва за окно ожидания (норма для мусорного ключа)")
    except OSError as e:
        elapsed = (time.monotonic() - t0) * 1000
        sock.close()
        return ProbeResult(host, port, True, False, elapsed, repr(e))


def probe_many(host: str, port: int, dc_idx: int, repeat: int,
                connect_timeout: float, alive_window: float) -> list:
    return [probe(host, port, dc_idx, connect_timeout, alive_window)
            for _ in range(max(1, repeat))]


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('host', nargs='?', default=None,
                     help='Telegram DC IP (по умолчанию -- перебор DC_DEFAULT_IPS 1-5)')
    ap.add_argument('--port', type=int, default=443)
    ap.add_argument('--dc-idx', type=int, default=2,
                     help='Номер DC для поля в init-пакете (не влияет на то, куда коннектимся)')
    ap.add_argument('--connect-timeout', type=float, default=DEFAULT_CONNECT_TIMEOUT)
    ap.add_argument('--alive-window', type=float, default=DEFAULT_ALIVE_WINDOW)
    ap.add_argument('--repeat', type=int, default=3,
                     help='Повторов на каждый хост -- одиночный успех/провал может быть шумом (default 3)')
    args = ap.parse_args()

    if args.host:
        targets = [(args.host, args.dc_idx)]
    else:
        targets = [(ip, dc) for dc, ip in DC_DEFAULT_IPS.items()]

    all_ok = True
    for ip, dc_idx in targets:
        results = probe_many(ip, args.port, dc_idx, args.repeat,
                              args.connect_timeout, args.alive_window)
        for r in results:
            print(r.summary())
        ok = sum(1 for r in results if r.survived)
        print(f"  -> DC{dc_idx} {ip}:{args.port}: {ok}/{len(results)} survived\n")
        all_ok = all_ok and ok == len(results)

    sys.exit(0 if all_ok else 1)


if __name__ == '__main__':
    main()
