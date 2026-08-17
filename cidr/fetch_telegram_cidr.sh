#!/usr/bin/env bash
# fetch_telegram_cidr.sh -- тянет официальный список подсетей Telegram
# (https://core.telegram.org/resources/cidr.txt, публикуется самим
# Telegram, обновляется НЕ на каждый деплой -- это не хостлист доменов,
# а список IP-диапазонов, поэтому и матчится в zapret2/nfqws2 через
# --ipset=, а не --hostlist= -- у Telegram (обфусцированный MTProto)
# просто нет SNI/domain, который можно было бы сматчить, единственный
# признак -- destination IP + порт, отсюда и весь смысл этого файла.
#
# Формат --ipset= у (n)fqws -- как у ОРИГИНАЛЬНОГО zapret (bol-van), не
# выдумка этого модуля: он сам исторически поставляет
# ipset/get_config_telegram.sh + ipset-telegram.txt именно для этого же
# случая -- плоский текстовый файл, один CIDR (или голый IP) на строку,
# "#"-комментарии допустимы. Live-ПРОВЕРКА на целевом сервере всё равно
# нужна перед боевым использованием (нет исполнительного доступа к
# деплой-боксу из этой сессии, см. z2r_autobench/CLAUDE.md) -- если
# конкретная сборка zapret2/nfqws2 ожидает другой формат, --ipset=
# откажет явной ошибкой при старте, не тихо.
#
# IPv6-диапазоны из официального списка НЕ включены в основной файл --
# поддержка IPv6 в --ipset= у nfqws2 не проверена вживую (тоже нужна
# live-проверка), пишутся отдельным файлом *_ipv6.txt на всякий случай,
# не в TG_MTPROTO.block.conf по умолчанию.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_URL="https://core.telegram.org/resources/cidr.txt"
OUT_V4="$SCRIPT_DIR/telegram_ipv4.txt"
OUT_V6="$SCRIPT_DIR/telegram_ipv6.txt"

raw="$(curl -fsS --max-time 15 "$SOURCE_URL")" || {
  echo "Не удалось скачать $SOURCE_URL" >&2
  exit 1
}

[ -n "$raw" ] || { echo "Пустой ответ от $SOURCE_URL -- отказ, не буду перезаписывать существующие файлы." >&2; exit 1; }

v4_lines="$(printf '%s\n' "$raw" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' | sort -V)"
v6_lines="$(printf '%s\n' "$raw" | grep -E ':' | sort -V)"

[ -n "$v4_lines" ] || { echo "В ответе не нашлось ни одной IPv4 CIDR-строки -- формат источника изменился? Отказ." >&2; exit 1; }

{
  echo "# Источник: $SOURCE_URL"
  echo "# Обновлено: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# IPv4-подсети официальных Telegram DC -- используется в"
  echo "# zapret2/TG_MTPROTO.block.conf через --ipset=. Диапазоны МЕНЯЮТСЯ"
  echo "# со временем (не часто, но бывает) -- перезапускать этот скрипт"
  echo "# периодически, не считать разово скачанный файл вечным."
  printf '%s\n' "$v4_lines"
} > "$OUT_V4"

if [ -n "$v6_lines" ]; then
  {
    echo "# Источник: $SOURCE_URL"
    echo "# Обновлено: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# IPv6-подсети официальных Telegram DC -- НЕ используется по"
    echo "# умолчанию (--ipset= с IPv6 не проверен вживую на nfqws2, см."
    echo "# докстринг этого скрипта). Подключать явно и только после"
    echo "# проверки на целевом сервере."
    printf '%s\n' "$v6_lines"
  } > "$OUT_V6"
fi

echo "OK: $(printf '%s\n' "$v4_lines" | wc -l) IPv4-подсетей -> $OUT_V4" >&2
[ -n "$v6_lines" ] && echo "OK: $(printf '%s\n' "$v6_lines" | wc -l) IPv6-подсетей -> $OUT_V6" >&2
