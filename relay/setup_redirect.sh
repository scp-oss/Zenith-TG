#!/usr/bin/env bash
# setup_redirect.sh -- прозрачно перенаправляет исходящий TCP:443 трафик
# к официальным подсетям Telegram (см. ../cidr/telegram_ipv4.txt) на
# локальный transparent_relay.py (127.0.0.1:8447 по умолчанию).
#
# ПОЧЕМУ REDIRECT в OUTPUT-цепочку, а не PREROUTING/FORWARD: трафик,
# который реально нужно перехватывать здесь -- это то, что ЛОКАЛЬНО
# порождает сам сервер (в т.ч. Xray/VLESS "freedom"-outbound делает для
# туннелированных клиентов ОБЫЧНЫЙ локальный socket.connect(), это и
# есть OUTPUT, не FORWARD, проверено вживую на NETH-4 при разборе
# DNAT-варианта этого же профиля).
#
# Использование:
#   setup_redirect.sh apply [--port N]
#   setup_redirect.sh remove [--port N]
#   setup_redirect.sh status

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CIDR_FILE="$SCRIPT_DIR/../cidr/telegram_ipv4.txt"
PORT=8447
ACTION="${1:-}"
shift || true

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    *) echo "Неизвестный аргумент: $1" >&2; exit 1 ;;
  esac
done

[ -f "$CIDR_FILE" ] || { echo "Не найден $CIDR_FILE -- сначала запустите cidr/fetch_telegram_cidr.sh" >&2; exit 1; }

mapfile -t CIDRS < <(grep -vE '^\s*#|^\s*$' "$CIDR_FILE")
[ "${#CIDRS[@]}" -gt 0 ] || { echo "$CIDR_FILE пуст -- нечего перенаправлять" >&2; exit 1; }

case "$ACTION" in
  apply)
    for cidr in "${CIDRS[@]}"; do
      iptables -t nat -A OUTPUT -p tcp -d "$cidr" --dport 443 \
        -j REDIRECT --to-port "$PORT"
    done
    echo "Применено: ${#CIDRS[@]} подсетей -> 127.0.0.1:$PORT" >&2
    ;;
  remove)
    for cidr in "${CIDRS[@]}"; do
      iptables -t nat -D OUTPUT -p tcp -d "$cidr" --dport 443 \
        -j REDIRECT --to-port "$PORT" 2>/dev/null || true
    done
    echo "Правила для порта $PORT удалены (если были)" >&2
    ;;
  status)
    iptables -t nat -L OUTPUT -n -v --line-numbers | grep -E "REDIRECT|Chain OUTPUT"
    ;;
  *)
    echo "Использование: $0 apply|remove|status [--port N]" >&2
    exit 1
    ;;
esac
