#!/usr/bin/env bash
# Запуск elf-gate с поддержкой режима TUN на Linux.
# Положите рядом с бинарником elf-gate (ожидается bin/xray рядом).
# Запускать от обычного пользователя, НЕ через sudo: sudo спросится сам,
# и только один раз - чтобы выдать xray право на создание TUN.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_XRAY="$DIR/bin/xray"
DST_DIR="/usr/local/lib/elf-gate"
DST_XRAY="$DST_DIR/xray"

if [[ $EUID -eq 0 ]]; then
    echo "Не запускайте через sudo: настройки elf-gate окажутся у root." >&2
    exit 1
fi

needs_setup=0
if [[ ! -x "$DST_XRAY" ]]; then
    needs_setup=1
elif ! getcap "$DST_XRAY" 2>/dev/null | grep -q cap_net_admin; then
    needs_setup=1
elif [[ -f "$SRC_XRAY" ]] && ! cmp -s "$SRC_XRAY" "$DST_XRAY"; then
    # xray обновился - копию нужно обновить, setcap слетает при замене файла
    needs_setup=1
fi

if [[ $needs_setup -eq 1 ]]; then
    if [[ ! -f "$SRC_XRAY" ]]; then
        echo "Не найден $SRC_XRAY" >&2
        exit 1
    fi
    echo "Первичная настройка TUN (нужен пароль sudo)..."
    sudo mkdir -p "$DST_DIR"
    sudo install -o root -g root -m 0755 "$SRC_XRAY" "$DST_XRAY"
    sudo setcap cap_net_admin+ep "$DST_XRAY"
    echo "Готово."
fi

exec "$DIR/elf-gate" "$@"
