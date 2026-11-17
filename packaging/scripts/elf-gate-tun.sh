#!/usr/bin/env bash
# Запуск elf-gate с поддержкой режима TUN на Linux.
# Лежит в папке архива рядом с elf-gate, xray, geoip.dat и geosite.dat (из репозитория, где ядро в bin/,
# тоже работает).
# Запускать от обычного пользователя, НЕ через sudo: sudo спросится сам,
# и только один раз - чтобы выдать xray право на создание TUN.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Где лежат ядро и его данные: рядом со скриптом (архив) или в bin/ (папка разработки).
SRC_DIR="$DIR"
if [[ ! -f "$DIR/xray" && -f "$DIR/bin/xray" ]]; then
    SRC_DIR="$DIR/bin"
fi
SRC_XRAY="$SRC_DIR/xray"
DST_DIR="/usr/local/lib/elf-gate"
DST_XRAY="$DST_DIR/xray"

# Права ядра. По умолчанию три: создание TUN, плюс чтение сокетов и файловых дескрипторов чужих и
# "песочных" процессов (Chromium, Electron, Discord из Flatpak, systemd-resolved): без них правила по
# процессам их не видят, а в журнале десятки ошибок "no process found" в минуту (проверено на практике).
# Права даются только root-копии ядра, которую никто кроме root не может изменить.
# ELF_GATE_FULL_CAPS=0 - отказаться и оставить только cap_net_admin.
if [[ "${ELF_GATE_FULL_CAPS:-1}" == "0" ]]; then
    CAPS="cap_net_admin+ep"
    WANT_CAP="cap_net_admin"
else
    CAPS="cap_net_admin,cap_sys_ptrace,cap_dac_read_search+ep"
    WANT_CAP="cap_sys_ptrace"
fi

if [[ $EUID -eq 0 ]]; then
    echo "Не запускайте через sudo: настройки elf-gate окажутся у root." >&2
    exit 1
fi

needs_setup=0
if [[ ! -x "$DST_XRAY" ]]; then
    needs_setup=1
elif ! getcap "$DST_XRAY" 2>/dev/null | grep -q "$WANT_CAP"; then
    needs_setup=1
elif [[ -f "$SRC_XRAY" ]] && ! cmp -s "$SRC_XRAY" "$DST_XRAY"; then
    # xray обновился - копию нужно обновить, setcap слетает при замене файла
    needs_setup=1
fi

# Копия ядра ищет geoip.dat и geosite.dat только рядом с собой: держим их там же и обновляем, если исходники изменились.
GEO_FILES=(geoip.dat geosite.dat)
for f in "${GEO_FILES[@]}"; do
    if [[ -f "$SRC_DIR/$f" ]] && ! cmp -s "$SRC_DIR/$f" "$DST_DIR/$f"; then
        needs_setup=1
    fi
done

if [[ $needs_setup -eq 1 ]]; then
    if [[ ! -f "$SRC_XRAY" ]]; then
        echo "Не найден $SRC_XRAY" >&2
        exit 1
    fi
    echo "Первичная настройка TUN (нужен пароль sudo)..."
    sudo mkdir -p "$DST_DIR"
    sudo install -o root -g root -m 0755 "$SRC_XRAY" "$DST_XRAY"
    sudo setcap "$CAPS" "$DST_XRAY"
    for f in "${GEO_FILES[@]}"; do
        if [[ -f "$SRC_DIR/$f" ]]; then
            sudo install -o root -g root -m 0644 "$SRC_DIR/$f" "$DST_DIR/$f"
        else
            echo "Предупреждение: нет $SRC_DIR/$f, TUN не стартует без него в $DST_DIR" >&2
        fi
    done
    echo "Готово."
fi

exec "$DIR/elf-gate" "$@"
