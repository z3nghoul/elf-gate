# The real elf-gate binary driving TUN end to end (needs a debug build: cargo build).
ELFGATE=${ELFGATE:-$ROOT/target/debug/elf-gate}
[ -x "$ELFGATE" ] || { echo "build elf-gate first: cargo build"; exit 2; }
start_server server_plain
# The connection check asks connectivitycheck.gstatic.com: make it resolve to the lab web server.
echo "203.0.113.80 connectivitycheck.gstatic.com" > "$L/hosts"; mount --bind "$L/hosts" /etc/hosts
python3 "$HERE/elfgate_e2e.py" "$ELFGATE" "$XR" "$L"
