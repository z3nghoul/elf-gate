# The real background process (elf-gated) owning TUN end to end (needs: cargo build).
ELFGATED=${ELFGATED:-$ROOT/target/debug/elf-gated}
[ -x "$ELFGATED" ] || { echo "build elf-gated first: cargo build"; exit 2; }
start_server server_plain
echo "203.0.113.80 connectivitycheck.gstatic.com" > "$L/hosts"; mount --bind "$L/hosts" /etc/hosts
python3 "$HERE/elfgated_e2e.py" "$ELFGATED" "$XR" "$L"
