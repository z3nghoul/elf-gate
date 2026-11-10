# Xray TUN inbound, everything through VLESS: TCP, UDP, sizes, cleanup after kill -9.
start_server server_plain
start_xray tun_all
echo "--- after start:"; ip -br addr show xray0; ip route; ip rule | grep -v -E 'local|main|default'
echo "TCP : $(web)"
for size in 100 1200 1400; do echo -n "UDP : "; udp 5000 30 $size; done
echo "UDP flows are separate VLESS connections (server access log):"
grep -c "accepted udp:203.0.113.80:5000" "$WORK/server-access.log" | sed 's/^/  accepted UDP flows: /'
echo "--- kill -9 the client; what is left?"
kill -9 $XPID; sleep 1
ip link show xray0 2>&1 | head -1; ip route
