# UDP over VLESS + Reality, with the three flow settings, through the Xray TUN.
inB openssl s_server -accept 127.0.0.1:9443 -cert "$L/dest.crt" -key "$L/dest.key" -tls1_3 -alpn h2 -www >/dev/null 2>&1 &
sleep 0.5
start_server server_reality
for V in vision vision_udp443 noflow; do
  echo "===== Reality, client flow variant: $V ====="
  start_xray reality_$V
  echo "  TCP            : $(web)"
  echo -n "  UDP port 5000  : "; udp 5000 20 300
  echo -n "  UDP port 443   : "; udp 443 6 300
  stop_xray
done
