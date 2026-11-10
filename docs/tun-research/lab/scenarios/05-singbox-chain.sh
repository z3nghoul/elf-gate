# Option B: sing-box TUN (process_name rules) -> Xray socks inbound (UDP) -> VLESS Reality Vision.
SB=${SB:?set SB=/path/to/sing-box}
inB openssl s_server -accept 127.0.0.1:9443 -cert "$L/dest.crt" -key "$L/dest.key" -tls1_3 -alpn h2 -www >/dev/null 2>&1 &
sleep 0.5
start_server server_reality
cat "$L/names.txt"
for CFG in sb_include sb_exclude sb_exclude_noguard; do
  echo; echo "===== sing-box config: $CFG ====="
  $XR run -c "$L/xray_socks_reality.json" >"$L/xs.out" 2>&1 & XP=$!; sleep 1
  $SB run -c "$L/$CFG.json" >"$L/sb.out" 2>&1 & SP=$!
  for i in $(seq 1 50); do ip link show sb0 >/dev/null 2>&1 && break; sleep 0.1; done; sleep 1
  echo "ip rule: $(ip rule | grep -v -E 'local|main|default' | head -3 | tr '\n' ';')"
  echo "curl   TCP : $(web)"
  echo "python TCP : $(pyweb)"
  echo -n "socat  UDP : "; socat_udp
  echo -n "python UDP : "; udp 5000 3 100
  kill $SP; wait $SP 2>/dev/null; kill $XP; wait $XP 2>/dev/null
  for i in $(seq 1 50); do ip link show sb0 >/dev/null 2>&1 || break; sleep 0.1; done; sleep 0.5
done
