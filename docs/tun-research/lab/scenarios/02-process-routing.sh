# Process-name routing through the Xray TUN, TCP and UDP, include and exclude modes.
start_server server_plain
cat "$WORK/names.txt"
for MODE in include exclude; do
  echo; echo "===== mode: $MODE ====="
  start_xray tun_$MODE
  echo "curl   TCP : $(web)"
  echo "python TCP : $(pyweb)"
  echo -n "socat  UDP : "; socat_udp
  echo -n "python UDP : "; udp 5000 3 60
  stop_xray
done
