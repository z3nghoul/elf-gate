# DNS routed by domain: queries for domains of the "via VPN" list go through the tunnel, others do not.
# The "application" asks its upstream resolver 203.0.113.53 directly (as systemd-resolved would).
start_server server_plain
for MODE in include exclude; do
  echo; echo "===== mode: $MODE (listed domain: discord.test) ====="
  : > "$L/dns.log"; : > "$L/dns54.log"
  start_xray dns_$MODE
  echo "discord.test -> $(python3 "$HERE/dns_query.py" 203.0.113.53 discord.test)   (7.7.7.7 = tunnel DNS answer, 198.51.100.2 = local upstream answer)"
  echo "other.test   -> $(python3 "$HERE/dns_query.py" 203.0.113.53 other.test)"
  echo "  local upstream (203.0.113.53) was asked: $(sort -u "$L/dns.log" | tr '\n' ';')"
  echo "  tunnel DNS     (203.0.113.54) was asked: $(sort -u "$L/dns54.log" | tr '\n' ';')"
  echo "  (10.0.0.1 = asked directly from this machine; any other source = came out of the VPN server)"
  stop_xray
done
