# Routing-loop protection: VPS by IP and by domain, with and without autoOutboundsInterface.
start_server server_enc
echo "nameserver 203.0.113.53" > "$L/resolv.conf"; mount --bind "$L/resolv.conf" /etc/resolv.conf
r() { echo "$1 $(web)"; }
start_xray loop_auto_ip;        r "[1] VPS by IP, autoOutboundsInterface=auto:           "; stop_xray
start_xray loop_manual_ip;      ip route add default dev xray0 metric 1
                                r "[2] VPS by IP, manual routes, no protection:          "; stop_xray
start_xray loop_manual_ip;      ip route add default dev xray0 metric 1; ip route add 198.51.100.2/32 via 10.0.0.2 dev vA
                                r "[3] same + static route to the VPS via the NIC:       "; stop_xray; ip route del 198.51.100.2/32 2>/dev/null
: > "$L/dns.log"
start_xray loop_auto_domain;    r "[4] VPS by DOMAIN, auto, system resolver:             "
                                echo "    resolver asked by: $(sort -u $L/dns.log | tr '\n' ';')"; stop_xray
start_xray loop_dns_explicit;   r "[5] VPS by DOMAIN, auto, explicit dns.servers:        "
                                echo "    resolver asked by: $(sort -u $L/dns.log | tr '\n' ';')"; stop_xray
echo "198.51.100.2 vps.test" > "$L/hosts"; mount --bind "$L/hosts" /etc/hosts
start_xray loop_auto_domain;    r "[6] VPS by DOMAIN found in /etc/hosts:                "; stop_xray
