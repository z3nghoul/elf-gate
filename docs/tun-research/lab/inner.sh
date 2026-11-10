#!/bin/bash
# Runs inside the namespaces. Builds the two-machine topology, then sources the scenario.
HERE=$(cd "$(dirname "$0")" && pwd)
export XRAY_LOCATION_ASSET=$(dirname "$XR")
L=$WORK
ip link set lo up
sysctl -qw net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.default.rp_filter=2
unshare -n sleep 3000 & BPID=$!
sleep 0.4
ip link add vA type veth peer name vB
ip link set vB netns $BPID
ip addr add 10.0.0.1/24 dev vA; ip link set vA up; sysctl -qw net.ipv4.conf.vA.rp_filter=2
nsenter -t $BPID -n bash -c 'ip link set lo up; ip addr add 10.0.0.2/24 dev vB; ip link set vB up;
  ip addr add 203.0.113.80/32 dev lo; ip addr add 198.51.100.2/32 dev lo; ip addr add 203.0.113.53/32 dev lo; ip addr add 203.0.113.54/32 dev lo'
ip route add default via 10.0.0.2 dev vA metric 100
inB() { nsenter -t $BPID -n "$@"; }
inB python3 "$HERE/servers.py" 203.0.113.80 >/dev/null 2>&1 &
inB python3 "$HERE/dns_server.py" 203.0.113.53 "$L/dns.log" >/dev/null 2>&1 &
inB python3 "$HERE/dns_server.py" 203.0.113.54 "$L/dns54.log" 7.7.7.7 >/dev/null 2>&1 &
[ -n "$B_EXTRA" ] && inB bash -c "$B_EXTRA" >/dev/null 2>&1 &
sleep 0.3
start_server() { inB $XR run -c "$L/$1.json" >"$L/server.out" 2>&1 & sleep 1; }
# --- helpers for scenarios ---
start_xray() { $XR run -c "$L/$1.json" >"$L/$1.out" 2>&1 & XPID=$!
  for i in $(seq 1 50); do ip link show xray0 >/dev/null 2>&1 && break; sleep 0.1; done; sleep 0.7; }
stop_xray() { kill $XPID 2>/dev/null; wait $XPID 2>/dev/null; sleep 0.5; }
web() { R=$(curl -s --max-time 5 http://203.0.113.80:8080/ | tr -d '\n'); echo "${R:-FAIL}"; }
pyweb() { python3 -c "
import urllib.request;print(urllib.request.urlopen('http://203.0.113.80:8080/',timeout=5).read().decode().strip())" 2>&1 | tail -1; }
udp() { python3 "$HERE/udp_probe.py" 203.0.113.80 "${1:-5000}" "${2:-10}" "${3:-200}"; }
socat_udp() { echo -n hello | timeout 4 socat -t1 - UDP:203.0.113.80:5000 2>&1 | head -c 70; echo; }
echo "legend: peer=10.0.0.1 => direct, peer=203.0.113.80 => through the VPN server, FAIL => no connectivity"
source "$1"
