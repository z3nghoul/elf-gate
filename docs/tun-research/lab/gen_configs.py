#!/usr/bin/env python3
"""Generates every config the lab scenarios use into WORK. Keys are created fresh each run."""
import json, os, shutil, subprocess, sys

WORK, XR = sys.argv[1], sys.argv[2]
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
ACCESS = f"{WORK}/server-access.log"


def put(name, obj):
    with open(f"{WORK}/{name}.json", "w") as f:
        json.dump(obj, f, indent=1)


def run(*args):
    return subprocess.run([XR, *args], capture_output=True, text=True).stdout


def exe_name(cmd):
    """Process name Xray/sing-box see: the real file name after resolving symlinks."""
    return os.path.basename(os.path.realpath(shutil.which(cmd)))


# --- keys -----------------------------------------------------------------
x = run("x25519")
PRIV = next(l.split()[-1] for l in x.splitlines() if l.lower().startswith("privatekey"))
PUB = next(l.split()[-1] for l in x.splitlines() if "publickey" in l.lower())
v = run("vlessenc").splitlines()
DEC = next(l.split('"')[3] for l in v if '"decryption"' in l)
ENC = next(l.split('"')[3] for l in v if '"encryption"' in l)  # same call => matching pair

CURL, SOCAT, PYTHON = exe_name("curl"), exe_name("socat"), exe_name("python3")
with open(f"{WORK}/names.txt", "w") as f:
    f.write(f"curl={CURL} socat={SOCAT} python={PYTHON}\n")

# --- servers (run in the "internet" namespace) -------------------------------
def server(decryption, flow=None, reality=False):
    client = {"id": UUID}
    if flow:
        client["flow"] = flow
    stream = {"network": "tcp", "security": "none"}
    if reality:
        stream = {"network": "tcp", "security": "reality", "realitySettings": {
            "dest": "127.0.0.1:9443", "serverNames": ["www.example.com"], "privateKey": PRIV, "shortIds": ["ab12cd34"]}}
    return {"log": {"loglevel": "warning", "access": ACCESS},
            "inbounds": [{"listen": "0.0.0.0", "port": 8443, "protocol": "vless",
                          "settings": {"clients": [client], "decryption": decryption}, "streamSettings": stream}],
            # Xray 26.x freedom blocks the server's own addresses by default; the lab targets live there.
            "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]}


put("server_plain", server("none"))
put("server_enc", server(DEC))
put("server_reality", server("none", flow="xtls-rprx-vision", reality=True))

# --- Xray clients -------------------------------------------------------------
TUN = {"name": "xray0", "mtu": 1500, "gateway": ["10.255.0.1/24"]}


def tun(auto_routes=True, auto_iface="auto"):
    s = dict(TUN)
    if auto_routes:
        s["autoSystemRoutingTable"] = ["0.0.0.0/0"]
    if auto_iface is not None:
        s["autoOutboundsInterface"] = auto_iface
    return {"tag": "tun-in", "protocol": "tun", "settings": s,
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}}


def vless(addr, enc="none", flow=None, reality=False, fp="firefox"):
    user = {"id": UUID, "encryption": enc}
    if flow:
        user["flow"] = flow
    stream = {"network": "tcp", "security": "none"}
    if reality:
        stream = {"network": "tcp", "security": "reality", "realitySettings": {
            "serverName": "www.example.com", "fingerprint": fp, "publicKey": PUB, "shortId": "ab12cd34"}}
    return {"tag": "proxy", "protocol": "vless", "streamSettings": stream,
            "settings": {"vnext": [{"address": addr, "port": 8443, "users": [user]}]}}


DIRECT = {"tag": "direct", "protocol": "freedom"}


def client(inbound, outbounds, rules=None, dns=None):
    c = {"log": {"loglevel": "info"}, "inbounds": [inbound], "outbounds": outbounds,
         "routing": {"domainStrategy": "AsIs", "rules": rules or []}}
    if dns:
        c["dns"] = dns
    return c


plain = vless("10.0.0.2")  # private address: Xray allows unencrypted VLESS there
put("tun_all", client(tun(), [plain, DIRECT]))
put("tun_include", client(tun(), [DIRECT, plain],
    [{"type": "field", "process": [CURL, SOCAT], "outboundTag": "proxy"}]))
put("tun_exclude", client(tun(), [plain, DIRECT],
    [{"type": "field", "process": [PYTHON], "outboundTag": "direct"}]))

pub = "198.51.100.2"  # "public" address, reachable only through the default route
put("loop_auto_ip", client(tun(), [vless(pub, ENC), DIRECT]))
put("loop_manual_ip", client(tun(auto_routes=False, auto_iface=None), [vless(pub, ENC), DIRECT]))
put("loop_auto_domain", client(tun(), [vless("vps.test", ENC), DIRECT]))
put("loop_manual_domain", client(tun(auto_routes=False, auto_iface=None), [vless("vps.test", ENC), DIRECT]))
put("loop_dns_explicit", client(tun(), [vless("vps.test", ENC), DIRECT],
    dns={"servers": [{"address": "203.0.113.53", "port": 53}]}))

for name, flow in [("vision", "xtls-rprx-vision"), ("vision_udp443", "xtls-rprx-vision-udp443"), ("noflow", None)]:
    put(f"reality_{name}", client(tun(), [vless(pub, flow=flow, reality=True), DIRECT]))

# --- option B: sing-box TUN in front of an Xray socks inbound -----------------
socks = {"tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
         "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}}
put("xray_socks_reality", client(socks, [vless(pub, flow="xtls-rprx-vision", reality=True), DIRECT]))


def singbox(mode, loop_guard=True):
    rules = [{"process_name": ["xray"], "action": "route", "outbound": "direct"}] if loop_guard else []
    if mode == "include":
        rules.append({"process_name": [CURL, SOCAT], "action": "route", "outbound": "xray"})
        final = "direct"
    else:
        rules.append({"process_name": [PYTHON], "action": "route", "outbound": "direct"})
        final = "xray"
    return {"log": {"level": "info", "output": f"{WORK}/sb.log"},
            "inbounds": [{"type": "tun", "tag": "tun-in", "interface_name": "sb0",
                          "address": ["172.19.0.1/30"], "auto_route": True, "stack": "system"}],
            "outbounds": [{"type": "socks", "tag": "xray", "server": "127.0.0.1", "server_port": 10808, "version": "5"},
                          {"type": "direct", "tag": "direct"}],
            "route": {"auto_detect_interface": True, "rules": rules, "final": final}}


put("sb_include", singbox("include"))
put("sb_exclude", singbox("exclude"))
put("sb_exclude_noguard", singbox("exclude", loop_guard=False))

# Certificate for the local TLS 1.3 "dest" that Reality borrows its handshake from.
subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                "-keyout", f"{WORK}/dest.key", "-out", f"{WORK}/dest.crt", "-subj", "/CN=www.example.com",
                "-days", "2"], capture_output=True)
