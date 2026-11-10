#!/usr/bin/env python3
"""End-to-end test of the real elf-gate binary driving TUN, run inside the lab namespaces
(see scenarios/07-elfgate-e2e.sh). Every check prints PASS/FAIL; the exit code is the number of FAILs."""
import fcntl, json, os, pty, select, signal, struct, subprocess, sys, termios, time, glob, shutil

ELFGATE, XR, WORK, HERE = sys.argv[1], sys.argv[2], sys.argv[3], os.path.dirname(os.path.abspath(__file__))
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
failures = 0


def check(name, ok, detail=""):
    global failures
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok or not detail else f"   [{detail}]"), flush=True)
    failures += 0 if ok else 1


def sh(cmd, timeout=20):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout).stdout.strip()


def names():
    out = {}
    for line in open(f"{WORK}/names.txt").read().split():
        k, v = line.split("=")
        out[k] = v
    return out


NAMES = names()


class App:
    """elf-gate on a pty, with isolated config and state directories."""

    def __init__(self, tag, config_toml=None, args=()):
        """`config_toml=None` reuses the directories of an earlier run (state included)."""
        self.dir = f"{WORK}/e2e-{tag}"
        if config_toml is not None:
            shutil.rmtree(self.dir, ignore_errors=True)
            os.makedirs(f"{self.dir}/cfg/elf-gate")
            open(f"{self.dir}/cfg/elf-gate/config.toml", "w").write(config_toml)
        env = dict(os.environ, XDG_CONFIG_HOME=f"{self.dir}/cfg", XDG_STATE_HOME=f"{self.dir}/state",
                   ELF_GATE_LAB_TRUST_ALL="1", HOME=self.dir)
        env.pop("SUDO_USER", None)
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.environ.update(env)
            os.execv(ELFGATE, ["elf-gate", *args])
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        self.out = b""
        self.pump(1.0)

    def pump(self, t):
        end = time.time() + t
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if r:
                try:
                    self.out += os.read(self.fd, 65536)
                except OSError:
                    return

    def send(self, data, wait=0.5):
        os.write(self.fd, data)
        self.pump(wait)

    def log_text(self):
        return "\n".join(open(p, errors="ignore").read() for p in glob.glob(f"{self.dir}/state/elf-gate/logs/*"))

    def wait_log(self, needle, timeout=30):
        end = time.time() + timeout
        while time.time() < end:
            self.pump(0.3)
            if needle in self.log_text():
                return True
        return False

    def alive(self):
        try:
            return os.waitpid(self.pid, os.WNOHANG) == (0, 0)
        except ChildProcessError:
            return False

    def quit(self):
        self.send(b"q", 0.6)
        self.send(b"y", 0.6)
        end = time.time() + 10
        while self.alive() and time.time() < end:
            time.sleep(0.2)
        return not self.alive()


def config(routing="include", rules=(), presets=(), dns=False, last="manual/Lab"):
    # No local-direct here: the lab's addresses (203.0.113.0/24, 198.51.100.0/24) are in
    # geoip:private, so that preset would correctly send them direct.
    rules_toml = "".join(f'\n[[rules]]\nkind = "{k}"\nvalue = "{v}"\n' for k, v in rules)
    extra = ""
    if dns:  # point the DNS routing at the lab resolvers
        extra = 'local_dns = ["203.0.113.53"]\ntunnel_dns = "203.0.113.54"\n'
    return f'''[core]
xray_path = "{XR}"

[mode]
traffic = "tun"
routing = "{routing}"

[tun]
xray_path = "{XR}"
{extra}
[presets]
enabled = {json.dumps(list(presets))}

[ui]
last_server = "{last}"
tun_intro_done = true

[[servers]]
link = "vless://{UUID}@10.0.0.2:8443?security=none&type=tcp#Lab"
{rules_toml}'''


def iface_up(name="elfgate0"):
    return name in sh("ip -br link")


def wait_iface(up, timeout=20, name="elfgate0"):
    end = time.time() + timeout
    while time.time() < end:
        if iface_up(name) == up:
            return True
        time.sleep(0.2)
    return False


def web():
    return sh("curl -s --max-time 5 http://203.0.113.80:8080/") or "FAIL"


def pyweb():
    return sh("""python3 -c "
import urllib.request
try: print(urllib.request.urlopen('http://203.0.113.80:8080/',timeout=5).read().decode().strip())
except Exception as e: print('FAIL')" """) or "FAIL"


def dnsq(name):
    return sh(f"python3 {HERE}/dns_query.py 203.0.113.53 {name}")


def xray_pids():
    """Client-side xray processes (the lab server, also an xray, is excluded)."""
    out = []
    for p in sh("pgrep -x xray").split():
        try:
            cmd = open(f"/proc/{p}/cmdline", "rb").read().decode(errors="ignore")
        except OSError:
            continue
        if "server_plain" not in cmd:
            out.append(p)
    return out


def start_and_connect(tag, cfg, args=("--tun",)):
    app = App(tag, cfg, args)
    ok = app.wait_log("connected to", 40)
    check(f"[{tag}] elf-gate --tun connects", ok, app.log_text()[-300:])
    check(f"[{tag}] TUN interface elfgate0 is up", wait_iface(True, 5))
    return app


print("=== A. include mode: process rule curl -> VPN, everything else direct ===")
app = start_and_connect("include", config("include", [("process", NAMES["curl"])]))
check("[include] curl goes through the VPN", web() == "peer=203.0.113.80", web())
check("[include] python goes direct", pyweb() == "peer=10.0.0.1", pyweb())
check("[include] connection check passed", app.wait_log("connection check passed", 20), app.log_text()[-300:])
check("[include] xray is running", len(xray_pids()) == 1, str(xray_pids()))
state = json.load(open(f"{app.dir}/state/elf-gate/state.json")) if os.path.exists(f"{app.dir}/state/elf-gate/state.json") else {}
check("[include] state.json records the TUN", bool(state.get("tun")), str(state))
check("[include] system proxy was not touched in TUN mode", "sys-proxy" not in app.out.decode(errors="ignore"))
check("[include] quit stops everything", app.quit())
check("[include] interface gone after quit", wait_iface(False, 8))
check("[include] xray gone after quit", not xray_pids(), str(xray_pids()))
state = json.load(open(f"{app.dir}/state/elf-gate/state.json")) if os.path.exists(f"{app.dir}/state/elf-gate/state.json") else {}
check("[include] state.json cleared", not state.get("tun"), str(state))
check("[include] routes cleaned up", "elfgate0" not in sh("ip route"), sh("ip route"))

print("\n=== B. exclude mode: process rule python -> direct, everything else VPN ===")
app = start_and_connect("exclude", config("exclude", [("process", NAMES["python"])]))
check("[exclude] curl goes through the VPN", web() == "peer=203.0.113.80", web())
check("[exclude] python goes direct", pyweb() == "peer=10.0.0.1", pyweb())
check("[exclude] quit", app.quit())
check("[exclude] interface gone", wait_iface(False, 8))

print("\n=== C. DNS by domain: listed domain through the tunnel, others as before ===")
app = start_and_connect("dns", config("include", [("domain", "discord.test")], dns=True))
open(f"{WORK}/dns.log", "w").close(); open(f"{WORK}/dns54.log", "w").close()
check("[dns] discord.test resolves through the tunnel (tunnel resolver answers 7.7.7.7)", dnsq("discord.test") == "7.7.7.7", dnsq("discord.test"))
check("[dns] other.test resolves locally as before (local upstream answers 198.51.100.2)", dnsq("other.test") == "198.51.100.2", dnsq("other.test"))
local, tunnel = open(f"{WORK}/dns.log").read(), open(f"{WORK}/dns54.log").read()
check("[dns] the local upstream was asked directly from this machine, only for the other name",
      "other.test from 10.0.0.1" in local and "discord.test" not in local, local)
check("[dns] the tunnel resolver saw only the listed name, from the VPN side",
      "discord.test" in tunnel and "other.test" not in tunnel and "from 10.0.0.1" not in tunnel, tunnel)
check("[dns] quit", app.quit())

print("\n=== D. kill -9 of elf-gate leaves no tunnel behind ===")
app = start_and_connect("kill", config("include", [("process", NAMES["curl"])]))
xr = xray_pids()
check("[kill] xray runs before the kill", len(xr) == 1, str(xr))
os.kill(app.pid, signal.SIGKILL)
try:
    os.waitpid(app.pid, 0)
except ChildProcessError:
    pass
end = time.time() + 8
while xray_pids() and time.time() < end:
    time.sleep(0.2)
check("[kill] the core dies with elf-gate", not xray_pids(), str(xray_pids()))
check("[kill] TUN interface gone", wait_iface(False, 8))
check("[kill] routes gone and direct internet works", "elfgate0" not in sh("ip route") and web() == "peer=10.0.0.1", sh("ip route"))

print("\n=== E. the next start cleans up what the crash left in state.json ===")
state_path = f"{app.dir}/state/elf-gate/state.json"
check("[restart] state.json still names the dead run", bool(json.load(open(state_path)).get("tun")))
app2 = App("kill", None, ())  # same directories, no auto-connect
check("[restart] startup reports the cleanup", app2.wait_log("TUN:", 10), app2.log_text()[-300:])
check("[restart] state.json cleared", not json.load(open(state_path)).get("tun"))
app2.quit()

print("\n=== F. the capability supervisor stops the core when its parent is killed ===")
cfg_path = f"{WORK}/tun_all.json"  # the lab's plain TUN config (interface xray0)
parent = subprocess.Popen(["bash", "-c", f'"{ELFGATE}" --supervise "{XR}" run -c "{cfg_path}" >/dev/null 2>&1 & wait'])
check("[supervisor] the tunnel comes up", wait_iface(True, 15, "xray0"))
check("[supervisor] the core runs under the supervisor", len(xray_pids()) == 1, str(xray_pids()))
check("[supervisor] a supervisor process exists", bool(sh("pgrep -f -- '--supervise'")))
parent.kill()
end = time.time() + 10
while xray_pids() and time.time() < end:
    time.sleep(0.2)
check("[supervisor] killing the parent stops the core", not xray_pids(), str(xray_pids()))
check("[supervisor] and the tunnel is gone", wait_iface(False, 5, "xray0"))

print(f"\n{failures} failure(s)")
sys.exit(failures)
