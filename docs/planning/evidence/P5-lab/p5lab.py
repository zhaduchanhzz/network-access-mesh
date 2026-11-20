#!/usr/bin/env python3
"""Phase 5 — lab VM + thu bằng chứng (P5-T02), AC-20/V-02 (P5-T02a), AC-13/14 (P5-T05), IT-07/08 (P5-T05a).

  python -B p5lab.py <bước> [...]
  inventory          đẩy collect.sh (kiểm md5) lên mọi VM lab, `snapshot` ⇒ bảng kiểm kê (OS, client, mạng, đường tới
                     control: DNS công khai → VPS hay /etc/hosts → LAN, ép relay của tiến trình, netcheck, derp-map)
  paths              cặp cùng tenant (a1↔a2, b1↔b2): listener tạm 8000 (grant của fixture) + 8001 (ngoài grant),
                     `tailscale ping`, TCP thật, thời gian; gỡ listener
  relaydemo <vm>     phương pháp ép relay trên một client: bỏ TS_DEBUG_ALWAYS_USE_DERP ⇒ ping/TCP ⇒ trả về file gốc
                     (`collect.sh relay direct|off`) — hoàn tác trong cùng bước
  ac20               từ máy này qua Internet: quét TCP 1–65535 IP công khai, UDP (STUN 3478, cổng tunnel, cổng phổ biến),
                     `external.py --admin-public`, endpoint nội bộ trên MỌI hostname (app./admin./auth./*.mesh)
  v02                netcheck / derp-map / debug derp từ client LAN và client sau NAT của cả hai tenant; IP công khai do
                     STUN trả so với IP nguồn edge thấy qua PROXY protocol cho một request đánh dấu từ chính VM đó
  provision          2 tenant thử p5a-<hex>, p5b-<hex> (Owner qua create-user.sh, đăng nhập lần đầu + TOTP)
  t05                AC-13 (lab A/B thật + tenant thử) và AC-14: pre-auth key chéo tenant, Auth ID chéo tenant
  t05a               IT-07/IT-08: router + exit node có tag ở mỗi tenant thử (VM 105 kernel cho p5a, container cho p5b),
                     extra record ở mỗi tenant; kiểm từ client của tenant kia và từ lab A/B; hoàn tác
  exitsel            IT-08 "không chọn được exit node của tenant kia": quảng bá + duyệt lại, chọn theo hostname peer và theo
                     IP (trùng giữa hai tailnet ⇒ so node key của peer ExitNode), bỏ chọn, hoàn tác (gồm xóa record)
  provision a|b      provision lại một vai (tenant mới)
  cleanup           gỡ mọi thứ còn lại: listener, container, logout VM 105, deprovision 2P tenant thử, xóa credential
Chạy trên máy vận hành. Không có IP/domain trong file này: staging đọc từ staging.env qua tools/mgenv.py; VM lab từ
~/.meshguard/p5-lab.json (P5_LAB): {"jump": "root@<proxmox>", "vms": {"a1": {"ssh": "mgdeploy@<ip>", "tenant":
"tenant-a", "net": "lan|nat", "jump": false}, ..., "c": {...VM 105...}}}. Super Admin thử từ ~/.meshguard/g3-creds.json.
Mật khẩu/TOTP/key/Auth ID chỉ trong tiến trình + file 0600 ~/.meshguard/p5-*.json (xóa ở cleanup). Output đã che
(IP công khai ⇒ <vps>/a.b.c.x, domain ⇒ <domain>, hskey-… ⇒ [REDACTED]) trong P5_OUT (mặc định ~/.meshguard/p5-out).
"""
from __future__ import annotations

import concurrent.futures as cf
import hashlib
import io
import ipaddress
import json
import os
import pathlib
import re
import secrets
import shlex
import socket
import string
import subprocess
import sys
import tarfile
import time

sys.stdout.reconfigure(encoding="utf-8")
HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[3]   # docs/planning/evidence/P5-lab → gốc repo
sys.path[:0] = [str(ROOT / "tests" / "g3"), str(ROOT / "tests" / "e2e" / "harness"), str(ROOT / "tools"),
                str(ROOT / "tests" / "security" / "edge")]
import backend  # noqa: E402
import conformance as conf  # noqa: E402
import stun_probe  # noqa: E402
from g3platform import Platform, TargetBrowser  # noqa: E402
from g3target import Target, load_creds  # noqa: E402

HOME = pathlib.Path(os.path.expanduser("~/.meshguard"))
LABF = pathlib.Path(os.environ.get("P5_LAB") or HOME / "p5-lab.json")
STATE = HOME / "p5-state.json"
CREDS = HOME / "p5-creds.json"
TOTPF = HOME / "p5-totp-last.json"
OUT = pathlib.Path(os.environ.get("P5_OUT") or HOME / "p5-out")
OUT.mkdir(parents=True, exist_ok=True)
KEY = (pathlib.Path.home() / ".ssh" / "id_ed25519_meshguard").as_posix()   # "/" — ProxyCommand chạy qua shell
SSHBASE = ["ssh", "-i", KEY, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
           "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3"]
AUTH_RE = re.compile(r"https://([a-z0-9.-]+)/register/(hskey-authreq-[A-Za-z0-9_-]{24})")
ROUTE = {"a": "198.18.250.0/24", "b": "198.18.251.0/24"}   # dải benchmark (RFC 2544) — không trùng LAN/tailnet
EXIT = ["0.0.0.0/0", "::/0"]
TAG = "tag:p5-router"
RECORD = {"a": "p5a-secret.lab.test", "b": "p5b-secret.lab.test"}

t = Target(ROOT / "infrastructure/environments/staging/staging.env",
           {"host_docker": " ".join(SSHBASE) + " mgdeploy@${MG_LAN_IPV4} sudo -n docker"})
DOMAIN = t.domain
VPS = t.env["MG_PUBLIC_IPV4"]
HOSTSSH = SSHBASE + [f"mgdeploy@{t.env['MG_LAN_IPV4']}"]
LOG = open(OUT / "run.log", "a", encoding="utf-8")
RESULTS = OUT / "results.json"


# ------------------------------------------------------------------------------------------------ che + log
def mask_ip(m: re.Match) -> str:
    s = m.group(0)
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return s
    if s == VPS:
        return "<vps>"
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip in ipaddress.ip_network("100.64.0.0/10") \
            or ip in ipaddress.ip_network("198.18.0.0/15") or ip.is_unspecified or ip.is_multicast:
        return s
    return ".".join(s.split(".")[:3]) + ".x"


IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def redact(text: str) -> str:
    text = t.redact(text)
    text = text.replace(DOMAIN, "<domain>")
    return IPV4_RE.sub(mask_ip, text)


def log(*a) -> None:
    line = redact(time.strftime("%H:%M:%S", time.gmtime()) + " " + " ".join(str(x) for x in a))
    print(line, flush=True)
    LOG.write(line + "\n")
    LOG.flush()


def result(step: str, name: str, ok: bool | None, detail: str) -> bool | None:
    doc = json.loads(RESULTS.read_text(encoding="utf-8")) if RESULTS.exists() else {}
    doc.setdefault(step, []).append({"name": name, "ok": ok, "detail": redact(detail),
                                     "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    RESULTS.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    log(f"{'PASS' if ok else ('INFO' if ok is None else 'FAIL')} [{step}] {name} — {detail}")
    return ok


def load_state() -> dict:
    return json.loads(STATE.read_text(encoding="utf-8")) if STATE.exists() else {}


def save_state(st: dict) -> None:
    STATE.write_text(json.dumps(st, indent=1), encoding="utf-8")
    try:
        os.chmod(STATE, 0o600)
    except OSError:
        pass


def wait(fn, timeout: float, every: float = 2.0):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(every)
    return None


# ------------------------------------------------------------------------------------------------ ssh
def lab() -> dict:
    return json.loads(LABF.read_text(encoding="utf-8"))


def sshcmd(vm: str) -> list[str]:
    cfg = lab()
    v = cfg["vms"][vm]
    extra = []
    if v.get("jump"):
        extra = ["-o", "ProxyCommand=" + " ".join(SSHBASE) + f" -W %h:%p {cfg['jump']}"]
    return SSHBASE + extra + [v["ssh"]]


def run(cmd: list[str], stdin: bytes | None = None, timeout: float = 300, binary: bool = False):
    try:
        p = subprocess.run(cmd, input=stdin if stdin is not None else b"", capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, b"" if binary else "timeout"
    if binary:
        return p.returncode, p.stdout
    return p.returncode, (p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace")).strip()


SSH_FLAKE = ("UNKNOWN port 65535", "Connection timed out", "Connection closed by", "kex_exchange_identification",
             "Connection reset by")


def vm(name: str, cmd: str, stdin: bytes | None = None, timeout: float = 300) -> tuple[int, str]:
    """Lệnh trên VM lab; mạng tới LAN mất gói ⇒ lỗi kết nối SSH (255, chưa chạy lệnh) được thử lại tối đa 3 lần."""
    for i in range(4):
        rc, out = run(sshcmd(name) + [cmd], stdin, timeout)
        if not (rc == 255 and any(x in out for x in SSH_FLAKE)):
            return rc, out
        time.sleep(3 + 3 * i)
    return rc, out


def host(cmd: str, stdin: bytes | None = None, timeout: float = 300) -> str:
    return run(HOSTSSH + [cmd], stdin, timeout)[1]


def sql(q: str) -> str:
    return host("sudo -n docker exec -i mg-core-postgres-1 psql -X -At -U postgres -d meshguard", q.encode())


def hs_nodes(slug: str) -> list[dict]:
    try:
        return json.loads(host(f"sudo -n docker exec mg-hs-{slug} headscale nodes list -o json") or "[]") or []
    except ValueError:
        return []


def node_keys(nodes: list[dict]) -> set[str]:
    return {n.get("node_key") or n.get("nodeKey") or "" for n in nodes} - {""}


def push_collect(name: str) -> bool:
    body = (HERE / "collect.sh").read_bytes().replace(b"\r\n", b"\n")
    rc, out = vm(name, "mkdir -p ~/p5lab && chmod 0700 ~/p5lab && cat > ~/p5lab/collect.sh && md5sum ~/p5lab/collect.sh",
                 body, 60)
    ok = hashlib.md5(body).hexdigest() in out
    if not ok:
        log(f"  {name}: đẩy collect.sh LỖI rc={rc} {out[-200:]}")
    return ok


def collect(name: str, args: str, timeout: float = 300) -> tuple[int, str]:
    return vm(name, f"sh ~/p5lab/collect.sh {args}", None, timeout)


def fetch(name: str, label: str) -> tuple[pathlib.Path, dict[str, str]]:
    """`collect.sh pack` ⇒ OUT/<label>/<vm>/ (mỗi file văn bản đã che); trả kèm bản thô CHỈ trong bộ nhớ (so sánh IP)."""
    for i in range(4):
        rc, blob = run(sshcmd(name) + [f"sh ~/p5lab/collect.sh pack {label}"], None, 120, binary=True)
        if rc == 0 and blob:
            break
        time.sleep(3 + 3 * i)
    dst = OUT / label / name
    dst.mkdir(parents=True, exist_ok=True)
    raw: dict[str, str] = {}
    if rc != 0 or not blob:
        log(f"  {name}: pack {label} lỗi rc={rc}")
        return dst, raw
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            data = tf.extractfile(m).read().decode("utf-8", "replace")
            fn = pathlib.Path(m.name).name
            raw[fn] = data
            (dst / fn).write_text(redact(data), encoding="utf-8")
    return dst, raw


def jload(src) -> dict:
    """JSON từ một file (Path) hoặc văn bản thô (str); bỏ phần trước dấu { đầu tiên."""
    try:
        txt = src.read_text(encoding="utf-8") if isinstance(src, pathlib.Path) else (src or "")
        return json.JSONDecoder().raw_decode(txt[txt.index("{"):])[0] if "{" in txt else {}   # bỏ phần thừa sau JSON
    except (OSError, ValueError):
        return {}


def ip4(status: dict) -> str:
    return next((x for x in (status.get("Self") or {}).get("TailscaleIPs") or [] if "." in x), "")


# ------------------------------------------------------------------------------------------------ inventory (T02)
def kv(text: str) -> dict:
    return dict(x.split("=", 1) for x in (text or "").splitlines() if "=" in x)


def snapshot_summary(name: str, raw: dict[str, str]) -> dict:
    """Tóm tắt một snapshot từ bản THÔ (trong bộ nhớ); mọi trường văn bản trả ra đã che, trừ `_global_ip`/`_stun_ip`
    (IP công khai thô, chỉ dùng để so sánh rồi bỏ)."""
    st, nc, dm = jload(raw.get("status.json")), jload(raw.get("netcheck.json")), jload(raw.get("derp-map.json"))
    osx, net = kv(raw.get("os.txt", "")), kv(raw.get("net.txt", ""))
    proc_env = raw.get("tailscaled-flags.txt", "").split("(TS_*)", 1)[-1]
    regions = []
    for r in (dm.get("Regions") or {}).values():
        for n in r.get("Nodes") or []:
            regions.append({"id": r.get("RegionID"), "code": r.get("RegionCode"), "host": n.get("HostName"),
                            "ipv4": n.get("IPv4"), "stun": n.get("STUNPort"), "derp_port": n.get("DERPPort")})
    derp, stun_ip = {}, ""
    for fn, txt in raw.items():
        if not fn.startswith("debug-derp-"):
            continue
        j = jload(txt)
        line = next((x for x in j.get("Info") or [] if "STUN" in x), "")
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)", line)
        stun_ip = m.group(1) if m else stun_ip
        derp[fn[len("debug-derp-"):-5]] = {
            "ok": any("Successfully established a DERP connection" in x for x in j.get("Info") or []),
            "stun": redact(line), "errors": [redact(e) for e in j.get("Errors") or []],
            "warnings": [redact(w) for w in j.get("Warnings") or []]}
    peers = []
    for p in (st.get("Peer") or {}).values():
        peers.append({"name": p.get("HostName"), "online": p.get("Online"), "relay": p.get("Relay"),
                      "cur_addr": redact(p.get("CurAddr") or ""), "peer_relay": p.get("PeerRelay", ""),
                      "exit_option": p.get("ExitNodeOption"), "primary_routes": p.get("PrimaryRoutes") or [],
                      "key": p.get("PublicKey")})
    ctl_ip = net.get("getent", "")
    gv4 = nc.get("GlobalV4", "") or ""
    return {
        "vm": name, "os": osx.get("os"), "kernel": osx.get("kernel"),
        "tailscale": (raw.get("version.txt", "").splitlines() or [""])[0],
        "backend": st.get("BackendState"), "self": (st.get("Self") or {}).get("HostName"), "self_ip": ip4(st),
        "self_key": (st.get("Self") or {}).get("PublicKey"),
        "tailnet": redact(((st.get("CurrentTailnet") or {}).get("Name") or "")),
        "magic_suffix": redact(((st.get("CurrentTailnet") or {}).get("MagicDNSSuffix") or "")),
        "peers": peers, "control": redact(net.get("control_host", "")),
        "control_resolves_to": redact(ctl_ip),
        "control_via": ("(chưa đăng nhập)" if not net.get("control_host") else
                        "DNS công khai → VPS → tunnel → edge" if ctl_ip == VPS else
                        "/etc/hosts → edge LAN-direct" if net.get("etc_hosts", "0") not in ("0", "") else "?"),
        "default_route": redact(net.get("default_route", "")), "addr": redact(net.get("addr", "")),
        "forced_derp_process": "TS_DEBUG_ALWAYS_USE_DERP=true" in proc_env,
        "netcheck": {"udp": nc.get("UDP"), "global_v4": redact(gv4), "mapping_varies": nc.get("MappingVariesByDestIP"),
                     "preferred_derp": nc.get("PreferredDERP"),
                     "latency": {k: round(v / 1e6, 2) for k, v in (nc.get("RegionLatency") or {}).items()}},
        "derp_map": [{**r, "ipv4": redact(r["ipv4"] or ""), "host": redact(r["host"] or "")} for r in regions],
        "derp_map_ipv4_is_vps": bool(regions) and all(r["ipv4"] == VPS for r in regions),
        "debug_derp": derp,
        "_global_ip": gv4.rsplit(":", 1)[0] if gv4 else "", "_stun_ip": stun_ip,
    }


def do_snapshot(name: str, label: str) -> dict:
    push_collect(name)
    collect(name, f"snapshot {label}", 240)
    _, raw = fetch(name, label)
    return snapshot_summary(name, raw)


def cmd_inventory() -> None:
    label = "inv-" + time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    rows = {}
    with cf.ThreadPoolExecutor(max_workers=5) as ex:
        futs = {ex.submit(do_snapshot, n, label): n for n in lab()["vms"]}
        for f in cf.as_completed(futs):
            rows[futs[f]] = f.result()
    for n in sorted(rows):
        s = rows[n]
        s.pop("_global_ip", None)
        s.pop("_stun_ip", None)
        result("inventory", f"{n} ({lab()['vms'][n].get('tenant') or '—'}, {lab()['vms'][n].get('net')})",
               s["tailscale"].startswith("1.10") and (s["backend"] in ("Running", "NeedsLogin", "Stopped")),
               f"{s['os']} {s['kernel']}; Tailscale {s['tailscale']}; {s['backend']} self {s['self']} {s['self_ip']}; "
               f"control {s['control_via']}; ép relay (tiến trình) {s['forced_derp_process']}; route {s['default_route']}; "
               f"peers {[(p['name'], p['online'], p['cur_addr'] or ('DERP(' + str(p['relay']) + ')')) for p in s['peers']]}; "
               f"netcheck UDP {s['netcheck']['udp']} v4 {s['netcheck']['global_v4']} DERP ưu tiên {s['netcheck']['preferred_derp']} "
               f"{s['netcheck']['latency']}; derp-map {[(r['id'], r['code'], r['ipv4'], r['stun']) for r in s['derp_map']]}; "
               f"debug derp {s['debug_derp']}")
    (OUT / "inventory.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    log("inventory ⇒", OUT / "inventory.json")


# ------------------------------------------------------------------------------------------------ paths (T02)
PAIRS = [("a1", "a2"), ("a2", "a1"), ("b1", "b2"), ("b2", "b1")]


def cmd_paths() -> None:
    label = "paths-" + time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    ips = {}
    for n in ("a1", "a2", "b1", "b2"):
        push_collect(n)
        rc, out = vm(n, "tailscale ip -4")
        ips[n] = out.strip().splitlines()[0] if rc == 0 and out.strip() else ""
        for port in (8000, 8001):
            rc, out = collect(n, f"listen {port}")
            log(f"  {n} listen {port}: {out}")
    try:
        for src, dst in PAIRS:
            rc, ping = collect(src, f"ping {label} {ips[dst]} 3", 90)
            via = next((ln for ln in ping.splitlines() if "pong" in ln), ping.splitlines()[-1] if ping else "")
            rc8, o8 = collect(src, f"tcp {label} {ips[dst]} 8000 5", 60)
            rc9, o9 = collect(src, f"tcp {label} {ips[dst]} 8001 5", 60)
            result("paths", f"{src}→{dst}: ping + TCP 8000 (grant) / 8001 (ngoài grant)",
                   o8.startswith("OPEN") and not o9.startswith("OPEN"),
                   f"ping: {via.strip()}; tcp/8000: {o8.strip()}; tcp/8001: {o9.strip()}")
        for n in ("a1", "a2", "b1", "b2"):
            fetch(n, label)
    finally:
        for n in ("a1", "a2", "b1", "b2"):
            for port in (8000, 8001):
                collect(n, f"unlisten {port}")
        log("  listener tạm đã gỡ trên a1/a2/b1/b2")


def cmd_relaydemo(name: str) -> None:
    """Trên client ép relay sẵn (a2/b2): tắt ép relay tạm ⇒ đo ⇒ trả về file gốc. Hoàn tác trong cùng bước."""
    peer = {"a2": "a1", "b2": "b1", "a1": "a2", "b1": "b2"}[name]
    label = f"relaydemo-{name}-" + time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    push_collect(name)
    push_collect(peer)
    pip = vm(peer, "tailscale ip -4")[1].strip().splitlines()[0]
    collect(peer, "listen 8000")
    try:
        rc, before = collect(name, "relay status")
        rc, p1 = collect(name, f"ping {label} {pip} 5", 90)
        rc, t1 = collect(name, f"tcp {label} {pip} 8000 5", 60)
        rc, flip = collect(name, "relay direct", 120)
        time.sleep(5)
        rc, t2 = collect(name, f"tcp {label} {pip} 8000 5", 60)
        rc, p2 = collect(name, f"ping {label} {pip} 10", 120)
        rc, back = collect(name, "relay off", 120)
        time.sleep(3)
        rc, p3 = collect(name, f"ping {label} {pip} 5", 90)
        rc, after = collect(name, "relay status")
        last = lambda s: next((ln for ln in reversed(s.splitlines()) if "pong" in ln), s.splitlines()[-1] if s else "")  # noqa: E731
        result("relaydemo", f"{name}→{peer}: ép relay (TS_DEBUG_ALWAYS_USE_DERP) ⇒ bỏ ⇒ trả lại",
               "DERP(" in last(p1) and "DERP(" not in last(p2) and "DERP(" in last(p3) and before.strip() == after.strip(),
               f"ban đầu [{before.strip()}]: {last(p1).strip()} | tcp {t1.strip()}; bỏ ép [{flip.strip()}]: {last(p2).strip()} | "
               f"tcp {t2.strip()}; trả lại [{back.strip()}]: {last(p3).strip()}; trạng thái cuối = ban đầu {before.strip() == after.strip()}")
        fetch(name, label)
    finally:
        collect(name, "relay off", 120)
        collect(peer, "unlisten 8000")


# ------------------------------------------------------------------------------------------------ ac20 (T02a)
COMMON_UDP = [53, 67, 69, 123, 137, 161, 500, 514, 1194, 1900, 3479, 4500, 5060, 5353, 11211, 41641]


def tcp_scan(ip: str, ports: range, workers: int = 400, timeout: float = 1.5) -> dict[int, str]:
    def probe(port: int) -> tuple[int, str]:
        s = socket.socket()
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            return port, "open"
        except socket.timeout:
            return port, "filtered"
        except ConnectionRefusedError:
            return port, "closed"
        except OSError as e:
            return port, f"error {e.errno}"
        finally:
            s.close()
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        return dict(ex.map(probe, ports))


def udp_probe(ip: str, port: int, timeout: float = 2.0) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.send(b"\x00p5lab-probe\x00")
        s.recv(512)
        return "answered"
    except socket.timeout:
        return "no-answer"
    except ConnectionResetError:
        return "icmp-unreachable"
    except OSError as e:
        return f"error {e.errno}"
    finally:
        s.close()


SPA_MARK = b'id="root"'
LEAK_MARKS = [b"# HELP", b"# TYPE", b"go_goroutines", b"process_cpu_seconds", b"headscale", b"Headscale",
              b"swagger", b"\"decisions\"", b"crowdsec", b"Keycloak Administration", b"keycloak.v2.admin",
              b"pprof", b"\"Containers\"", b"\"admin\":", b"\"apps\":", b"\"status\":\"ok\"", b"\"status\": \"ok\"",
              b"serving\"", b"\"version\":"]
INTERNAL_PATHS = ["/internal/", "/internal/prometheus/sd", "/internal/health", "/metrics", "/healthz", "/readyz",
                  "/livez", "/api/v1/healthz", "/api/v1/metrics", "/api/v1/internal/x", "/api/v1/apikey",
                  "/api/v1/node", "/api/v1/policy", "/swagger", "/swagger/", "/swagger/v1/openapiv2.json", "/verify",
                  "/debug/pprof/", "/debug/vars", "/debug/", "/version", "/health", "/admin/", "/admin/master/console/",
                  "/realms/master/", "/realms/master/protocol/openid-connect/certs", "/q/metrics", "/q/health",
                  "/config/", "/load", "/id/", "/reverse_proxy/upstreams", "/v1/decisions", "/v1/heartbeat",
                  "/v1.41/containers/json", "/_ping", "/grafana/", "/api/health", "/-/healthy", "/api/v1/status/config",
                  "/api/v1/../metrics", "/api/v1/..%2fmetrics", "/api/v1/%2e%2e/internal/prometheus/sd",
                  "/api/v1/auth/../../internal/prometheus/sd", "/%2e%2e/internal/", "/api/v1/internal/prometheus/sd"]


def classify(host_: str, path: str) -> tuple[bool, str]:
    st, hdr, body = conf.https(VPS, host_, "GET", path, timeout=10)
    if st is None:
        return True, f"không TLS/không trả lời ({str(hdr)[:40]})"
    leak = [m.decode() for m in LEAK_MARKS if m in body]
    spa = SPA_MARK in body
    ct = (hdr.get("Content-Type") or hdr.get("content-type") or "")[:24]
    if leak and not spa:
        return False, f"{st} {ct} LỘ {leak}"
    if st in (400, 401, 403, 404, 405, 421, 308, 301, 302) or (st == 200 and spa):
        return True, f"{st}{' SPA' if spa else ''}"
    return False, f"{st} {ct} body {body[:60]!r}"


TESTNET = "203.0.113.10"   # RFC 5737 TEST-NET-3: không định tuyến ⇒ "mở" ở đây = middlebox trên đường đi của máy quét


def confirm(ip: str, port: int, tries: int = 3, timeout: float = 4.0) -> int:
    """Số lần kết nối được trong `tries` lần tuần tự (không song song — tránh tràn bảng conntrack của router)."""
    ok = 0
    for _ in range(tries):
        ok += tcp_scan(ip, range(port, port + 1), 1, timeout)[port] == "open"
        time.sleep(0.3)
    return ok


def cmd_ac20() -> None:
    """Quét nhẹ (P5_SCAN_WORKERS mặc định 64, timeout 1,5 s): lượt đầu 400 luồng làm tràn bảng conntrack của router
    phía máy quét ⇒ cổng mở bị báo nhầm là filtered (2026-11-20 — mục 2 của P5-T02a)."""
    workers = int(os.environ.get("P5_SCAN_WORKERS", "64"))
    tmo = float(os.environ.get("P5_SCAN_TIMEOUT", "1.5"))
    t0 = time.time()
    res = tcp_scan(VPS, range(1, 65536), workers, tmo)
    open_ports = sorted(p for p, s in res.items() if s == "open")
    closed = [p for p, s in res.items() if s == "closed"]
    errs = {p: s for p, s in res.items() if s.startswith("error")}
    expected = {80, 443}
    known = {22: "SSH quản trị (key-only) — ngoại lệ đã ghi ở G1", 587: "thư của chủ dự án (P1-T15)",
             25: "thư của chủ dự án (P1-T15)"}
    time.sleep(60)
    verify = {p: confirm(VPS, p) for p in sorted(set(open_ports) | expected | set(known))}
    intercept = {p: confirm(TESTNET, p, 2) for p in open_ports if p not in expected and p not in known}
    real_open = sorted(p for p, n in verify.items() if n > 0 and not intercept.get(p))
    extra = [p for p in real_open if p not in expected and p not in known]
    result("ac20", "quét TCP 1–65535 IP công khai (máy vận hành → Internet → VPS) + kiểm lại tuần tự",
           not extra and expected <= set(real_open),
           f"{len(res)} cổng, {workers} luồng, timeout {tmo} s, {time.time() - t0:.0f} s; lượt quét thấy mở {open_ports}; "
           f"RST {len(closed)}; timeout/drop {len(res) - len(open_ports) - len(closed) - len(errs)}; lỗi {len(errs)}; "
           f"kiểm lại 3 lần tuần tự (số lần kết nối được) {verify}; cùng cổng tới TEST-NET-3 (không định tuyến) {intercept} "
           f"⇒ mở thật {real_open} — ngoài 80/443: { {p: known.get(p, 'KHÔNG MONG ĐỢI') for p in real_open if p not in expected} }; "
           f"bị middlebox phía máy quét trả lời {sorted(p for p, n in intercept.items() if n)}")
    try:
        mapped = stun_probe.probe(VPS, 3478)
        result("ac20", "UDP 3478 (stund) trả lời STUN Binding", True, f"XOR-MAPPED-ADDRESS {mapped[0]}:{mapped[1]}")
        st = load_state()
        st["operator_wan_ip"] = mapped[0]
        save_state(st)
    except Exception as e:  # noqa: BLE001
        result("ac20", "UDP 3478 (stund) trả lời STUN Binding", False, f"{type(e).__name__}: {e}")
    tun = int(t.env.get("MG_TUNNEL_PORT", "0") or 0)
    udp = {p: udp_probe(VPS, p) for p in sorted(set(COMMON_UDP + ([tun] if tun else [])))}
    answered = [p for p, s in udp.items() if s == "answered"]
    result("ac20", "UDP: cổng phổ biến + cổng tunnel (gói rác)", not answered,
           f"{udp}; cổng tunnel (MG_TUNNEL_PORT) {udp.get(tun)} — WireGuard im lặng với gói không xác thực nên "
           "'no-answer' không phân biệt mở/drop từ ngoài")
    rc, out = run([sys.executable, "-I", str(ROOT / "tests/security/edge/external.py"), VPS, f"mesh.{DOMAIN}",
                   "tenant-a,tenant-b" + "".join("," + s for s in load_state().get("slugs", {}).values()), "--admin-public"],
                  None, 1800)
    (OUT / "external.txt").write_text(redact(out), encoding="utf-8")
    summary = [ln for ln in out.splitlines() if ln.startswith(("TCP scan", "AC-20", "FAIL", "PASS ", "OK", "RESULT"))][-6:]
    result("ac20", "external.py --admin-public (path cấm, traversal, :80, /key, SNI lạ, admin. public + cổng console)",
           rc == 0, f"rc {rc}; " + " | ".join(summary)[-900:])
    hosts = [f"app.{DOMAIN}", f"admin.{DOMAIN}", f"auth.{DOMAIN}", f"tenant-a.mesh.{DOMAIN}", f"tenant-b.mesh.{DOMAIN}",
             f"nope-tenant.mesh.{DOMAIN}"] + [f"{s}.mesh.{DOMAIN}" for s in load_state().get("slugs", {}).values()]
    rows, fails = [], []
    for h in hosts:
        for p in INTERNAL_PATHS:
            ok, what = classify(h, p)
            rows.append((h, p, ok, what))
            if not ok:
                fails.append((h, p, what))
    by_host = {redact(h): f"{sum(1 for r in rows if r[0] == h and r[2])}/{sum(1 for r in rows if r[0] == h)}" for h in hosts}
    (OUT / "ac20-internal.json").write_text(json.dumps([(redact(h), p, ok, w) for h, p, ok, w in rows], ensure_ascii=False,
                                                       indent=0), encoding="utf-8")
    dist = {}
    for _, _, _, w in rows:
        dist[w.split(" (")[0]] = dist.get(w.split(" (")[0], 0) + 1
    result("ac20", f"endpoint nội bộ trên mọi hostname qua VPS ({len(INTERNAL_PATHS)} path × {len(hosts)} host)", not fails,
           f"{len(rows) - len(fails)}/{len(rows)} không tới được backend; theo host {by_host}; kiểu trả lời {dist}; LỖI {fails[:6]}")


# ------------------------------------------------------------------------------------------------ v02 (T02a)
def edge_seen_ip(marker: str) -> str:
    out = host(f"sudo -n grep -h -F {shlex.quote(marker)} /opt/meshguard/logs/edge/access.log | tail -1")
    try:
        j = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return ""
    req = j.get("request") or {}
    return req.get("client_ip") or req.get("remote_ip") or ""


def cmd_v02() -> None:
    label = "v02-" + time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    for n in ("a1", "b1", "a2", "b2"):
        s = do_snapshot(n, label)
        marker = f"/p5v02-{secrets.token_hex(4)}-{n}"
        rc, code = vm(n, f"curl -s -o /dev/null -w '%{{http_code}} %{{remote_ip}}' --max-time 15 https://app.{DOMAIN}{marker}")
        time.sleep(1.5)
        seen = edge_seen_ip(marker)
        gip = s.pop("_global_ip", "")
        derp_ok = all(v["ok"] for v in s["debug_derp"].values()) and bool(s["debug_derp"])
        stun_line = " / ".join(v["stun"] for v in s["debug_derp"].values())
        stun_ip = s.pop("_stun_ip", "")
        result("v02", f"{n} ({lab()['vms'][n]['tenant']}, {lab()['vms'][n]['net']}): netcheck + derp-map + debug derp",
               bool(s["netcheck"]["udp"]) and s["derp_map_ipv4_is_vps"] and derp_ok and bool(gip) and gip == seen
               and all(r["stun"] == 3478 for r in s["derp_map"]),
               f"UDP {s['netcheck']['udp']}; GlobalV4 {s['netcheck']['global_v4']}; DERP ưu tiên {s['netcheck']['preferred_derp']} "
               f"{s['netcheck']['latency']} ms; derp-map {[(r['id'], r['code'], r['ipv4'], r['stun']) for r in s['derp_map']]}; "
               f"debug derp {[(k, v['ok'], v['errors']) for k, v in s['debug_derp'].items()]}; STUN của debug derp: {stun_line}; "
               f"IP edge thấy (PROXY v2) cho request đánh dấu từ {n} qua DNS công khai: {redact(seen)} (curl {redact(code)}) ⇒ "
               f"= IP của netcheck {gip == seen and bool(gip)}, = IP STUN của debug derp {stun_ip == seen and bool(seen)}")
    op = load_state().get("operator_wan_ip", "")
    if op:
        marker = f"/p5v02-{secrets.token_hex(4)}-op"
        conf.https(VPS, f"app.{DOMAIN}", "GET", marker)
        time.sleep(1.5)
        seen = edge_seen_ip(marker)
        result("v02", "máy vận hành (điểm quét AC-20): STUN 3478 vs IP edge thấy", op == seen,
               f"STUN {redact(op)}; edge {redact(seen)}; cùng mạng với lab: {op == load_state().get('lab_wan', '')}")


# ------------------------------------------------------------------------------------------------ tenant thử
class Owner:
    def __init__(self, slug: str):
        creds = json.loads(CREDS.read_text(encoding="utf-8"))[slug]
        self.slug = slug
        self.user = {"username": creds["username"], "password": creds["password"]}
        t.secret_values.add(creds["password"])
        self.otp = backend.TOTP()
        self.otp.key = creds.get("totp_raw", "").encode()
        self.otp.last = int(creds.get("totp_last", 0))
        if creds.get("totp_raw"):
            t.secret_values.add(creds["totp_raw"])
        self.host = f"app.{DOMAIN}"
        self.b = TargetBrowser(t)
        self.sess: dict = {}
        self.tid = ""

    def login(self) -> list[str]:
        self.b = TargetBrowser(t)
        self.sess, steps = backend.portal_login(t, self.b, self.host, f"scope=tenant&tenant={self.slug}", self.user, self.otp)
        c = json.loads(CREDS.read_text(encoding="utf-8"))
        c[self.slug].update(totp_raw=self.otp.key.decode(), totp_last=self.otp.last)
        CREDS.write_text(json.dumps(c), encoding="utf-8")
        t.secret_values.add(self.otp.key.decode())
        self.tid = next((m.get("tenant_id") for m in self.sess.get("memberships") or [] if m.get("tenant_slug") == self.slug), "")
        return steps

    def call(self, method: str, path: str, body=None, idem: str | None = None, if_match: str | None = None,
             tries: int = 8) -> backend.Resp:
        if not self.sess:
            self.login()
        data = json.dumps(body).encode() if body is not None else None
        h = None
        if method != "GET":
            h = {"Origin": f"https://{self.host}", "X-CSRF-Token": self.sess.get("csrf_token", ""),
                 "Content-Type": "application/json"}
            if idem:
                h["Idempotency-Key"] = idem
            if if_match:
                h["If-Match"] = if_match
        r = None
        for _ in range(tries):
            r = self.b.request(method, f"https://{self.host}/api/v1{path}", data if data is not None else
                               (b"" if method != "GET" else None), h)
            if r.status == 429:
                try:
                    w = min(30.0, float(r.header("Retry-After") or 5))
                except ValueError:
                    w = 5.0
                time.sleep(w + 0.5)
                continue
            if r.status == 401 and r.json().get("code") in ("reauth_required", "unauthenticated"):
                self.login()
                if h:
                    h["X-CSRF-Token"] = self.sess.get("csrf_token", "")
                continue
            return r
        return r

    def T(self, path: str = "") -> str:
        return f"/tenants/{self.tid}{path}"

    def job(self, jid: str, timeout: float = 300) -> dict:
        end, doc = time.time() + timeout, {}
        while time.time() < end:
            r = self.call("GET", self.T(f"/jobs/{jid}"))
            doc = r.json() if r.status == 200 else {"status": f"HTTP {r.status}"}
            if doc.get("status") in ("succeeded", "failed", "cancelled", "rolled_back", "failed_resumable"):
                return doc
            time.sleep(2)
        return doc


def platform() -> Platform:
    pf = Platform(t, load_creds(HOME / "g3-creds.json", t))
    last = {}
    for f in (HOME / "g4a-totp-last.json", TOTPF):
        if f.exists():
            for k, v in json.loads(f.read_text()).items():
                last[k] = max(int(v), int(last.get(k, 0)))
    for s_ in (pf.a, pf.b):
        s_.otp.last = int(last.get(s_.user["username"], 0))
        orig = s_.login

        def wrapped(orig=orig, s_=s_):
            orig()
            d = json.loads(TOTPF.read_text()) if TOTPF.exists() else {}
            d[s_.user["username"]] = s_.otp.last
            TOTPF.write_text(json.dumps(d))
        s_.login = wrapped
    return pf


def cmd_provision(roles: list[str] | None = None) -> None:
    st = load_state()
    pf = platform()
    pf.a.fresh()
    hexs = secrets.token_hex(2)
    st.setdefault("slugs", {})
    for role in roles or ["a", "b"]:
        slug = st["slugs"].get(role) or f"p5{role}-{hexs}"
        st["slugs"][role] = slug
        save_state(st)
        email = f"owner@{slug}.example.invalid"
        t0 = time.time()
        r, job = pf.create_tenant(slug, email)
        done = pf.wait_job(job.get("id", ""), timeout=600)
        tid = done.get("tenant_id") or next((x["id"] for x in pf.get("/platform/tenants").get("items", []) if x.get("slug") == slug), "")
        inst = next((x for x in pf.get("/platform/instances").get("items", []) if x.get("tenant_id") == tid), {})
        st.setdefault("tenants", {})[role] = {"slug": slug, "tenant_id": tid, "instance_id": inst.get("id", "")}
        save_state(st)
        result("provision", f"tenant thử {role}: SA1 POST /platform/tenants ⇒ tenant.provision",
               r.status == 202 and done.get("status") == "succeeded",
               f"{slug}: HTTP {r.status}; job {done.get('status')} {time.time() - t0:.1f} s; {len(done.get('steps') or [])} bước")
        pw = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        t.secret_values.add(pw)
        creds = json.loads(CREDS.read_text(encoding="utf-8")) if CREDS.exists() else {}   # đọc lại: Owner.login ghi file
        creds[slug] = {"username": f"{slug}-owner", "password": pw, "email": email}
        CREDS.write_text(json.dumps(creds), encoding="utf-8")
        try:
            os.chmod(CREDS, 0o600)
        except OSError:
            pass
        out = host(f"cd ~/mg && sudo -n bash infrastructure/idp/create-user.sh {slug} {slug}-owner {email} P5 Owner",
                   (pw + "\n").encode())
        o = Owner(slug)
        steps = o.login()
        ms = [(m.get("tenant_slug"), m.get("role")) for m in o.sess.get("memberships") or []]
        result("provision", f"Owner {role} (create-user.sh + đăng nhập lần đầu, TOTP)",
               ("created" in out or "exists" in out) and (slug, "tenant_owner") in ms,
               f"create-user {out.splitlines()[-1][:60] if out else ''}; bước {steps}; memberships {ms}")
        st["tenants"][role]["membership"] = next((m.get("membership_id") or m.get("id") for m in o.sess.get("memberships") or []
                                                  if m.get("tenant_slug") == slug), "")
        save_state(st)


# ------------------------------------------------------------------------------------------------ client container (VM 105)
def cdock(cmd: str, stdin: bytes | None = None, timeout: float = 180) -> tuple[int, str]:
    return vm("c", f"sudo -n docker {cmd}", stdin, timeout)


def cexec(name: str, cmd: str, stdin: bytes | None = None, timeout: float = 150) -> tuple[int, str]:
    return cdock(f"exec {'-i ' if stdin is not None else ''}{name} sh -c {shlex.quote(cmd)}", stdin, timeout)


def ctl(name: str) -> str:
    return f"tailscale --socket=/tmp/ts.sock"


def cstart(name: str) -> None:
    run_sh = ("tailscaled --tun=userspace-networking --state=mem: --socket=/tmp/ts.sock --statedir=/tmp/st "
              ">/tmp/tsd.log 2>&1 & exec sleep infinity")
    cdock(f"rm -f {name} >/dev/null 2>&1; true")
    rc, out = cdock(f"run -d --name {name} --hostname {name} --network bridge --read-only "
                    "--tmpfs /tmp:size=16m,mode=1777 --tmpfs /run/p5:size=1m,mode=0700 --cap-drop ALL "
                    "--security-opt no-new-privileges:true --memory 256m --pids-limit 128 --label meshguard.role=p5-client "
                    f"-e TS_NO_LOGS_NO_SUPPORT=true --entrypoint sh {t.images['tailscale']} -c {shlex.quote(run_sh)}")
    cexec(name, "i=0; while [ ! -S /tmp/ts.sock ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done")
    log(f"  container {name}: rc {rc}")


def cstatus(name: str) -> dict:
    rc, out = cexec(name, f"{ctl(name)} status --json")
    try:
        return json.loads(out[out.index("{"):]) if "{" in out else {}
    except ValueError:
        return {}


def cup_key(name: str, key: str, login: str, extra: str = "", expect_ok: bool = True) -> tuple[int, str, str]:
    """tailscale up --auth-key=file: trong container; trả (rc, BackendState, thông điệp đã che)."""
    cexec(name, "umask 077; cat > /run/p5/authkey", stdin=key.encode())
    rc, out = cexec(name, f"timeout 75 {ctl(name)} up --login-server={login} --auth-key=file:/run/p5/authkey "
                          f"--hostname={name} --accept-dns=false --timeout=60s {extra}; rc=$?; rm -f /run/p5/authkey; exit $rc",
                    timeout=120)
    s = cstatus(name)
    return rc, s.get("BackendState", "?"), redact(out.replace("\n", " "))[-200:]


def preauth(o: Owner, label: str) -> str:
    r = o.call("POST", o.T("/enrollment/requests"), {"method": "preauth_key", "device_label": label, "ttl_minutes": 10},
               idem="p5-pk-" + secrets.token_hex(6))
    key = ((r.json().get("credential") or {}).get("preauth_key", "")) if r.status == 201 else ""
    if key:
        t.secret_values.add(key)
    else:
        log(f"  preauth {label}: HTTP {r.status} {r.json().get('code')}")
    return key


def login_url(slug: str) -> str:
    return f"https://{slug}.mesh.{DOMAIN}"


# ------------------------------------------------------------------------------------------------ t05
def cmd_t05() -> None:
    st = load_state()
    A, B = st["tenants"]["a"], st["tenants"]["b"]
    oa, ob = Owner(A["slug"]), Owner(B["slug"])
    oa.login()
    ob.login()
    # ---------------------------------------------------------------- AC-13 trên lab thật (tenant-a / tenant-b)
    keys = {s: node_keys(hs_nodes(s)) for s in ("tenant-a", "tenant-b", A["slug"], B["slug"])}
    label = "t05-" + time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    for n in ("a1", "a2", "b1", "b2"):
        push_collect(n)
        collect(n, f"snapshot {label}", 240)
        _, raw = fetch(n, label)
        s = jload(raw.get("status.json"))
        mine = lab()["vms"][n]["tenant"]
        other = "tenant-b" if mine == "tenant-a" else "tenant-a"
        pk = {p.get("PublicKey") for p in (s.get("Peer") or {}).values()}
        same = pk & keys[mine]
        foreign = pk & (keys[other] | keys[A["slug"]] | keys[B["slug"]])
        result("t05", f"AC-13 {n} ({mine}): status --json có peer cùng tenant, 0 node key của tenant khác",
               len(same) >= 1 and not foreign and (s.get("Self") or {}).get("PublicKey") in keys[mine],
               f"{len(pk)} peer; cùng tenant {len(same)} ({[p.get('HostName') for p in (s.get('Peer') or {}).values()]}); "
               f"node key của {other}/{A['slug']}/{B['slug']} ({len(keys[other])}/{len(keys[A['slug']])}/{len(keys[B['slug']])} key "
               f"từ `headscale nodes list`) xuất hiện: {len(foreign)}")
    # ---------------------------------------------------------------- AC-14: pre-auth key chéo tenant
    for name in ("p5-ma", "p5-mb"):
        cstart(name)
    ka, kb = preauth(oa, "p5-ma"), preauth(ob, "p5-mb")
    before = {s: len(hs_nodes(s)) for s in (A["slug"], B["slug"], "tenant-a", "tenant-b")}
    cases = [("p5-ma", ka, B["slug"], "key A → login server B"), ("p5-ma", ka, "tenant-b", "key A → tenant-b"),
             ("p5-mb", kb, A["slug"], "key B → login server A"), ("p5-mb", kb, "tenant-a", "key B → tenant-a")]
    for name, key, target, what in cases:
        rc, state, msg = cup_key(name, key, login_url(target))
        result("t05", f"AC-14 pre-auth: {what} ⇒ bị từ chối", rc != 0 and state != "Running",
               f"rc {rc}; BackendState {state}; {msg}")
        cexec(name, f"{ctl(name)} logout >/dev/null 2>&1; true")
        cstart(name)
    after = {s: len(hs_nodes(s)) for s in before}
    result("t05", "AC-14 pre-auth: không node nào được tạo ở tenant đích", after == before, f"số node trước {before} sau {after}")
    for name, key, slug, what in (("p5-ma", ka, A["slug"], "key A → A"), ("p5-mb", kb, B["slug"], "key B → B")):
        rc, state, msg = cup_key(name, key, login_url(slug))
        s = cstatus(name)
        st.setdefault("clients", {})[name] = {"ip": ip4(s), "tenant": slug, "key": (s.get("Self") or {}).get("PublicKey")}
        save_state(st)
        result("t05", f"đối chứng: {what} ⇒ Running (key hợp lệ — lần từ chối không tiêu key)", rc == 0 and state == "Running",
               f"rc {rc}; {state}; IP {ip4(s)}")
    # ---------------------------------------------------------------- AC-14: Auth ID chéo tenant
    for src, dst, osrc, odst, cname in (("a", "b", oa, ob, "p5-wa"), ("b", "a", ob, oa, "p5-wb")):
        S, D = st["tenants"][src], st["tenants"][dst]
        req = osrc.call("POST", osrc.T("/enrollment/requests"), {"method": "web_auth", "device_label": cname},
                        idem="p5-wa-" + secrets.token_hex(6))
        rj = req.json()
        code = (rj.get("credential") or {}).get("enroll_code", "")
        rid = (rj.get("request") or {}).get("id", "")
        if code:
            t.secret_values.add(code)
        cstart(cname)
        cdock(f"exec -d {cname} sh -c " + shlex.quote(f"{ctl(cname)} login --login-server={login_url(S['slug'])} "
                                                       f"--hostname=mg-{code} --accept-dns=false --timeout=600s >/tmp/up.log 2>&1"))
        link = wait(lambda: (lambda m: m.groups() if m else None)(AUTH_RE.search(cexec(cname, "cat /tmp/up.log")[1])), 60, 1.5)
        hostp, auth = link or ("", "")
        if auth:
            t.secret_values.add(auth)
        result("t05", f"Auth ID sinh ở {src} ({cname}: tailscale login --login-server <{src}>)", bool(auth) and
               hostp == f"{S['slug']}.mesh.{DOMAIN}", f"web_auth request {req.status}; link host = <{src}>.mesh {hostp == f'{S['slug']}.mesh.{DOMAIN}'}")
        if not auth:
            continue
        n0 = {s: len(hs_nodes(s)) for s in (S["slug"], D["slug"])}
        # (i) không có yêu cầu đang chờ ở phiên của đích ⇒ từ chối trước mọi lời gọi Headscale
        c0 = odst.call("POST", odst.T("/enrollment/web-auth/claim"), {"auth_id": auth})
        # (ii) đích có yêu cầu web_auth đang chờ ⇒ Headscale của đích không biết Auth ID
        r2 = odst.call("POST", odst.T("/enrollment/requests"), {"method": "web_auth", "device_label": f"p5-x{dst}"},
                       idem="p5-wx-" + secrets.token_hex(6))
        rid2 = (r2.json().get("request") or {}).get("id", "")
        c1 = odst.call("POST", odst.T("/enrollment/web-auth/claim"), {"auth_id": auth, "request_id": rid2})
        time.sleep(3)
        n1 = {s: len(hs_nodes(s)) for s in (S["slug"], D["slug"])}
        rq2 = odst.call("GET", odst.T(f"/enrollment/requests/{rid2}")).json()
        bs = cstatus(cname).get("BackendState")
        result("t05", f"AC-14 Auth ID của {src} gửi tới endpoint claim của {dst} ⇒ bị từ chối, không node nào được tạo",
               c0.status == 409 and c1.status == 409 and n0 == n1 and bs != "Running",
               f"không yêu cầu chờ: {c0.status} {c0.json().get('code')}/{c0.json().get('reason', c0.json().get('detail', ''))[:60]}; "
               f"có yêu cầu chờ: {c1.status} {c1.json().get('code')}/{str(c1.json().get('reason') or c1.json().get('detail', ''))[:60]}; "
               f"yêu cầu của {dst}: {rq2.get('status')} {rq2.get('failure_code')}; node {n0} → {n1}; client {bs}")
        time.sleep(5)
        c2 = osrc.call("POST", osrc.T("/enrollment/web-auth/claim"), {"auth_id": auth, "request_id": rid})
        running = wait(lambda: cstatus(cname).get("BackendState") == "Running", 90, 2)
        result("t05", f"đối chứng: cùng Auth ID claim ở chính {src} ⇒ verified, client Running",
               c2.status == 200 and c2.json().get("status") == "verified" and bool(running),
               f"claim {c2.status} {c2.json().get('status')} {c2.json().get('failure_code') or ''}; Running {bool(running)}")
        s = cstatus(cname)
        st.setdefault("clients", {})[cname] = {"ip": ip4(s), "tenant": S["slug"], "key": (s.get("Self") or {}).get("PublicKey")}
        save_state(st)


# ------------------------------------------------------------------------------------------------ t05a
def P(typ: str, ref: str) -> dict:
    return {"type": typ, "ref": ref}


def apply_policy(o: Owner, slug: str, source: dict, label: str) -> bool:
    c = o.call("POST", o.T("/policies"), {"source": source}, idem="p5-pol-" + secrets.token_hex(6))
    v = c.json() if c.status == 201 else {}
    val = o.call("POST", o.T(f"/policies/{v.get('id')}/validate"), None, if_match=v.get("etag")) if v else None
    vv = val.json() if val is not None and val.status == 200 else {}
    rep = vv.get("validation_report") or {}
    ap = o.call("POST", o.T(f"/policies/{vv.get('id')}/approve"), {"content_sha256": vv.get("content_sha256")},
                if_match=vv.get("etag")) if vv.get("state") == "validated" else None
    va = ap.json() if ap is not None and ap.status == 200 else {}
    r = o.call("POST", o.T(f"/policies/{va.get('id')}/apply"), None, idem="p5-ap-" + secrets.token_hex(6)) if va else None
    j = o.job(((r.json() if r is not None else {}).get("job") or {}).get("id", "")) if r is not None and r.status == 202 else {}
    return bool(result("t05a", f"policy {label}: draft → validate → approve → apply",
                       j.get("status") == "succeeded",
                       f"POST {c.status} {c.json().get('code', '') if c.status != 201 else ''}; validate {val.status if val else '-'} "
                       f"{rep.get('result')} lỗi {[e.get('code') for e in rep.get('errors') or []]} cảnh báo "
                       f"{[w.get('code') for w in rep.get('warnings') or []]}; approve {ap.status if ap else '-'}; "
                       f"apply {r.status if r is not None else '-'} job {j.get('status')}"))


def policy_source(tag_id: str, route: str, via: bool) -> dict:
    exit_grant = {"src": [P("autogroup", "member")], "dst": [P("autogroup", "internet")], "ip": ["*"]}
    src = {"grants": [
        {"src": [P("autogroup", "member")], "dst": [P("autogroup", "member")], "ip": ["tcp:8000"]},
        {"src": [P("autogroup", "member")], "dst": [P("tag", tag_id)], "ip": ["tcp:8000"]},
        {"src": [P("autogroup", "member")], "dst": [P("cidr", route)], "ip": ["tcp:8000"]}, exit_grant]}
    if via:
        exit_grant["via"] = [P("tag", tag_id)]
    else:   # L7 internet_without_via cần xác nhận
        src["acknowledgements"] = [{"rule": "L7", "reason": "P5-T05a: exit node thử trên tenant thử"}]
    return src


def wait_route_device(o: Owner, name: str, timeout: float = 120, need_adv: list[str] | None = None) -> dict:
    def find():
        o.call("POST", o.T("/devices/sync"), None, idem="p5-sync-" + secrets.token_hex(6))
        time.sleep(2)
        items = o.call("GET", o.T("/routes")).json().get("items") or []
        return next((x for x in items if name in (str(x.get("name", "")) + " " + str(x.get("given_name", "")))
                     and (not need_adv or (set(need_adv) <= set(x.get("advertised_routes") or [])
                                           and (x.get("exit_node") or {}).get("advertised")))), None)
    return wait(find, timeout, 5) or {}


def route_dev_id(d: dict) -> str:
    return (d.get("device") or {}).get("id") or d.get("device_id") or d.get("id") or ""


def peer_view(status: dict) -> list[tuple]:
    return [(p.get("HostName"), sorted(p.get("PrimaryRoutes") or []), bool(p.get("ExitNodeOption")),
             sorted(x for x in (p.get("AllowedIPs") or []) if not x.startswith(("100.", "fd7a:"))))
            for p in (status.get("Peer") or {}).values()]


def sees(status: dict, prefix: str, router_key: str) -> dict:
    pr, ex, ai = False, False, False
    for p in (status.get("Peer") or {}).values():
        if prefix in (p.get("PrimaryRoutes") or []):
            pr = True
        if prefix in (p.get("AllowedIPs") or []):
            ai = True
        if p.get("PublicKey") == router_key and p.get("ExitNodeOption"):
            ex = True
        if p.get("ExitNodeOption") and p.get("PublicKey") == router_key:
            ex = True
    any_exit = any(p.get("ExitNodeOption") for p in (status.get("Peer") or {}).values())
    return {"route": pr or ai, "exit_of_router": ex, "any_exit": any_exit}


def vm105_status() -> dict:
    rc, out = vm("c", "tailscale status --json 2>/dev/null")
    try:
        return json.loads(out)
    except ValueError:
        return {}


def lab_status(n: str) -> dict:
    rc, out = vm(n, "tailscale status --json 2>/dev/null")
    try:
        return json.loads(out)
    except ValueError:
        return {}


def dnsq(where: str, name: str) -> str:
    if where == "p5-ra":
        rc, out = vm("c", f"sudo -n tailscale dns query {name} A")
    elif where.startswith("p5-"):
        rc, out = cexec(where, f"{ctl(where)} dns query {name} A")
    else:
        rc, out = vm(where, f"sudo -n tailscale dns query {name} A")
    rcode = (re.search(r"Response code: (\w+)", out) or [None, "?"])[1]
    ans = re.findall(r"TypeA\s+(\d+\.\d+\.\d+\.\d+)", out)
    return f"{rcode} {ans}"


def cmd_t05a() -> None:
    st = load_state()
    T = st["tenants"]
    owners = {r: Owner(T[r]["slug"]) for r in ("a", "b")}
    for o in owners.values():
        o.login()
    # ---------------------------------------------------------------- tag + policy
    for r, o in owners.items():
        tg = o.call("POST", o.T("/tags"), {"name": TAG, "purpose": "server", "description": "P5-T05a router/exit"},
                    idem="p5-tag-" + secrets.token_hex(6))
        tag = tg.json() if tg.status == 201 else next((x for x in o.call("GET", o.T("/tags")).json().get("items") or []
                                                       if x.get("name") == TAG), {})
        T[r]["tag_id"] = tag.get("id", "")
        save_state(st)
        jid = ((tg.json().get("job") or {}).get("id")) if tg.status == 201 else ""
        if jid:
            o.job(jid)
        time.sleep(3)
        result("t05a", f"tag {TAG} ở {r}", bool(T[r]["tag_id"]), f"POST /tags {tg.status}")
        apply_policy(o, T[r]["slug"], policy_source(T[r]["tag_id"], ROUTE[r], via=True),
                     f"{r} (member→member/tag/route tcp:8000; internet via tag)")
    # ---------------------------------------------------------------- router + exit node có tag
    keys = {}
    for r, o in owners.items():
        k = o.call("POST", o.T("/enrollment/keys"), {"tags": [TAG], "ttl_minutes": 10, "device_label": f"p5-r{r}"},
                   idem="p5-tk-" + secrets.token_hex(6))
        keys[r] = (k.json().get("credential") or {}).get("preauth_key", "") if k.status == 201 else ""
        if keys[r]:
            t.secret_values.add(keys[r])
        result("t05a", f"key chỉ-tag {TAG} ở {r} (POST /enrollment/keys, 10 phút)", k.status == 201 and bool(keys[r]),
               f"HTTP {k.status} {k.json().get('code', '') if k.status != 201 else ''}")
    # router A = tailscaled kernel của VM 105 (Linux, VM lab); router B = container client chính thức
    push_collect("c")
    vm("c", "umask 077; mkdir -p ~/p5lab && cat > ~/p5lab/authkey", keys["a"].encode())
    rc, out = vm("c", f"sudo -n timeout 90 tailscale up --login-server={login_url(T['a']['slug'])} "
                      "--auth-key=file:$HOME/p5lab/authkey --hostname=p5-ra --accept-dns=false --timeout=75s; "
                      "rc=$?; rm -f ~/p5lab/authkey; exit $rc", None, 150)
    s_ra = vm105_status()
    st.setdefault("clients", {})["p5-ra"] = {"ip": ip4(s_ra), "tenant": T["a"]["slug"], "key": (s_ra.get("Self") or {}).get("PublicKey")}
    cstart("p5-rb")
    rc2, state2, msg2 = cup_key("p5-rb", keys["b"], login_url(T["b"]["slug"]))
    s_rb = cstatus("p5-rb")
    st["clients"]["p5-rb"] = {"ip": ip4(s_rb), "tenant": T["b"]["slug"], "key": (s_rb.get("Self") or {}).get("PublicKey")}
    save_state(st)
    tags_a = (s_ra.get("Self") or {}).get("Tags") or []
    tags_b = (s_rb.get("Self") or {}).get("Tags") or []
    result("t05a", "router có tag: A = VM 105 (kernel), B = container", rc == 0 and rc2 == 0 and TAG in tags_a and TAG in tags_b,
           f"A rc {rc} {s_ra.get('BackendState')} tags {tags_a} IP {ip4(s_ra)}; B rc {rc2} {state2} tags {tags_b} IP {ip4(s_rb)} {msg2 if rc2 else ''}")
    vm("c", f"sudo -n tailscale set --advertise-routes={ROUTE['a']} --advertise-exit-node")
    cexec("p5-rb", f"{ctl('p5-rb')} set --advertise-routes={ROUTE['b']} --advertise-exit-node")
    st["advertised"] = True
    save_state(st)
    for r, o in owners.items():
        name = f"p5-r{r}"
        d = wait_route_device(o, name, 180, [ROUTE[r]])
        did = route_dev_id(d)
        T[r]["router_device"] = did
        save_state(st)
        ap = o.call("POST", o.T("/routes/approve"), {"device_id": did, "prefixes": [ROUTE[r]] + EXIT, "confirm_exit_node": True},
                    idem="p5-ra-" + secrets.token_hex(6), if_match=d.get("routes_etag", ""))
        aj = ap.json()
        T[r]["approved"] = ap.status == 200
        save_state(st)
        result("t05a", f"duyệt route + exit node của {name} qua API Portal (POST /routes/approve)", ap.status == 200,
               f"thiết bị {bool(did)} tags {d.get('tags')} quảng bá {d.get('advertised_routes')} exit {d.get('exit_node')}; HTTP {ap.status} "
               f"{aj.get('code', '')}; đã duyệt {aj.get('approved') or aj.get('approved_routes')}; cảnh báo "
               f"{[w.get('code') if isinstance(w, dict) else w for w in aj.get('warnings') or []]}")
    # ---------------------------------------------------------------- extra record
    for r, o in owners.items():
        member = "p5-ma" if r == "a" else "p5-mb"
        ipm = st["clients"][member]["ip"]
        rr = o.call("POST", o.T("/dns/records"), {"name": RECORD[r], "type": "A", "value": ipm}, idem="p5-dns-" + secrets.token_hex(6))
        rj = rr.json()
        T[r]["record_id"] = (rj.get("record") or {}).get("id", "")
        save_state(st)
        j = o.job((rj.get("job") or {}).get("id", "")) if rr.status == 201 else {}
        result("t05a", f"extra record {RECORD[r]} → IP của {member} ở {r} (POST /dns/records ⇒ dns.records_write)",
               rr.status == 201 and j.get("status") == "succeeded", f"HTTP {rr.status} {rj.get('code', '')}; job {j.get('status')}")
    time.sleep(10)
    # ---------------------------------------------------------------- quan sát
    observers = {"p5-ma": "a", "p5-wa": "a", "p5-ra": "a", "p5-mb": "b", "p5-wb": "b", "p5-rb": "b",
                 "a1": "tenant-a", "a2": "tenant-a", "b1": "tenant-b", "b2": "tenant-b"}

    def status_of(n: str) -> dict:
        if n == "p5-ra":
            return vm105_status()
        if n.startswith("p5-"):
            return cstatus(n)
        return lab_status(n)

    def observe(phase: str) -> dict:
        views = {}
        for n, ten in observers.items():
            s = status_of(n)
            row = {}
            for r in ("a", "b"):
                router = st["clients"][f"p5-r{r}"]["key"]
                row[r] = sees(s, ROUTE[r], router)
                row[f"dns_{r}"] = dnsq(n, RECORD[r])
            row["peers"] = peer_view(s)
            row["exit_list"] = (cexec(n, f"{ctl(n)} exit-node list")[1] if n.startswith("p5-") and n != "p5-ra"
                                else vm("c" if n == "p5-ra" else n, "tailscale exit-node list")[1])
            views[n] = row
        (OUT / f"t05a-{phase}.json").write_text(redact(json.dumps(views, ensure_ascii=False, indent=1)), encoding="utf-8")
        return views

    def resolved(v: str) -> bool:
        return v.startswith("RCodeSuccess") and v.split(" ", 1)[1] != "[]"

    def ready(x: dict) -> bool:
        return all(x[m][r]["route"] and x[m][r]["exit_of_router"] and resolved(x[m][f"dns_{r}"])
                   for m, r in (("p5-ma", "a"), ("p5-mb", "b")))

    v = wait(lambda: (lambda x: x if ready(x) else None)(observe("on")), 120, 10) or observe("on")
    if not ready(v) and not all(v[m][r]["exit_of_router"] for m, r in (("p5-ma", "a"), ("p5-mb", "b"))):
        result("t05a", "exit node qua grant `via` tag không hiện ExitNodeOption ⇒ policy thay thế (internet không via + xác nhận L7)",
               None, f"p5-ma {v['p5-ma']['a']}; p5-mb {v['p5-mb']['b']}")
        for r, o in owners.items():
            apply_policy(o, T[r]["slug"], policy_source(T[r]["tag_id"], ROUTE[r], via=False), f"{r} thay thế (internet + ack L7)")
        v = wait(lambda: (lambda x: x if ready(x) else None)(observe("on2")), 120, 10) or observe("on2")
    # AC-13 cho tenant thử (sau khi có policy cho phép — danh sách peer không rỗng)
    keys = {s_: node_keys(hs_nodes(s_)) for s_ in ("tenant-a", "tenant-b", T["a"]["slug"], T["b"]["slug"])}
    for name in ("p5-ma", "p5-wa", "p5-ra", "p5-mb", "p5-wb", "p5-rb"):
        s_ = status_of(name)
        mine = st["clients"].get(name, {}).get("tenant", "")
        others = set().union(*[k for sl, k in keys.items() if sl != mine])
        pk = {p.get("PublicKey") for p in (s_.get("Peer") or {}).values()}
        result("t05", f"AC-13 tenant thử {name}: có peer cùng tenant, 0 node key của tenant khác",
               bool(pk & keys.get(mine, set())) and not (pk & others),
               f"{len(pk)} peer ({[p.get('HostName') for p in (s_.get('Peer') or {}).values()]}); cùng tenant "
               f"{len(pk & keys.get(mine, set()))}; node key của 3 tenant còn lại ({len(others)} key) xuất hiện {len(pk & others)}")
    for n, ten in observers.items():
        own = ten if ten in ("a", "b") else ""
        for r in ("a", "b"):
            if r == own:
                if n == f"p5-r{r}":
                    continue   # router không tự thấy route của chính nó trong Peer
                ok = v[n][r]["route"] and v[n][r]["exit_of_router"] and resolved(v[n][f"dns_{r}"])
                result("t05a", f"đối chứng cùng tenant: {n} ({r}) thấy route + exit node của p5-r{r}, phân giải {RECORD[r]}",
                       ok, f"{v[n][r]}; dns {v[n][f'dns_{r}']}")
            else:
                ok = not v[n][r]["route"] and not v[n][r]["exit_of_router"] and not resolved(v[n][f"dns_{r}"])
                result("t05a", f"IT-08/IT-07: {n} ({ten}) KHÔNG thấy route/exit node của {r}, KHÔNG phân giải {RECORD[r]}",
                       ok, f"{v[n][r]}; dns {v[n][f'dns_{r}']}; exit-node list: {redact(v[n]['exit_list']).replace(chr(10), ' ')[:120]}")
    exit_selection(st)
    # MagicDNS name của client tenant kia
    for n, other in (("p5-ma", "p5-mb"), ("p5-mb", "p5-ma"), ("a1", "p5-ma"), ("b1", "p5-mb")):
        s = cstatus(other)
        fq = ((s.get("Self") or {}).get("DNSName") or "").rstrip(".")
        res = dnsq(n, fq) if fq else "?"
        own = dnsq(other, fq) if fq else "?"
        result("t05a", f"IT-07: {n} phân giải tên MagicDNS của {other} ⇒ không được (đối chứng: chính {other} phân giải được)",
               bool(fq) and not resolved(res) and resolved(own), f"{redact(fq)}: từ {n} {res}; từ {other} {own}")
    undo_t05a(st, owners)


def self_id(n: str) -> str:
    s_ = vm105_status() if n == "p5-ra" else cstatus(n)
    return str((s_.get("Self") or {}).get("ID") or "")


def exit_selection(st: dict) -> None:
    """IT-08 "exit node của A không chọn được từ B". Hai tailnet dùng lại cùng IP và cùng số ID node (p5-ra và p5-rb đều
    100.64.0.3, ID 3) ⇒ (1) chọn theo hostname peer của router tenant kia ⇒ lỗi; (2) chọn theo IP ⇒ peer được đánh dấu
    `ExitNode` phải mang node key của router CÙNG tenant (khóa là duy nhất toàn cục), rồi bỏ chọn; lab A/B chỉ đọc."""
    for n, r, own in (("p5-mb", "a", "b"), ("p5-ma", "b", "a")):
        router, mine = f"p5-r{r}", f"p5-r{own}"
        rc1, o1 = cexec(n, f"{ctl(n)} set --exit-node={router}")
        cexec(n, f"{ctl(n)} set --exit-node=")
        rip = st["clients"][router]["ip"]
        rc2, o2 = cexec(n, f"{ctl(n)} set --exit-node={rip}")
        s_ = cstatus(n)
        chosen = [p.get("PublicKey") for p in (s_.get("Peer") or {}).values() if p.get("ExitNode")]
        cexec(n, f"{ctl(n)} set --exit-node=")
        after = [p for p in (cstatus(n).get("Peer") or {}).values() if p.get("ExitNode")]
        own_key, other_key = st["clients"][mine]["key"], st["clients"][router]["key"]
        result("t05a", f"IT-08: {n} ({own}) không chọn được exit node của {r}",
               rc1 != 0 and other_key not in chosen and (rc2 != 0 or chosen == [own_key]) and not after,
               f"theo hostname {router}: rc {rc1} {redact(o1)[-80:]}; theo IP {rip} (trùng IP router của chính {own}): rc {rc2} "
               f"⇒ peer ExitNode = node key của {mine} {chosen == [own_key]}, của {router} {other_key in chosen}; đã bỏ chọn {not after}")
    for n in ("a1", "b1"):
        rc0, out = vm(n, "tailscale exit-node list")
        result("t05a", f"IT-08: {n} (lab, chỉ đọc) không có exit node nào để chọn", "no exit nodes found" in out,
               f"exit-node list: {redact(out).replace(chr(10), ' ')[:100]}")


def advertise_and_approve(st: dict, owners: dict) -> None:
    T = st["tenants"]
    vm("c", f"sudo -n tailscale set --advertise-routes={ROUTE['a']} --advertise-exit-node")
    cexec("p5-rb", f"{ctl('p5-rb')} set --advertise-routes={ROUTE['b']} --advertise-exit-node")
    st["advertised"] = True
    save_state(st)
    for r, o in owners.items():
        d = wait_route_device(o, f"p5-r{r}", 180, [ROUTE[r]])
        ap = o.call("POST", o.T("/routes/approve"), {"device_id": route_dev_id(d), "prefixes": [ROUTE[r]] + EXIT,
                                                     "confirm_exit_node": True},
                    idem="p5-ra-" + secrets.token_hex(6), if_match=d.get("routes_etag", ""))
        T[r]["approved"] = ap.status == 200
        save_state(st)
        result("t05a", f"duyệt lại route + exit node của p5-r{r} (cho phép thử chọn exit node)", ap.status == 200,
               f"HTTP {ap.status}; đã duyệt {ap.json().get('approved_routes')}")


def cmd_exitsel() -> None:
    st = load_state()
    T = st["tenants"]
    owners = {r: Owner(T[r]["slug"]) for r in ("a", "b")}
    for o in owners.values():
        o.login()
    advertise_and_approve(st, owners)
    ok = wait(lambda: all((cstatus(m).get("Peer") or {}) and any(p.get("ExitNodeOption") for p in cstatus(m)["Peer"].values())
                          for m in ("p5-ma", "p5-mb")), 120, 10)
    log("  exit node hiện ở client cùng tenant:", bool(ok))
    exit_selection(st)
    undo_t05a(st, owners)


def undo_t05a(st: dict, owners: dict | None = None) -> None:
    T = st.get("tenants", {})
    owners = owners or {r: Owner(T[r]["slug"]) for r in ("a", "b") if r in T}
    for o in owners.values():
        if not o.sess:
            o.login()
    if st.get("advertised"):
        rc1, o1 = vm("c", "sudo -n tailscale set --advertise-routes= --advertise-exit-node=false")
        rc2, o2 = cexec("p5-rb", f"{ctl('p5-rb')} set --advertise-routes= --advertise-exit-node=false")
        result("undo", "gỡ quảng bá route + exit node (p5-ra, p5-rb)", rc1 == 0 and rc2 == 0, f"rc {rc1}/{rc2} {o1[-80:]} {o2[-80:]}")
        st["advertised"] = False
        save_state(st)
    for r, o in owners.items():
        if T[r].get("approved"):
            d = wait_route_device(o, f"p5-r{r}", 60)
            rv = o.call("POST", o.T("/routes/revoke"), {"device_id": route_dev_id(d), "prefixes": [ROUTE[r]] + EXIT},
                        if_match=d.get("routes_etag", ""))
            result("undo", f"gỡ duyệt route + exit node ở {r} (POST /routes/revoke)", rv.status == 200,
                   f"HTTP {rv.status} {rv.json().get('code', '')}; còn duyệt {rv.json().get('approved') or rv.json().get('approved_routes')}")
            T[r]["approved"] = False
            save_state(st)
        for rec in [x for x in o.call("GET", o.T("/dns/records")).json().get("items") or [] if x.get("name") == RECORD[r]]:
            dl = o.call("DELETE", o.T(f"/dns/records/{rec['id']}"), None, if_match=rec.get("etag", ""))
            j = o.job(dl.json().get("id", "")) if dl.status == 202 else {}
            left = o.call("GET", o.T("/dns/records")).json().get("items") or []
            member = "p5-ma" if r == "a" else "p5-mb"
            gone = wait(lambda: (lambda v: v if not v.startswith("RCodeSuccess") or "[]" in v else None)(dnsq(member, RECORD[r])), 60, 5)
            result("undo", f"xóa extra record ở {r} (bản ghi cuối ⇒ file [] ⇒ tên hết phân giải ở chính tenant)",
                   dl.status == 202 and j.get("status") == "succeeded" and not left and bool(gone),
                   f"HTTP {dl.status}; job {j.get('status')}; còn {len(left)} bản ghi; {member} hỏi {RECORD[r]}: {gone}")
            T[r]["record_id"] = ""
            save_state(st)


# ------------------------------------------------------------------------------------------------ cleanup
def cmd_cleanup() -> None:
    st = load_state()
    if st.get("tenants"):
        try:
            undo_t05a(st)
        except Exception as e:  # noqa: BLE001
            log("  undo_t05a lỗi:", type(e).__name__, e)
    use_c = not st.get("vm105_released")   # VM 105 đã trả lại cho người điều phối (G4b) ⇒ không chạm nữa
    if use_c:
        rc, out = vm("c", "sudo -n timeout 60 tailscale logout; sudo -n tailscale switch --list; tailscale status 2>&1 | head -2; "
                          "rm -rf ~/p5lab")
        log("  VM 105 logout:", redact(out)[-200:])
        rc, out = cdock("ps -aq --filter label=meshguard.role=p5-client | xargs -r sudo -n docker rm -f")
        log("  container p5:", out[-120:])
    for n in ("a1", "a2", "b1", "b2"):
        for port in (8000, 8001):
            collect(n, f"unlisten {port}")
        rc, out = collect(n, "relay status")
        vm(n, "rm -rf ~/p5lab/out ~/p5lab/listen-*")
        log(f"  {n}: relay {out.strip()}")
    if st.get("tenants"):
        pf = platform()
        for r, ten in st["tenants"].items():
            if ten.get("deleted"):
                continue
            d = pf.deprovision(ten["tenant_id"], ten["slug"], "P5-T05/T05a: dọn tenant thử sau kiểm chứng")
            j = pf.wait_job(d.get("job_id", ""), 600) if d.get("job_id") else {}
            tst = pf.tenant(ten["tenant_id"]).get("status")
            ok = result("cleanup", f"deprovision 2P {r}", d.get("request_status") == 202 and d.get("approve_status") == 200
                        and j.get("status") == "succeeded" and tst == "deleted",
                        f"DELETE {d.get('request_status')}, tự duyệt {d.get('self_approval_status')}, SA2 {d.get('approve_status')}, "
                        f"job {j.get('status')}; tenant {tst} {d.get('error', '')}")
            ten["deleted"] = bool(ok)
            save_state(st)
            chk = host(f"echo c=$(sudo -n docker ps -a --format '{{{{.Names}}}}' | grep -c -- '{ten['slug']}'); "
                       f"echo n=$(sudo -n docker network ls --format '{{{{.Name}}}}' | grep -c -- '{ten['slug']}'); "
                       f"echo v=$(sudo -n docker volume ls --format '{{{{.Name}}}}' | grep -c -- '{ten['slug']}'); "
                       f"echo d=$(sudo -n ls /opt/meshguard/tenants | grep -c -- '{ten.get('instance_id') or 'none'}')")
            result("cleanup", f"host không còn tài nguyên của {r}", all(x.endswith("=0") for x in chk.split()), chk.replace("\n", " "))
    if use_c:
        rc, out = vm("c", "sudo -n tailscale switch --list; tailscale status 2>&1 | head -1; sudo -n docker ps -a --filter label=meshguard.role=p5-client -q | wc -l")
        result("cleanup", "VM 105 không thuộc tailnet nào, 0 container p5", "p5" not in out.split("\n")[0:2].__str__() and out.strip().endswith("0"),
               redact(out).replace("\n", " | "))
    for f in (CREDS, TOTPF):
        if f.exists():
            f.unlink()
    log("  credential p5 đã xóa (p5-creds.json, p5-totp-last.json)")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "provision" and len(argv) > 2:
        cmd_provision(argv[2:])
        return 0
    fn = {"inventory": cmd_inventory, "paths": cmd_paths, "ac20": cmd_ac20, "v02": cmd_v02, "provision": cmd_provision,
          "t05": cmd_t05, "t05a": cmd_t05a, "exitsel": cmd_exitsel, "cleanup": cmd_cleanup}.get(cmd)
    if cmd == "relaydemo":
        cmd_relaydemo(argv[2])
        return 0
    if not fn:
        print(__doc__)
        return 2
    fn()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
