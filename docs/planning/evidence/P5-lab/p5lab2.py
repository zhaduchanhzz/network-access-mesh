#!/usr/bin/env python3
"""Phase 5 — nhóm lab thứ hai: P5-T04 (AC-10/11, V-09), P5-T06 (AC-15/16, V-20, V-22, IT-09), P5-T07 (AC-17),
P5-T07a (V-21), P5-T03 (AC-08/09, V-27). Dùng chung hạ tầng của p5lab.py (SSH, che, Owner, Platform).

  python -B p5lab2.py <bước>
  setup        tenant thử P (p5p-<hex>) và Q (p5q-<hex>); Q: node_expiry 1h (PUT /settings/security) + policy cho
               phép tcp:8000; node tạm q1 (b1), q2 (a2); bắt đầu dò TCP q1→q2 (cho T07a, ~100 phút)
  t04          P: node tạm p1 (a1), p2 (a2, ép relay — dữ liệu qua VPS), p3 (b2, không ép — LAN NAT); 3 vòng policy
               allow 8000 → chỉ 8001 → deny-all (apply qua API); dò TCP p1→p2/p3 8000+8001; đo trễ lan truyền
  t07          P: thu hồi (expire) p2 và p3 đang online (dò TCP mới + luồng đang mở), rồi p4 (b1) offline → expire →
               bật lại; UI hai pha (Chromium thật) cho một lần thu hồi
  t07a         Q: sau khi hết hạn 1h — trạng thái client, peer loại bỏ, re-auth qua Portal (web-auth + claim)
  t06          AC-15/16 trên lab tenant-a/b (a2/b2 bỏ ép tạm ⇒ direct, trả lại ⇒ relay) + metrics theo path; V-20
               thông lượng relay vs direct; V-22 netcheck; IT-09 derpprobe qua Internet (khóa của P và Q)
  t03          V-27: bắt gói DNS + SNI trên b1 cho một node tạm mới (4 tình huống × có/không TS_NO_LOGS_NO_SUPPORT)
  cleanup      dừng/xóa node tạm, listener, dò TCP; deprovision 2P tenant thử; xóa credential
Không dùng VM 105 (dành cho G4b). Không đổi tenant-a/b ngoài đọc + TCP thật (fixture `test-allow-intra`). Mọi output
đã che trong P5_OUT (mặc định ~/.meshguard/p5-out2).
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import secrets
import shlex
import statistics
import subprocess
import sys
import time

os.environ.setdefault("P5_OUT", os.path.expanduser("~/.meshguard/p5-out2"))
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import p5lab as L  # noqa: E402

L.STATE = L.HOME / "p5-state2.json"
OUT = L.OUT
log, result, vm, host, sql, wait = L.log, L.result, L.vm, L.host, L.sql, L.wait
DOMAIN = L.DOMAIN
SOCKS = {"p1": 18081, "p2": 18082, "p3": 18083, "p4": 18084, "p5": 18085, "p6": 18086, "p7": 18087, "p8": 18088,
         "q1": 18091, "q2": 18092, "q3": 18093, "q4": 18094, "x1": 18095}
WHERE = {"p1": "a1", "p2": "a2", "p3": "b2", "p4": "b1", "p5": "a2", "p6": "b2", "p7": "a2", "p8": "b2",
         "q1": "b1", "q2": "a2", "q3": "a2", "q4": "b2", "x1": "b1"}
FORCED = {"p2", "p5", "p7"}   # node tạm ép relay ⇒ dữ liệu luôn qua DERP của tenant trên VPS
# Hai tailnet dùng lại cùng dải: node tạm có IP trùng IP tailnet (tenant-a/b) của VM dò thì SOCKS5 của tailscaled
# userspace — khi đích KHÔNG còn là peer (deny-all, thu hồi) — quay sang quay số bằng mạng của hệ điều hành và tới đúng
# node tenant-a/b có IP đó (sai kết luận). Lần chạy t04 đầu dính lỗi này (p2 = 100.64.0.2 = lab-a2) ⇒ mọi đích được
# kiểm `no_collision` trước khi đo.


# ------------------------------------------------------------------------------------------------ tiện ích
def push(vmname: str, fname: str) -> bool:
    import hashlib
    body = (HERE / fname).read_bytes().replace(b"\r\n", b"\n")
    rc, out = vm(vmname, f"mkdir -p ~/p5lab && chmod 0700 ~/p5lab && cat > ~/p5lab/{fname} && md5sum ~/p5lab/{fname}", body, 60)
    ok = hashlib.md5(body).hexdigest() in out
    if not ok:
        log(f"  {vmname}: đẩy {fname} LỖI {out[-120:]}")
    return ok


def vn(name: str, args: str, stdin: bytes | None = None, timeout: float = 150) -> tuple[int, str]:
    return vm(WHERE[name], f"sh ~/p5lab/vnode.sh {args}", stdin, timeout)


def vstatus(name: str) -> dict:
    rc, out = vn(name, f"ts {name} status --json")
    return L.jload(out)


def clock_offset(vmname: str, n: int = 12) -> float:
    """offset = đồng hồ VM − đồng hồ máy này, qua MỘT phiên SSH giữ mở (lấy mẫu RTT nhỏ nhất)."""
    p = subprocess.Popen(L.sshcmd(vmname) + ["python3 -u -c 'import sys,time\nfor l in sys.stdin: print(repr(time.time()),flush=True)'"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    best = (9e9, 0.0)
    try:
        for _ in range(n):
            t0 = time.time()
            p.stdin.write("x\n"); p.stdin.flush()
            line = p.stdout.readline()
            t1 = time.time()
            if not line:
                break
            rtt = t1 - t0
            if rtt < best[0]:
                best = (rtt, float(line) - (t0 + t1) / 2)
            time.sleep(0.1)
    finally:
        p.stdin.close(); p.terminate()
    log(f"  đồng hồ {vmname}: offset {best[1]:+.3f} s (RTT {best[0] * 1000:.0f} ms)")
    return best[1]


def owner(role: str) -> L.Owner:
    o = L.Owner(L.load_state()["tenants"][role]["slug"])
    o.login()
    return o


def login_url(role: str) -> str:
    return L.login_url(L.load_state()["tenants"][role]["slug"])


def enroll(o: L.Owner, role: str, name: str, env: list[str] | None = None) -> dict:
    """Node tạm `name` trên WHERE[name]: start (env riêng) + pre-auth key của Owner (một lần, 10 phút) qua stdin."""
    for f in ("vnode.sh", "tcpwatch.py", "collect.sh"):
        push(WHERE[name], f)
    vn(name, f"stop {name}")
    vn(name, f"rm {name}")
    rc, out = vn(name, f"start {name} {SOCKS[name]} {' '.join(env or [])}")
    log(f"  {name}@{WHERE[name]}: {out.strip()[-120:]}")
    key = L.preauth(o, name)
    rc, out = vn(name, f"up {name} {login_url(role)} {name}", key.encode(), 150)
    s = vstatus(name)
    st = L.load_state()
    st.setdefault("nodes", {})[name] = {"role": role, "vm": WHERE[name], "ip": L.ip4(s),
                                         "key": (s.get("Self") or {}).get("PublicKey"), "env": env or []}
    L.save_state(st)
    result("enroll", f"node tạm {name} ({role}) trên {WHERE[name]}{' ép relay' if name in FORCED else ''}",
           rc == 0 and s.get("BackendState") == "Running", f"rc {rc}; {s.get('BackendState')}; IP {L.ip4(s)}; {L.redact(out)[-100:]}")
    return st["nodes"][name]


def device_id(o: L.Owner, name: str) -> str:
    def find():
        o.call("POST", o.T("/devices/sync"), None, idem="p5-sync-" + secrets.token_hex(6))
        time.sleep(2)
        items = o.call("GET", o.T("/devices")).json().get("items") or []
        return next((d.get("id") for d in items if name in (str(d.get("name")), str(d.get("given_name")))), None)
    return wait(find, 90, 4) or ""


def hs_sha(slug: str) -> str:
    return host(f"sudo -n docker exec mg-hs-{slug} headscale policy get | head -c -1 | sha256sum | cut -c1-64").strip()


def apply_policy(o: L.Owner, slug: str, source: dict, label: str, step: str) -> dict:
    """draft → validate → approve → apply; trả các mốc (máy này): ack (202), job succeeded, read-back sha khớp."""
    c = o.call("POST", o.T("/policies"), {"source": source}, idem="p5-pol-" + secrets.token_hex(6))
    v = c.json() if c.status == 201 else {}
    val = o.call("POST", o.T(f"/policies/{v.get('id')}/validate"), None, if_match=v.get("etag"))
    vv = val.json() if val.status == 200 else {}
    ap = o.call("POST", o.T(f"/policies/{vv.get('id')}/approve"), {"content_sha256": vv.get("content_sha256")},
                if_match=vv.get("etag"))
    va = ap.json() if ap.status == 200 else {}
    before = hs_sha(slug)
    t_req = time.time()
    r = o.call("POST", o.T(f"/policies/{va.get('id')}/apply"), None, idem="p5-ap-" + secrets.token_hex(6))
    t_ack = time.time()
    jid = (r.json().get("job") or {}).get("id", "") if r.status == 202 else ""
    t_job, j = None, {}
    while time.time() - t_ack < 120 and jid:
        j = o.call("GET", o.T(f"/jobs/{jid}"), tries=2).json()
        if j.get("status") in ("succeeded", "failed", "cancelled"):
            t_job = time.time()
            break
        time.sleep(0.3)
    app = sql(f"SELECT applied_sha256 FROM policy_applications WHERE tenant_id = '{o.tid}' ORDER BY created_at DESC, id DESC LIMIT 1")
    t_rb = None
    t_end = time.time() + 60
    while time.time() < t_end:
        sha = hs_sha(slug)
        if sha and sha == app and sha != before:
            t_rb = time.time()
            break
        time.sleep(0.3)
    ok = c.status == 201 and (vv.get("validation_report") or {}).get("result") == "passed" and r.status == 202 \
        and j.get("status") == "succeeded" and t_rb is not None
    result(step, f"apply {label}", ok,
           f"validate {(vv.get('validation_report') or {}).get('result')}; apply {r.status}; job {j.get('status')} "
           f"{(t_job - t_ack) if t_job else -1:.2f} s sau ack; read-back sha Headscale = applied_sha256 "
           f"{(t_rb - t_ack) if t_rb else -1:.2f} s sau ack (sha {app[:12]}…)")
    return {"req": t_req, "ack": t_ack, "job": t_job, "rb": t_rb, "ok": ok}


def P(t: str, r: str) -> dict:
    return {"type": t, "ref": r}


def grants(*ports: int) -> dict:
    return {"grants": [{"src": [P("autogroup", "member")], "dst": [P("autogroup", "member")], "ip": [f"tcp:{p}"]}
                       for p in ports]}


def no_collision(prober: str, ips: list[str]) -> bool:
    """IP đích không được trùng IP tailnet của tailscaled HỆ THỐNG trên VM dò (self + peer)."""
    s = L.jload(vm(WHERE[prober], "tailscale status --json")[1])
    sys_ips = set((s.get("Self") or {}).get("TailscaleIPs") or [])
    for p in (s.get("Peer") or {}).values():
        sys_ips |= set(p.get("TailscaleIPs") or [])
    bad = [ip for ip in ips if ip in sys_ips]
    result("guard", f"IP đích {ips} không trùng tailnet hệ thống của {WHERE[prober]}", not bad, f"trùng {bad}" if bad else "ok")
    return not bad


def watch_start(name: str, secs: int, targets: list[str], tag: str, stream: str = "") -> str:
    logf = f"~/p5lab/watch-{tag}.jsonl"
    vm(WHERE[name], f"rm -f {logf}")
    extra = f" --stream {stream}" if stream else ""
    rc, out = vm(WHERE[name], f"setsid nohup python3 ~/p5lab/tcpwatch.py {SOCKS[name]} {secs} {logf} {' '.join(targets)}"
                              f" --every 0.5{extra} </dev/null >/dev/null 2>&1 & echo started")
    log(f"  dò TCP {tag} trên {WHERE[name]} qua {name}: {out.strip()} — {targets}{' stream ' + stream if stream else ''}")
    return logf


def watch_read(name: str, logf: str) -> list[dict]:
    rc, out = vm(WHERE[name], f"cat {logf}")
    rows = []
    for ln in out.splitlines():
        try:
            rows.append(json.loads(ln))
        except ValueError:
            pass
    return rows


def first_after(rows: list[dict], dst: str, state: str, t: float) -> float | None:
    """Mốc (đồng hồ VM) của lần thử đầu tiên SAU t mang trạng thái `state` cho `dst` (đổi trạng thái)."""
    for r in rows:
        if r.get("dst") == dst and r.get("state") == state and r.get("t_try", r["t"]) >= t:
            return r.get("t_try", r["t"])
    return None


def listeners(vms: list[str], ports=(8000, 8001)) -> None:
    for v in vms:
        L.push_collect(v)
        for p in ports:
            rc, out = L.collect(v, f"listen {p}")
            log(f"  {v} listen {p}: {out.strip()}")


# ------------------------------------------------------------------------------------------------ setup (+ T07a bắt đầu)
def cmd_setup() -> None:
    st = L.load_state()
    if not st.get("tenants"):
        L.cmd_provision(["p", "q"])
    st = L.load_state()
    if st.get("q_watch"):
        log("  setup đã chạy xong trước đó"); return
    st = L.load_state()
    oq = owner("q")
    # node_expiry 1h — khóa bảo mật (PUT /settings/security, step-up, If-Match = ETag của GET /settings)
    g = oq.call("GET", oq.T("/settings"))
    cur = g.json().get("settings") or g.json()
    body = {"enrollment": {k: cur["enrollment"][k] for k in ("identity_mode", "web_auth_enabled", "self_enroll", "requires_approval")},
            "node_expiry": "1h", "policy": {"four_eyes": cur["policy"]["four_eyes"], "sensitive_groups": cur["policy"]["sensitive_groups"]},
            "routes": {"four_eyes": cur["routes"]["four_eyes"]}}
    t0 = time.time()
    r = oq.call("PUT", oq.T("/settings/security"), body, if_match=g.header("ETag"))
    rj = r.json()
    jid = (rj.get("job") or {}).get("id") or ""
    j = oq.job(jid) if jid else {}
    inst = st["tenants"]["q"]["instance_id"]
    cfg = host(f"sudo -n grep -h -A1 '^node:' -r /opt/meshguard/tenants/{inst}/config 2>/dev/null | head -5; "
               f"sudo -n grep -rh 'expiry' /opt/meshguard/tenants/{inst}/config 2>/dev/null | head -3")
    jobs = sql(f"SELECT kind || ':' || status FROM jobs WHERE tenant_id = '{oq.tid}' AND created_at > now() - interval '3 minutes' ORDER BY created_at")
    result("setup", "Q: node_expiry = 1h (PUT /settings/security) ⇒ instance.reconfigure", r.status == 200,
           f"HTTP {r.status} {rj.get('code', '')}; job trong phản hồi {j.get('kind', '')} {j.get('status', '')}; job của tenant 3 phút: {jobs}; "
           f"config instance: {cfg.replace(chr(10), ' ')[:160]}; {time.time() - t0:.1f} s")
    wait(lambda: "instance.reconfigure:succeeded" in sql(f"SELECT string_agg(kind || ':' || status, ',') FROM jobs WHERE tenant_id = '{oq.tid}' "
                                                          "AND created_at > now() - interval '5 minutes'") or None, 120, 5)
    cfg = host(f"sudo -n grep -rh -B1 -A1 'expiry' /opt/meshguard/tenants/{inst}/ 2>/dev/null | head -6")
    log("  config Q sau reconfigure:", cfg.replace("\n", " | ")[:300])
    apply_policy(oq, st["tenants"]["q"]["slug"], grants(8000), "Q allow member→member tcp:8000", "setup")
    listeners(["a2", "b1", "a1", "b2"])
    for n in ("q1", "q2"):
        enroll(oq, "q", n)
    nodes = L.hs_nodes(st["tenants"]["q"]["slug"])
    result("setup", "Q: hạn node do Headscale đặt (node.expiry 1h)", all(n.get("expiry") for n in nodes),
           f"{[(n.get('given_name'), n.get('created_at', {}).get('seconds') if isinstance(n.get('created_at'), dict) else n.get('created_at'), n.get('expiry')) for n in nodes]}")
    st = L.load_state()
    st["q_watch"] = watch_start("q1", 6600, [f"{st['nodes']['q2']['ip']}:8000"], "t07a")
    st["q_offset_b1"] = clock_offset("b1")
    st["q_enrolled_at"] = time.time()
    L.save_state(st)


# ------------------------------------------------------------------------------------------------ T04
def cmd_t04() -> None:
    st = L.load_state()
    op = owner("p")
    slug = st["tenants"]["p"]["slug"]
    R, D = os.environ.get("P5_T04_RELAY", "p5"), os.environ.get("P5_T04_DIRECT", "p6")
    st = L.load_state()
    if "p1" not in st.get("nodes", {}):
        enroll(op, "p", "p1")
    for n in (R, D):
        if n not in st.get("nodes", {}):
            enroll(op, "p", n, ["TS_DEBUG_ALWAYS_USE_DERP=true"] if n in FORCED else [])
    st = L.load_state()
    ip2, ip3 = st["nodes"][R]["ip"], st["nodes"][D]["ip"]
    if not no_collision("p1", [ip2, ip3]):
        return
    targets = [f"{ip2}:8000", f"{ip2}:8001", f"{ip3}:8000", f"{ip3}:8001"]
    apply_policy(op, slug, {"grants": []}, "nền deny-all trước vòng đo", "t04")
    time.sleep(10)
    # đường đi thật: cần lưu lượng được phép ⇒ đo ở vòng allow; ở đây chỉ ghi IP
    for peer in ():
        rc, out = vn("p1", f"ts p1 ping --until-direct=false -c 6 --timeout=5s {st['nodes'][peer]['ip']}", None, 90)
        last = next((x for x in reversed(out.splitlines()) if "pong" in x), out[-120:])
        result("t04", f"đường p1→{peer} ({WHERE[peer]})", "pong" in last, L.redact(last))
    off = clock_offset("a1")
    logf = watch_start("p1", 1500, targets, "t04")
    time.sleep(8)
    marks = []
    for cycle in range(3):
        for label, src, expect in (("allow 8000", grants(8000), {"8000": "OPEN", "8001": "FAIL"}),
                                   ("chỉ 8001", grants(8001), {"8000": "FAIL", "8001": "OPEN"}),
                                   ("deny-all", {"grants": []}, {"8000": "FAIL", "8001": "FAIL"})):
            m = apply_policy(op, slug, src, f"vòng {cycle + 1}: {label}", "t04")
            marks.append({"cycle": cycle + 1, "label": label, "expect": expect, **m})
            if cycle == 0 and label == "allow 8000":
                for peer in (R, D):
                    rc, out = vn("p1", f"ts p1 ping --until-direct=false -c 4 --timeout=5s {st['nodes'][peer]['ip']}", None, 60)
                    last = next((x for x in reversed(out.splitlines()) if "pong" in x), out[-120:])
                    result("t04", f"đường p1→{peer} ({WHERE[peer]}{', ép relay' if peer in FORCED else ''})", "pong" in last, L.redact(last))
            time.sleep(25)
    time.sleep(5)
    rows = watch_read("p1", logf)
    vm(WHERE["p1"], "pkill -u $(id -u) -f '[t]cpwatch.py 18081' ; true")
    (OUT / "t04-watch.json").write_text(L.redact(json.dumps(rows)), encoding="utf-8")
    st = L.load_state()
    st.update(t04_marks=marks, t04_off=off, t04_ips=[ip2, ip3])
    L.save_state(st)
    eval_t04(rows, marks, off, ip2, ip3)
    for peer in (R, D):
        rc, out = vn("p1", f"ts p1 status", None, 60)
        log(f"  status p1 thấy {peer}: {L.redact(next((x for x in out.splitlines() if peer in x), ''))}")
    apply_policy(op, slug, grants(8000), "P trả về allow tcp:8000 (cho T07)", "t04")


def eval_t04(rows: list[dict], marks: list[dict], off: float, ip2: str, ip3: str) -> None:
    """Mỗi lần apply: cổng đổi trạng thái ⇒ trễ = lần thử đầu tiên mang trạng thái mới (kết thúc sau ack) − ack;
    cổng không đổi ⇒ phải giữ nguyên suốt cửa sổ — một lần timeout đơn lẻ tự hồi ngay lần thử sau (≤ 2 s) của cổng
    đang mở được ghi là "chập chờn", không phải vi phạm; cổng phải chặn mà mở dù một lần = vi phạm."""
    lat = {"relay": [], "direct": []}
    blips = 0
    for i, m in enumerate(marks):
        t_lo = m["ack"] + off
        t_hi = (marks[i + 1]["ack"] + off) if i + 1 < len(marks) else 9e18
        prev = marks[i - 1]["expect"] if i else {"8000": "FAIL", "8001": "FAIL"}
        det, okall = [], True
        for ip, path in ((ip2, "relay"), (ip3, "direct")):
            for port, want in m["expect"].items():
                dst = f"{ip}:{port}"
                ev = [r for r in rows if r.get("dst") == dst]
                if prev.get(port) == want:
                    flips = [r for r in ev if t_lo <= r["t"] < t_hi]
                    bad = [r for r in flips if r["state"] != want]
                    transient = want == "OPEN" and bad and all(
                        any(x["state"] == "OPEN" and 0 < x["t"] - r["t"] <= 2.5 for x in flips) for r in bad)
                    good = not bad or transient
                    blips += len(bad) if transient else 0
                    det.append(f"{path}:{port} giữ {want} " + ("đạt" if not bad else f"chập chờn {len(bad)} lần (tự hồi)" if transient
                                                               else "VI PHẠM " + str([x['state'] for x in flips])))
                else:
                    hit = next((r for r in ev if r["state"] == want and r["t"] >= t_lo), None)
                    good = hit is not None and hit["t"] < t_hi
                    if good:
                        d_ack = hit.get("t_try", hit["t"]) - t_lo
                        d_job = (hit.get("t_try", hit["t"]) - (m["job"] + off)) if m.get("job") else None
                        lat[path].append(d_ack)
                        det.append(f"{path}:{port}→{want} {d_ack:.2f} s sau ack" + (f" ({d_job:+.2f} s so với job succeeded)" if d_job is not None else ""))
                    else:
                        det.append(f"{path}:{port}→{want} KHÔNG thấy")
                okall &= good
        result("t04", f"vòng {m['cycle']} {m['label']}: TCP thật đổi đúng (AC-10/11)", okall and (m["ok"] or m.get("rb") is None),
               "; ".join(det))
    for path, v in lat.items():
        if v:
            result("t04", f"V-09 trễ lan truyền policy ({path}): ack của apply ⇒ lần thử TCP đầu tiên mang trạng thái mới", None,
                   f"n={len(v)}; min {min(v):.2f} s; trung vị {statistics.median(v):.2f} s; max {max(v):.2f} s; "
                   f"{blips} lần timeout đơn lẻ tự hồi ở cổng đang mở (độ phân giải dò 0,5 s, timeout 1,5 s; đồng hồ VM ± RTT/2)")


def cmd_t04eval() -> None:
    st = L.load_state()
    rows = json.loads((OUT / "t04-watch.json").read_text(encoding="utf-8"))
    eval_t04(rows, st["t04_marks"], st.get("t04_off", 0.707), *st.get("t04_ips", ["100.64.0.4", "100.64.0.5"]))


# ------------------------------------------------------------------------------------------------ T07
UI_JS = HERE / "ui_revoke.mjs"


def revoke_online(op: L.Owner, slug: str, name: str, path: str, ui: bool = False) -> None:
    st = L.load_state()
    ip = st["nodes"][name]["ip"]
    did = device_id(op, name)
    off = clock_offset("a1")
    logf = watch_start("p1", 400, [f"{ip}:8000"], f"t07-{name}", stream=f"{ip}:8002")
    time.sleep(10)
    uip = None
    if ui:
        uip = ui_start(op, name)
    t_req = time.time()
    e = op.call("POST", op.T(f"/devices/{did}/expire"), None, idem="p5-exp-" + secrets.token_hex(6))
    t_ack = time.time()
    first = (e.json().get("revocation") or {}).get("state")
    seen, t_app = [first], None
    while time.time() - t_ack < 180:
        rv = (op.call("GET", op.T(f"/devices/{did}"), tries=2).json().get("revocation") or {})
        if rv.get("state") and rv.get("state") != seen[-1]:
            seen.append(rv.get("state"))
        if rv.get("state") in ("applied", "failed"):
            t_app = time.time()
            break
        time.sleep(0.3)
    node = next((n for n in L.hs_nodes(slug) if n.get("given_name") == name or n.get("name") == name), {})
    t_rb = time.time()
    time.sleep(200)
    rows = watch_read("p1", logf)
    (OUT / f"t07-{name}.json").write_text(L.redact(json.dumps(rows)), encoding="utf-8")
    t_new = first_after(rows, f"{ip}:8000", "FAIL", t_ack + off)
    t_str = next((r["t"] for r in rows if r.get("dst") == "stream" and r.get("state") == "FAIL" and r["t"] >= t_ack + off), None)
    reopen = [r for r in rows if r.get("dst") in (f"{ip}:8000", "stream") and r.get("state") == "OPEN" and t_new and r.get("t_try", r["t"]) > t_new]
    base = (t_app or t_rb) + off
    ok = e.status == 202 and first == "pending" and seen[-1] == "applied" and t_new is not None and t_new - base <= 180 and not reopen
    result("t07", f"AC-17 thu hồi {name} đang ONLINE ({path})", ok,
           f"POST expire {e.status} (ack {t_ack - t_req:.2f} s) trạng thái {seen}; applied (read-back Headscale) "
           f"{(t_app - t_ack) if t_app else -1:.2f} s sau ack; node Headscale expiry {node.get('expiry')}; "
           f"kết nối TCP MỚI tới {name}:8000 thất bại {((t_new - (t_ack + off)) if t_new else -1):.2f} s sau ack "
           f"({((t_new - base) if t_new else -1):+.2f} s so với applied); luồng ĐANG MỞ bị cắt "
           f"{((t_str - (t_ack + off)) if t_str else -1):.2f} s sau ack (−1 = chưa cắt trong 200 s); mở lại sau đó {len(reopen)}")
    if uip:
        ui_finish(uip)
    vm("a1", "pkill -u $(id -u) -f '[t]cpwatch.py 18081' ; true")


def ui_start(op: L.Owner, name: str):
    """Chromium thật (playwright-core của G4a) theo dõi dòng thiết bị trên trang Devices trong lúc thu hồi."""
    pw = pathlib.Path(os.environ.get("P5_PW_DIR", ""))
    if not (pw / "node_modules" / "playwright-core").exists():
        log("  UI: không có playwright-core (P5_PW_DIR) — bỏ qua")
        return None
    h = L.HOME / "p5-ui"
    h.mkdir(exist_ok=True)
    for f in h.glob("*"):
        f.unlink()
    c = json.loads(L.CREDS.read_text(encoding="utf-8"))[op.slug]
    cfgf = L.HOME / "p5-ui.json"
    cfgf.write_text(json.dumps({"app": f"https://app.{DOMAIN}", "auth_host": f"auth.{DOMAIN}", "slug": op.slug,
                                "tenant_id": op.tid, "username": c["username"], "password": c["password"],
                                "totp_raw": c.get("totp_raw", ""), "totp_last": c.get("totp_last", 0), "device": name,
                                "handoff": str(h), "seconds": 60}), encoding="utf-8")
    try:
        os.chmod(cfgf, 0o600)
    except OSError:
        pass
    (pw / "ui_revoke.mjs").write_bytes(UI_JS.read_bytes())
    p = subprocess.Popen(["node", str(pw / "ui_revoke.mjs"), str(cfgf)], cwd=str(pw), stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, encoding="utf-8")
    ready = wait(lambda: (h / "ready").exists() or None, 150, 1)
    log(f"  UI sẵn sàng: {bool(ready)}")
    return p, h, cfgf


def ui_finish(uip) -> None:
    p, h, cfgf = uip
    try:
        out, _ = p.communicate(timeout=180)
    except subprocess.TimeoutExpired:
        p.kill()
        out = "timeout"
    # TOTP đã dùng trong trình duyệt ⇒ ghi lại để lần đăng nhập Python sau không dùng lại mã
    tl = h / "totp_last"
    if tl.exists():
        c = json.loads(L.CREDS.read_text(encoding="utf-8"))
        slug = json.loads(cfgf.read_text(encoding="utf-8"))["slug"]
        c[slug]["totp_last"] = max(int(c[slug].get("totp_last", 0)), int(tl.read_text().strip() or 0))
        L.CREDS.write_text(json.dumps(c), encoding="utf-8")
    cfgf.unlink(missing_ok=True)
    for ln in out.splitlines():
        if "[ui]" in ln:
            m = re.match(r"(PASS|FAIL) \[ui\] (.*?) — (.*)", ln)
            if m:
                result("t07", "UI: " + m.group(2), m.group(1) == "PASS", m.group(3))


def cmd_t07() -> None:
    st = L.load_state()
    op = owner("p")
    slug = st["tenants"]["p"]["slug"]
    for v in ("a2", "b2", "b1"):
        L.push_collect(v)
        rc, out = L.collect(v, "sink 8002")
    for n in ("p7", "p8"):
        if n not in L.load_state().get("nodes", {}):
            enroll(op, "p", n, ["TS_DEBUG_ALWAYS_USE_DERP=true"] if n in FORCED else [])
    st = L.load_state()
    if not no_collision("p1", [st["nodes"]["p7"]["ip"], st["nodes"]["p8"]["ip"]]):
        return
    revoke_online(op, slug, "p7", "relay qua VPS", ui=bool(os.environ.get("P5_PW_DIR")))
    revoke_online(op, slug, "p8", "LAN NAT direct")
    # peer OFFLINE: p4 trên b1 — đăng ký, dừng tailscaled (giữ state), thu hồi, bật lại
    p4 = enroll(op, "p", "p4")
    if not no_collision("p1", [p4["ip"]]):
        return
    did = device_id(op, "p4")
    off = clock_offset("a1")
    ok0 = vm("a1", f"python3 - <<'EOF'\nimport socket,struct\ns=socket.create_connection(('127.0.0.1',{SOCKS['p1']}),3);s.settimeout(3)\n"
                   f"s.sendall(b'\\x05\\x01\\x00');s.recv(2);s.sendall(b'\\x05\\x01\\x00\\x01'+socket.inet_aton('{p4['ip']}')+struct.pack('!H',8000))\n"
                   "r=s.recv(10);print('OPEN' if r[1]==0 and s.recv(100) else 'FAIL')\nEOF")[1]
    vn("p4", "stop p4")
    t_stop = time.time()
    time.sleep(5)
    e = op.call("POST", op.T(f"/devices/{did}/expire"), None, idem="p5-exp-" + secrets.token_hex(6))
    t_ack = time.time()
    rv = wait(lambda: (lambda x: x if x.get("state") in ("applied", "failed") else None)(
        op.call("GET", op.T(f"/devices/{did}")).json().get("revocation") or {}), 120, 0.5) or {}
    t_app = time.time()
    time.sleep(20)
    logf = watch_start("p1", 150, [f"{p4['ip']}:8000"], "t07-p4")
    time.sleep(3)
    rc, out = vn("p4", "start p4 18084")
    t_on = time.time()
    st4 = wait(lambda: (lambda s: s if s.get("BackendState") in ("NeedsLogin", "Running") else None)(vstatus("p4")), 60, 1) or {}
    t_seen = time.time()
    time.sleep(120)
    rows = watch_read("p1", logf)
    opens = [r for r in rows if r.get("dst") == f"{p4['ip']}:8000" and r.get("state") == "OPEN"]
    late = [r for r in opens if r.get("t_try", r["t"]) > t_on + off + 60]
    s4 = vstatus("p4")
    result("t07", "AC-17 thu hồi p4 khi OFFLINE rồi nối lại control", e.status == 202 and rv.get("state") == "applied"
           and not late and ok0.strip().endswith("OPEN"),
           f"trước khi dừng: TCP p1→p4 {ok0.strip()[-4:]}; dừng tailscaled (giữ state) → expire {e.status} → "
           f"{rv.get('state')} {t_app - t_ack:.2f} s sau ack (node offline); bật lại p4 {t_on - t_ack:.1f} s sau ack ⇒ "
           f"BackendState {st4.get('BackendState')} sau {t_seen - t_on:.1f} s, cuối {s4.get('BackendState')} "
           f"(Self.Expired {(s4.get('Self') or {}).get('KeyExpiry')}); TCP p1→p4 OPEN sau khi nối lại: {len(opens)} lần "
           f"(> 60 s: {len(late)})")
    vm("a1", "pkill -u $(id -u) -f '[t]cpwatch.py 18081' ; true")


# ------------------------------------------------------------------------------------------------ T07a
def obs_read(name: str) -> list[dict]:
    rc, out = vm(WHERE[name], f"cat ~/p5lab/obs-{name}.jsonl 2>/dev/null")
    rows = []
    for ln in out.splitlines():
        try:
            rows.append(json.loads(ln))
        except ValueError:
            pass
    return rows


def first(rows: list[dict], pred) -> float | None:
    return next((r["t"] for r in rows if pred(r)), None)


def cmd_t07a() -> None:
    """V-21 (i) trên Q (hạn 1h — kẹp hạn sau đăng ký). Quan sát: obs.sh (status mỗi 15 s) của q1 (b1), q3 (a2), q4 (b2);
    tcpwatch q4 → q3:8000 (b2). q1/q2 đăng ký 04:04, q3 04:14, q4 04:17 (UTC)."""
    st = L.load_state()
    oq = owner("q")
    slug = st["tenants"]["q"]["slug"]
    exp = {n.get("given_name"): (n.get("expiry") or {}).get("seconds") for n in L.hs_nodes(slug)}
    obs = {n: obs_read(n) for n in ("q1", "q3", "q4")}
    (OUT / "t07a-obs.json").write_text(L.redact(json.dumps(obs)), encoding="utf-8")
    hhmm = lambda t: time.strftime("%H:%M:%S", time.gmtime(t)) if t else "—"  # noqa: E731
    for n in ("q1", "q3", "q4"):
        rows = obs[n]
        t_need = first(rows, lambda r: r.get("state") == "NeedsLogin")
        t_selfexp = first(rows, lambda r: r.get("self_expired"))
        result("t07a", f"V-21 (i) {n}: client về trạng thái cần đăng nhập lại khi tới hạn", t_need is not None,
               f"hạn Headscale {hhmm(exp.get(n))}; client NeedsLogin lúc {hhmm(t_need)} "
               f"({(t_need - exp[n]) if t_need and exp.get(n) else float('nan'):+.0f} s so với hạn, độ phân giải 15 s); "
               f"Self.Expired lúc {hhmm(t_selfexp)}; mẫu cuối {rows[-1] if rows else '—'}")
    # q4 thấy q3 hết hạn / bị loại khỏi peer
    r4 = obs["q4"]
    t_gone = first(r4, lambda r: r.get("t", 0) > (exp.get("q3") or 0) - 60 and not any(p[0] == "q3" and not p[2] for p in r.get("peers") or []))
    seen = [(hhmm(r["t"]), r.get("state"), [(p[0], p[2]) for p in r.get("peers") or []]) for r in r4
            if abs(r["t"] - (exp.get("q3") or 0)) < 90]
    result("t07a", "V-21 (i): peer (q4) loại bỏ q3 khi q3 hết hạn", t_gone is not None,
           f"hạn q3 {hhmm(exp.get('q3'))}; q4 không còn thấy q3 hợp lệ lúc {hhmm(t_gone)} "
           f"({(t_gone - exp['q3']) if t_gone and exp.get('q3') else float('nan'):+.0f} s); mẫu quanh hạn: {seen}")
    rows = watch_read("q4", st["q_watch"])
    off = st.get("q_offset_b2", 0.0)
    ip3 = st["nodes"]["q3"]["ip"]
    flips = [(hhmm(r.get("t_try", r["t"]) - off), r["state"]) for r in rows if r.get("dst") == f"{ip3}:8000"]
    ev = [r for r in rows if r.get("dst") == f"{ip3}:8000"]
    # chuyển FAIL cuối cùng không còn OPEN sau đó (timeout đơn lẻ tự hồi trước đó là mất gói, không phải hạn)
    t_fail = (ev[-1].get("t_try", ev[-1]["t"]) - off) if ev and ev[-1]["state"] == "FAIL" else None
    result("t07a", "V-21 (i): TCP thật q4 → q3:8000 dừng khi hạn tới", t_fail is not None and abs(t_fail - (exp.get("q3") or 0)) < 120,
           f"đổi trạng thái {flips}; thất bại đầu tiên {((t_fail - exp['q3']) if t_fail and exp.get('q3') else float('nan')):+.1f} s so với hạn q3")
    # re-auth qua Portal: web-auth (q3) + claim bằng API
    req = oq.call("POST", oq.T("/enrollment/requests"), {"method": "web_auth", "device_label": "q3"}, idem="p5-wa-" + secrets.token_hex(6))
    rj = req.json()
    code = (rj.get("credential") or {}).get("enroll_code", "")
    rid = (rj.get("request") or {}).get("id", "")
    if code:
        L.t.secret_values.add(code)
    vn("q3", f"login q3 {login_url('q')} mg-{code}")
    link = wait(lambda: (lambda m: m.groups() if m else None)(L.AUTH_RE.search(vm(WHERE["q3"], "cat /dev/shm/p5v-$(id -un)/q3/up.log")[1])), 60, 2)
    auth = link[1] if link else ""
    if auth:
        L.t.secret_values.add(auth)
    t0 = time.time()
    c = oq.call("POST", oq.T("/enrollment/web-auth/claim"), {"auth_id": auth, "request_id": rid}) if auth else None
    run = wait(lambda: vstatus("q3").get("BackendState") == "Running", 90, 2)
    s3 = vstatus("q3")
    oq.call("POST", oq.T("/devices/sync"), None, idem="p5-s-" + secrets.token_hex(4))
    time.sleep(15)
    n3 = next((n for n in L.hs_nodes(slug) if n.get("given_name") == "q3"), {})
    result("t07a", "re-auth q3 qua Portal (web-auth → claim) sau khi hết hạn", bool(c) and c.status == 200 and bool(run),
           f"claim {c.status if c else '-'} {(c.json().get('status') if c else '')}; Running {bool(run)} sau {time.time() - t0:.1f} s; "
           f"node Headscale #{n3.get('id')} hạn mới {hhmm((n3.get('expiry') or {}).get('seconds'))} (≈ +1h — kẹp hạn lại); IP {L.ip4(s3)}")


# ------------------------------------------------------------------------------------------------ cleanup
def cmd_cleanup() -> None:
    st = L.load_state()
    for v in ("a1", "a2", "b1", "b2"):
        vm(v, "pkill -u $(id -u) -f [t]cpwatch.py; pkill -u $(id -u) -f [o]bs.sh; sh ~/p5lab/vnode.sh list; for d in /dev/shm/p5v-$(id -un)/*/; do "
              "[ -d \"$d\" ] && sh ~/p5lab/vnode.sh rm $(basename $d); done; rm -rf /dev/shm/p5v-$(id -un); true")
        for p in (8000, 8001, 8002):
            L.collect(v, f"unlisten {p}")
        rc, out = vm(v, "sh ~/p5lab/collect.sh relay status; ls /dev/shm | grep -c p5v; pgrep -u $(id -u) -c tailscaled; "
                        "rm -rf ~/p5lab/out ~/p5lab/watch-* ~/p5lab/listen-* ~/p5lab/cap ~/p5lab/derpprobe ~/p5lab/run_lab.sh ~/p5lab/obs* /dev/shm/p5cap; true")
        result("cleanup", f"{v}: node tạm + listener + dò TCP đã gỡ", True, out.replace("\n", " | ")[-160:])
    if st.get("tenants"):
        pf = L.platform()
        for r, ten in st["tenants"].items():
            if ten.get("deleted"):
                continue
            d = pf.deprovision(ten["tenant_id"], ten["slug"], "P5 lab 2: dọn tenant thử sau kiểm chứng")
            j = pf.wait_job(d.get("job_id", ""), 600) if d.get("job_id") else {}
            tst = pf.tenant(ten["tenant_id"]).get("status")
            ok = result("cleanup", f"deprovision 2P {r}", d.get("request_status") == 202 and j.get("status") == "succeeded"
                        and tst == "deleted", f"DELETE {d.get('request_status')}, tự duyệt {d.get('self_approval_status')}, "
                        f"SA2 {d.get('approve_status')}, job {j.get('status')}; tenant {tst}")
            ten["deleted"] = bool(ok)
            L.save_state(st)
    for f in (L.CREDS, L.TOTPF, L.HOME / "p5-ui.json"):
        if f.exists():
            f.unlink()
    log("  credential p5 đã xóa")


def main(argv: list[str]) -> int:
    fn = {"setup": cmd_setup, "t04": cmd_t04, "t04eval": cmd_t04eval, "t07": cmd_t07, "t07a": cmd_t07a, "cleanup": cmd_cleanup}
    if len(argv) < 2:
        print(__doc__)
        return 2
    if argv[1] in fn:
        fn[argv[1]]()
        return 0
    import p5lab2_net
    return p5lab2_net.main(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
