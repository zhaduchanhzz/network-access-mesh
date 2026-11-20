#!/usr/bin/env python3
"""Phần mạng của nhóm lab thứ hai (gọi qua p5lab2.py):

  t06   AC-15 (direct), AC-16 (relay của đúng tenant), V-20 (thông lượng relay qua VPS vs direct) trên client lab của
        tenant-a (a2→a1) và tenant-b (b2→b1) — chỉ TCP thật trên cổng 8000 của fixture; a2/b2 bỏ ép relay tạm
        (`collect.sh relay direct`) rồi trả lại (`relay off`); V-22 `netcheck` từ 1 và 2 lớp NAT; IT-09 `derpprobe`
        (tests/isolation/derpprobe/run_lab.sh) qua DNS công khai → VPS với khóa node của 2 tenant thử
  t03   AC-08/09 + ma trận Linux; V-27 bắt gói DNS/SNI (capture.py) cho node tạm x1 trên b1: nền, trước đăng nhập, sau
        map đầy đủ, DNS hệ thống lỗi (namespace mount riêng của tiến trình) — mỗi tình huống có/không
        TS_NO_LOGS_NO_SUPPORT=true
"""
from __future__ import annotations

import json
import re
import secrets
import time

import p5lab2 as M

L = M.L
log, result, vm, host, sql, wait = L.log, L.result, L.vm, L.host, L.sql, L.wait
OUT = L.OUT


def metrics(v: str) -> dict:
    rc, out = vm(v, "tailscale metrics print")
    d = {}
    for ln in out.splitlines():
        m = re.match(r'tailscaled_(inbound|outbound)_bytes_total\{path="([a-z0-9_]+)"\}\s+(\d+)', ln)
        if m:
            d[f"{m.group(1)}:{m.group(2)}"] = int(m.group(3))
    return d


def delta(a: dict, b: dict) -> dict:
    return {k: b.get(k, 0) - a.get(k, 0) for k in sorted(set(a) | set(b)) if b.get(k, 0) - a.get(k, 0)}


def pong(out: str) -> str:
    return next((x for x in reversed(out.splitlines()) if "pong" in x), (out.splitlines() or [""])[-1])


def peer_line(v: str, name: str) -> str:
    rc, out = vm(v, "tailscale status")
    return next((x for x in out.splitlines() if name in x), "")


def bulk(nat: str, ip: str, label: str, mib: int, n: int = 2) -> list[float]:
    speeds = []
    for _ in range(n):
        rc, out = L.collect(nat, f"bulk {label} {ip} 8000 {mib}", 300)
        m = re.search(r"MBps=([\d.]+)", out)
        log(f"  {nat} bulk {mib} MiB: {out.strip()[-120:]}")
        if rc == 0 and m:
            speeds.append(float(m.group(1)))
    return speeds


def cmd_t06() -> None:
    label = "t06-" + time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    v20 = {}
    for nat, lan, tenant in (("a2", "a1", "tenant-a"), ("b2", "b1", "tenant-b")):
        for v in (nat, lan):
            L.push_collect(v)
        lan_name = "lab-" + lan
        lan_ip = vm(lan, "tailscale ip -4")[1].strip().splitlines()[0]
        L.collect(lan, "unlisten 8000")
        L.collect(lan, "sink 8000")
        try:
            # ---- relay (trạng thái thường trực của a2/b2)
            rc, st0 = L.collect(nat, "relay status")
            m0 = metrics(nat)
            rc, p1 = L.collect(nat, f"ping {label} {lan_ip} 5", 90)
            sp_r = bulk(nat, lan_ip, label, 30)
            m1 = metrics(nat)
            pl_r = peer_line(nat, lan_name)
            d_r = delta(m0, m1)
            relay_ok = "DERP(mg-" + tenant in pong(p1) and sp_r and d_r.get("outbound:derp", 0) > 50e6 \
                and not any(k.startswith("outbound:direct") and v > 1e6 for k, v in d_r.items())
            result("t06", f"AC-16 {nat}→{lan} ({tenant}): ép relay ⇒ via DERP của đúng tenant + TCP thật", bool(relay_ok),
                   f"[{st0.strip()}] {L.redact(pong(p1).strip())}; status: {L.redact(' '.join(pl_r.split()))}; "
                   f"2 × 30 MiB sha256 khớp {sp_r} MB/s; Δ metrics {d_r}")
            # ---- direct (bỏ ép tạm)
            rc, flip = L.collect(nat, "relay direct", 120)
            time.sleep(5)
            bulk(nat, lan_ip, label, 1, 1)   # lưu lượng thật để nâng direct (CL-06)
            p2 = ""
            for _ in range(6):
                rc, p2 = L.collect(nat, f"ping {label} {lan_ip} 5", 90)
                if "via " in pong(p2) and "DERP" not in pong(p2):
                    break
            m2 = metrics(nat)
            sp_d = bulk(nat, lan_ip, label, 30)
            m3 = metrics(nat)
            pl_d = peer_line(nat, lan_name)
            d_d = delta(m2, m3)
            direct_bytes = sum(v for k, v in d_d.items() if k.startswith("outbound:direct"))
            direct_ok = "DERP" not in pong(p2) and "via " in pong(p2) and "direct" in pl_d and direct_bytes > 50e6 \
                and d_d.get("outbound:derp", 0) < direct_bytes / 10
            result("t06", f"AC-15 {nat}→{lan} ({tenant}): direct P2P qua NAT của OPNsense", bool(direct_ok),
                   f"[{flip.strip()}] {L.redact(pong(p2).strip())}; status: {L.redact(' '.join(pl_d.split()))}; "
                   f"2 × 30 MiB {sp_d} MB/s; Δ metrics {d_d}")
            v20[tenant] = {"relay": sp_r, "direct": sp_d, "rtt_relay": pong(p1), "rtt_direct": pong(p2)}
        finally:
            rc, back = L.collect(nat, "relay off", 120)
            time.sleep(3)
            rc, p3 = L.collect(nat, f"ping {label} {lan_ip} 3", 90)
            result("t06", f"{nat}: trả lại ép relay", "DERP(" in pong(p3), f"[{back.strip()}] {L.redact(pong(p3).strip())}")
            L.collect(lan, "unlisten 8000")
            L.collect(lan, "listen 8000")
    for ten, v in v20.items():
        r, d = v["relay"], v["direct"]
        rtt = lambda s: (re.search(r"in (\d+)ms", s) or [None, "?"])[1]  # noqa: E731
        result("t06", f"V-20 thông lượng {ten}: relay qua VPS vs direct (TCP 30 MiB, client kernel)", None,
               f"relay {r} MB/s (RTT {rtt(v['rtt_relay'])} ms) vs direct {d} MB/s (RTT {rtt(v['rtt_direct'])} ms)")
    # ---- V-22
    for v in ("a1", "b1", "a2", "b2"):
        rc, out = vm(v, "tailscale netcheck --format=json")
        j = L.jload(out)
        result("t06", f"V-22 netcheck {v} ({'1' if v.endswith('1') else '2'} lớp NAT)", None,
               f"UDP {j.get('UDP')}; MappingVariesByDestIP {j.get('MappingVariesByDestIP')}; HairPinning {j.get('HairPinning')}; "
               f"UPnP/PMP/PCP {j.get('UPnP')}/{j.get('PMP')}/{j.get('PCP')}; GlobalV4 {L.redact(j.get('GlobalV4') or '')}")
    # ---- IT-09 derpprobe qua Internet (khóa node thật của 2 tenant thử)
    st = L.load_state()
    op, oq = M.owner("p"), M.owner("q")
    kp, kq = L.preauth(op, "dp-tmp-a"), L.preauth(oq, "dp-tmp-b")
    body = (L.ROOT / "tests/isolation/derpprobe/run_lab.sh").read_bytes().replace(b"\r\n", b"\n")
    vm("a1", "cat > ~/p5lab/run_lab.sh", body)
    rc, out = vm("a1", f"sudo -n bash ~/p5lab/run_lab.sh $HOME/p5lab/derpprobe {M.login_url('p')} {M.login_url('q')}",
                 (kp + "\n" + kq + "\n").encode(), 300)
    lines = [L.redact(x) for x in out.splitlines() if x.startswith(("PASS", "FAIL", "node"))]
    (OUT / "t06-derpprobe.txt").write_text("\n".join(lines), encoding="utf-8")
    result("t06", "IT-09 derpprobe qua DNS công khai → VPS → edge: relay của mỗi tenant chỉ nhận node của chính nó",
           rc == 0 and sum(1 for x in lines if x.startswith("PASS")) == 6, " | ".join(lines)[:900])


# ------------------------------------------------------------------------------------------------ T03
def cap(tag: str, secs: int) -> str:
    vm("b1", f"mkdir -p ~/p5lab/cap && rm -f ~/p5lab/cap/{tag}.*")
    vm("b1", f"setsid nohup python3 ~/p5lab/capture.py run {secs} $HOME/p5lab/cap/{tag}.pcap $HOME/p5lab/cap/{tag}.json "
             "</dev/null >/dev/null 2>&1 & echo ok")
    time.sleep(2)
    return tag


def cap_read(tag: str, timeout: float = 200) -> list[dict]:
    out = wait(lambda: (lambda r: r[1] if r[0] == 0 and r[1].strip().startswith("{") else None)(
        vm("b1", f"cat ~/p5lab/cap/{tag}.json 2>/dev/null")), timeout, 5) or "{}"
    rows = (L.jload(out) or {}).get("rows", [])
    (OUT / f"t03-{tag}.json").write_text(L.redact(json.dumps(rows)), encoding="utf-8")
    return rows


def summarize(rows: list[dict], uid: int) -> dict:
    mine = [r for r in rows if r.get("uid") == uid]
    other = sorted({f"{r['uid']}:{r['kind']}→{L.redact(r['dst'])} {L.redact(r['name'])}".strip() for r in rows if r.get("uid") != uid})
    dns = sorted({L.redact(r["name"]) for r in mine if r["kind"] == "dns-query" and r["name"]})
    sni = sorted({L.redact(r["name"]) for r in mine if r["kind"] == "tls-sni"})
    tcp = sorted({f"{r['kind']}→{L.redact(r['dst'])}" for r in mine if r["kind"].startswith("tcp/")})
    udp = sorted({f"{r['kind']}→{L.redact(r['dst'])}" for r in mine if r["kind"].startswith("udp/")})
    return {"dns": dns, "sni": sni, "tcp": tcp, "udp": udp, "khác_uid": other}


def cmd_t03() -> None:
    st = L.load_state()
    # ---- AC-08/09 từ lab (đọc)
    for ten, pair in (("tenant-a", ("a1", "a2")), ("tenant-b", ("b1", "b2"))):
        tid = sql(f"SELECT id FROM tenants WHERE slug = '{ten}'")
        inv = sql(f"SELECT string_agg(coalesce(given_name, name), ',' ORDER BY given_name) FROM device_inventory_cache "
                  f"WHERE tenant_id = '{tid}' AND removed_at IS NULL")
        sees = []
        for v in pair:
            s = L.jload(vm(v, "tailscale status --json")[1])
            sees.append((v, s.get("BackendState"), [p.get("HostName") for p in (s.get("Peer") or {}).values()],
                         (s.get("Self") or {}).get("HostName")))
        ok = all(b == "Running" and len(p) >= 1 for _, b, p, _ in sees)
        result("t03", f"AC-{'08' if ten == 'tenant-a' else '09'}: hai official client đăng ký vào {ten}", ok,
               f"{sees}; sổ thiết bị (inventory): {inv}; client 1.104.7 / Ubuntu 24.04.5")
    # ---- V-27
    op = M.owner("p")
    for f in ("vnode.sh", "capture.py"):
        M.push("b1", f)
    uid = int(vm("b1", "id -u")[1].strip())
    login = M.login_url("p")
    resolv = "nameserver 127.0.0.9\noptions timeout:1 attempts:1\n"
    vm("b1", "mkdir -p /dev/shm/p5cap && cat > /dev/shm/p5cap/resolv.conf", resolv.encode())
    report = {}
    rows0 = []
    cap("s0-baseline", 45)
    rows0 = cap_read("s0-baseline")
    report["S0 nền (không có node tạm)"] = {"all_uids": sorted({str(r['uid']) for r in rows0}),
                                            "root": summarize(rows0, 0), "user": summarize(rows0, uid)}
    for nolog in (False, True):
        env = "TS_NO_LOGS_NO_SUPPORT=true" if nolog else ""
        tag = "nolog" if nolog else "default"
        M.vn("x1", "rm x1")
        cap(f"s1-{tag}", 50)
        M.vn("x1", f"start x1 {M.SOCKS['x1']} {env}")
        report[f"S1 trước đăng nhập [{tag}]"] = summarize(cap_read(f"s1-{tag}"), uid)
        cap(f"s2-{tag}", 75)
        key = L.preauth(op, "x1")
        rc, out = M.vn("x1", f"up x1 {login} x1", key.encode(), 120)
        s = M.vstatus("x1")
        report[f"S2 đăng nhập + map đầy đủ [{tag}]"] = {**summarize(cap_read(f"s2-{tag}"), uid),
                                                         "state": s.get("BackendState"), "peers": len(s.get("Peer") or {})}
        M.vn("x1", "stop x1")
        # S4: DNS hệ thống lỗi — chỉ trong mount namespace của tiến trình (resolv.conf → 127.0.0.9), không đổi hệ thống
        cap(f"s4-{tag}", 60)
        d = vm("b1", "echo /dev/shm/p5v-$(id -un)/x1")[1].strip()
        vm("b1", f"sudo -n unshare -m sh -c 'mount --bind /dev/shm/p5cap/resolv.conf /etc/resolv.conf && exec setpriv "
                 f"--reuid={uid} --regid={uid} --init-groups env {env} tailscaled --tun=userspace-networking --state={d}/state "
                 f"--statedir={d} --socket={d}/sock --port=0' </dev/null >/dev/null 2>&1 & echo started")
        time.sleep(50)
        s = M.vstatus("x1")
        report[f"S4 DNS hệ thống lỗi [{tag}]"] = {**summarize(cap_read(f"s4-{tag}"), uid), "state": s.get("BackendState")}
        vm("b1", f"for p in $(pgrep -u {uid} -x tailscaled); do grep -q x1/sock /proc/$p/cmdline && kill $p; done; true")
        M.vn("x1", "rm x1")
    (OUT / "t03-v27.json").write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    for k, v in report.items():
        result("t03", f"V-27 {k}", None, json.dumps(v, ensure_ascii=False)[:1100])
    vm("b1", "rm -rf /dev/shm/p5cap ~/p5lab/cap")


def main(argv: list[str]) -> int:
    fn = {"t06": cmd_t06, "t03": cmd_t03}.get(argv[1])
    if not fn:
        print(__doc__)
        return 2
    fn()
    return 0
