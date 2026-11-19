#!/usr/bin/env python3
"""E2E Playwright của Web Management (P4-T14) trên stack dev/CI thật — FUNCTIONAL only (§22.1).

Chạy sau `e2e.py up` trên cùng tham số (E2E_PREFIX, E2E_WORK, E2E_OUT, MG_E2E_NET_BASE, DOCKER, …), trên host có Docker
và python3 (hoặc gói gọn: `make e2e-playwright` — dựng → chạy → gỡ):

  WEB_NODE_MODULES=<node_modules đã cài của apps/web (npm ci)> python3 tests/e2e/harness/playwrightui.py [all|prepare|run]

  prepare  chuẩn bị user/dữ liệu (không lặp lại được trên cùng stack — E2E-21), viết <work>/state/pw/config.json
  run      chạy bộ Playwright PW_RUNS lần liên tiếp (mặc định 2) trên config đã chuẩn bị — chạy lại được
  all      prepare + run (mặc định)

Khác với platformui.py/peopleui.py (Vitest + jsdom sau proxy giữ cookie), đây là TRÌNH DUYỆT THẬT: Chromium của image
Playwright chính thức pin digest (versions.lock [images.playwright]) chạy trong container trên mạng riêng <prefix>-pw,
phân giải app./admin./auth.<domain> (--host-resolver-rules) về gateway của mạng đó, nơi một bộ chuyển tiếp TCP thuần
(<prefix>-pwfwd: Node pin digest, --network host, chỉ bind <gateway>:443) nối tới edge:443 — TLS đầu-cuối giữa
Chromium và edge, nguồn mà edge thấy là host (nguồn duy nhất được vào admin.). Không chạy Chromium trong `--network
host`: trên host dùng chung, mạng Docker của stack khác được tạo/xóa liên tục ⇒ Chromium hủy request đang chạy
(net::ERR_NETWORK_CHANGED). Chromium chỉ tin chứng chỉ edge của lượt chạy (SPKI pin); cookie __Host- HttpOnly do
Chromium giữ, CSP của edge áp thật, đăng nhập thật qua Keycloak (mật khẩu + TOTP). Không cài gì lên host.

Chuẩn bị (không phải ca): E2E-17/20/21 của backend.py; Super Admin 1 (check_platform) và Super Admin 2 (bootstrap-
super-admin — dùng cho ca đăng xuất; SA2 tạo một yêu cầu 2P gán Super Admin cho một platform user mới, để chờ — SA1
xem chi tiết); version policy mong muốn của tenant-a (policy-apply bootstrap); Tenant Owner, hai
Tenant Admin (seed-membership), một End User (mời qua API + đăng nhập lần đầu); một group; đồng bộ thiết bị tenant-a
(inventory.sync — Devices có dữ liệu thật). Mỗi user đã đăng nhập một lần qua harness (TOTP đã cấu hình); khóa TOTP và
bộ đếm cuối được đưa cho Playwright qua config.json (0600, trong <work> — bị xóa khi gỡ stack).

  PW-1, PW-2  hai lượt liên tiếp của bộ Playwright (apps/web/e2e: setup đăng nhập + spec × hai project vi/en): mọi test
              không bị skip/fixme PASS, 0 flaky (retries = 0); báo cáo HTML + results.json + trace khi lỗi dưới
              <out>/playwright/run<i>/
  PW-S        artifact không chứa giá trị secret nào của lượt (mật khẩu, khóa TOTP, secret của stack) — kể cả bên
              trong trace (.zip)

Thư viện chuẩn. Mật khẩu, TOTP, cookie chỉ nằm trong tiến trình này, config.json và storage state trong <work>.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import pathlib
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
import tomllib
import uuid
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import backend  # noqa: E402
import checks  # noqa: E402
from backend import TOTP, KeycloakAdmin, admin_cmd  # noqa: E402
from dualcontrol import tenant_id, unsafe  # noqa: E402
from idpadmin import platform_session  # noqa: E402
from members import invited_member, seeded, wait_job  # noqa: E402
from phase3 import policy_apply  # noqa: E402
from stack import ROOT, Stack, StackError, log  # noqa: E402
import dualcontrol  # noqa: E402


def pw_image() -> str:
    lock = tomllib.loads((ROOT / "versions.lock").read_text(encoding="utf-8"))["images"]["playwright"]
    return os.environ.get("PLAYWRIGHT_IMAGE", f"{lock['image']}@{lock['index']}")


def pw_dir(st: Stack) -> pathlib.Path:
    return st.work / "state" / "pw"


def edge_spki(st: Stack) -> str:
    """base64(sha256(SubjectPublicKeyInfo DER)) của chứng chỉ edge (lá, do CA dùng-một-lần của lượt ký) — đối số
    --ignore-certificate-errors-spki-list của Chromium (Chromium so với khóa của chứng chỉ server đưa ra). Chứng chỉ lấy
    qua bắt tay TLS thật tới edge, đã kiểm theo CA của lượt chạy (ssl của Python với cafile = ca.crt)."""
    ctx = ssl.create_default_context(cafile=str(st.work / "ca" / "ca.crt"))
    with socket.create_connection((st.edge_ip, 443), timeout=20) as raw:
        with ctx.wrap_socket(raw, server_hostname=f"app.{st.domain}") as tls:
            der_cert = tls.getpeercert(binary_form=True)
    pub = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-pubkey"], input=der_cert,
                         capture_output=True, check=True, timeout=30).stdout
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=pub, capture_output=True, check=True,
                         timeout=30).stdout
    return base64.b64encode(hashlib.sha256(der).digest()).decode()


def as_user(u: dict, display: str) -> dict:
    otp: TOTP = u["otp"]
    return {"username": u["username"], "password": u["password"], "totpKey": otp.key.decode(), "totpLast": otp.last,
            "displayName": display}


def prepare(st: Stack) -> dict:
    """Điều kiện của bộ Playwright; lỗi ⇒ StackError. Viết config.json, trả về nó."""
    state = json.loads((st.work / "state" / "backend.json").read_text(encoding="utf-8"))
    pre = checks.Results(st)
    backend.check_ready(pre, st, state)
    backend.check_idp_bootstrap(pre, st)
    backend.check_registry(pre, st, state)
    if pre.failed:
        raise StackError("chuẩn bị (E2E-17/20/21) thất bại: " + "; ".join(x["id"] for x in pre.rows if x["result"] != "PASS"))
    backend.check_platform(checks.Results(st), st, state)     # Super Admin 1 (st.platform_sa), đã đăng nhập (TOTP)
    kc = KeycloakAdmin(st)
    sa2 = {"username": "pw-sa2-" + secrets.token_hex(3), "password": secrets.token_urlsafe(18), "otp": TOTP()}
    st.secret_values.add(sa2["password"])
    sa2["sub"] = kc.create_user("platform", sa2["username"], sa2["password"])
    p = admin_cmd(st, ["bootstrap-super-admin", "--subject", sa2["sub"], "--display-name", "PW SA2"],
                  env={"MG_IDP_ID_PLATFORM": st.env["MG_IDP_ID_PLATFORM"]})
    b2, s2 = platform_session(st, sa2)
    base = (ROOT / "infrastructure" / "headscale" / "templates" / "bootstrap-policy.hujson").read_text(encoding="utf-8")
    code, out, _ = policy_apply(st, base, "--trigger", "bootstrap")
    a_id, b_id = tenant_id(st, "tenant-a"), tenant_id(st, "tenant-b")
    ob, osess, owner = dualcontrol.owner_session(st, "tenant-a")
    tb, tsess, admin = seeded(st, "tenant_admin", "pw-ta")
    _, _, admin2 = seeded(st, "tenant_admin", "pw-ta2")
    mem, _, _, _ = invited_member(st, ob, osess, a_id, "end_user")
    api = f"https://app.{st.domain}/api/v1"
    g = tb.request("POST", f"{api}/tenants/{a_id}/groups", json.dumps({"name": "pw-group-" + secrets.token_hex(3)}).encode(),
                   unsafe(st, tsess, **{"Idempotency-Key": "pw-" + secrets.token_hex(8)}))
    sync = ob.request("POST", f"{api}/tenants/{a_id}/devices/sync", None,
                      unsafe(st, osess, **{"Idempotency-Key": "pw-sync-" + secrets.token_hex(6)}))
    sync_status = wait_job(st, sync.json().get("id", ""))[0] if sync.status == 202 else f"HTTP {sync.status}"
    # một yêu cầu 2P đang chờ do SA2 tạo (gán Super Admin cho một platform user mới) — SA1 xem chi tiết: hash payload
    # tính trong trình duyệt (crypto.subtle) phải khớp server; không ai duyệt
    adm = f"https://admin.{st.domain}/api/v1"
    hdr = {"Origin": f"https://admin.{st.domain}", "X-CSRF-Token": s2.get("csrf_token", ""),
           "Content-Type": "application/json"}
    target_pw = secrets.token_urlsafe(18)              # không ai đăng nhập bằng user này
    st.secret_values.add(target_pw)
    target_sub = kc.create_user("platform", "pw-pu-" + secrets.token_hex(3), target_pw)
    pu = b2.request("POST", f"{adm}/platform/users", json.dumps({"subject": target_sub, "role": "platform_viewer",
                                                                  "display_name": "PW viewer"}).encode(),
                    {**hdr, "Idempotency-Key": str(uuid.uuid4())})
    ap = pu
    if pu.status == 201:
        ap = b2.request("PUT", f"{adm}/platform/users/{pu.json().get('id', '')}/super-admin-role",
                        json.dumps({"super_admin": True, "reason": "P4-T14 e2e (không duyệt)"}).encode(), hdr)
    role2 = s2.get("principal", {}).get("platform_role")
    if (p.returncode != 0 or role2 != "super_admin" or code != 0 or g.status != 201 or sync_status != "succeeded"
            or ap.status != 202):
        raise StackError(f"chuẩn bị: SA2 bootstrap {p.returncode} role {role2}, policy-apply {code} {out.get('state')}, "
                         f"group {g.status}, sync {sync_status}, platform user {pu.status} 2P {ap.status} "
                         f"{ap.body[:200]!r}")
    cfg = {"domain": st.domain, "edgeIp": st.edge_ip, "tlsSpki": edge_spki(st),
           "tenantA": {"id": a_id, "slug": "tenant-a"}, "tenantB": {"id": b_id, "slug": "tenant-b"},
           "platformApprovalId": ap.json().get("id", ""),
           "users": {"sa": as_user(st.platform_sa, "E2E SA"), "sa2": as_user(sa2, "PW SA2"),
                     "owner": as_user(owner, "E2E Owner tenant-a"), "admin": as_user(admin, "E2E pw-ta"),
                     "admin2": as_user(admin2, "E2E pw-ta2"), "member": as_user(mem, "member")}}
    d = pw_dir(st)
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    f = d / "config.json"
    f.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(f, 0o600)
    log(f"chuẩn bị xong: SA1, SA2, Owner, 2 Admin, End User, group, sync {sync_status}, policy-apply {out.get('state')}, "
        "một yêu cầu 2P platform.user.super_admin đang chờ")
    return cfg


def secret_set(st: Stack, cfg: dict) -> set[str]:
    vals = {v for v in st.secret_values if v and len(v) >= 8}
    for u in cfg.get("users", {}).values():
        vals |= {u["password"], u["totpKey"]}
    return vals


# bộ chuyển tiếp TCP thuần (không giải mã TLS): <gateway của mạng pw>:443 → edge:443, từ network namespace của host
FORWARDER_JS = """
const net = require("node:net");
const target = process.env.FWD_TARGET;
net.createServer((c) => {
  const u = net.connect(443, target);
  const end = () => { c.destroy(); u.destroy(); };
  for (const s of [c, u]) { s.on("error", end); s.on("close", end); }
  c.pipe(u); u.pipe(c);
}).listen(443, process.env.FWD_LISTEN, () => console.log("listening"));
"""


class Forwarder:
    """Mạng <prefix>-pw (bridge, <base>.9.0/24) + container <prefix>-pwfwd; `ip` = gateway (địa chỉ của host trên
    mạng đó) mà Chromium dùng cho app./admin./auth.<domain>."""

    def __init__(self, st: Stack):
        self.st = st
        base = st.edge_ip.rsplit(".", 2)[0]
        self.net, self.name, self.ip = st.name("pw"), st.name("pwfwd"), f"{base}.9.1"
        self.stop()
        st.docker("network", "create", "--driver", "bridge", "--subnet", f"{base}.9.0/24", "--gateway", self.ip,
                  "--label", "meshguard.role=e2e", self.net)
        st.docker("run", "-d", "--name", self.name, "--network", "host", "--read-only", "--cap-drop", "ALL",
                  "--cap-add", "NET_BIND_SERVICE", "--security-opt", "no-new-privileges", "--label", "meshguard.role=e2e",
                  "-e", f"FWD_LISTEN={self.ip}", "-e", f"FWD_TARGET={st.edge_ip}", st.images["node"], "node", "-e",
                  FORWARDER_JS)
        end = time.time() + 30
        while "listening" not in st.docker("logs", self.name, check=False).stdout:
            if time.time() > end:
                raise StackError("bộ chuyển tiếp Playwright không lắng nghe: "
                                 + st.docker("logs", self.name, check=False).stderr[-300:])
            time.sleep(0.5)

    def stop(self) -> None:
        self.st.docker("rm", "-f", self.name, check=False)
        self.st.docker("network", "rm", self.net, check=False)


def run_once(st: Stack, i: int, fwd: Forwarder) -> dict:
    nm = os.environ.get("WEB_NODE_MODULES", "")
    if not nm or not pathlib.Path(nm, "@playwright", "test").exists():
        raise StackError("WEB_NODE_MODULES phải trỏ tới node_modules đã cài của apps/web (npm ci) — gồm @playwright/test")
    out = st.out / "playwright" / f"run{i}"
    if out.exists():
        subprocess.run([*st.docker_cmd, "run", "--rm", "-v", f"{out.parent}:/o", st.images["alpine"], "rm", "-rf",
                        f"/o/run{i}"], check=False, capture_output=True, timeout=120)
    out.mkdir(parents=True, exist_ok=True)
    os.chmod(out, 0o777)
    (ROOT / "apps" / "web" / "node_modules").mkdir(exist_ok=True)   # điểm gắn của node_modules (cây gắn chỉ-đọc)
    d = pw_dir(st)
    name = f"{st.prefix}-pw{i}"
    cmd = [*st.docker_cmd, "run", "--rm", "--name", name, "--network", fwd.net, "--shm-size", "1g", "--init",
           "-u", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp", "-e", "CI=1",
           "-e", "MG_PW_CONFIG=/pw/config.json", "-e", "MG_PW_OUT=/out", "-e", f"MG_PW_EDGE={fwd.ip}",
           "-v", f"{ROOT}:/src:ro", "-v", f"{nm}:/src/apps/web/node_modules:ro", "-v", f"{d}:/pw", "-v", f"{out}:/out",
           "-w", "/src/apps/web", pw_image(), "npx", "--no-install", "playwright", "test", *os.environ.get("PW_ARGS", "").split()]
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=3600,
                           check=False)
    except subprocess.TimeoutExpired as e:
        st.docker("rm", "-f", name, check=False)
        raise StackError(f"Playwright lượt {i}: quá 3600 s") from e
    text = re.sub(r"\x1b\[[0-9;]*m", "", p.stdout + p.stderr)
    (out / "playwright.log").write_text(st.redact(text), encoding="utf-8")
    res = out / "results.json"
    stats = json.loads(res.read_text(encoding="utf-8")).get("stats", {}) if res.exists() else {}
    stats.update(exit=p.returncode, seconds=round(time.time() - t0))
    stats["failed_titles"] = failed_titles(res) if res.exists() else []
    stats["counts"] = count_tests(res) if res.exists() else {}
    log(f"Playwright lượt {i}: exit {p.returncode}, {stats.get('expected')} pass, {stats.get('unexpected')} fail, "
        f"{stats.get('flaky')} flaky, {stats.get('skipped')} skip, {stats['seconds']} s")
    return stats


def walk_specs(suite: dict):
    for s in suite.get("suites", []) or []:
        yield from walk_specs(s)
    for spec in suite.get("specs", []) or []:
        for t in spec.get("tests", []) or []:
            yield spec, t


def failed_titles(res: pathlib.Path) -> list[str]:
    data = json.loads(res.read_text(encoding="utf-8"))
    out = []
    for top in data.get("suites", []):
        for spec, t in walk_specs(top):
            if t.get("status") not in ("expected", "skipped"):
                out.append(f"[{t.get('projectName')}] {spec.get('file')}: {spec.get('title')} ({t.get('status')})")
    return out


def count_tests(res: pathlib.Path) -> dict:
    """Số test theo project × trạng thái (expected/unexpected/flaky/skipped)."""
    data = json.loads(res.read_text(encoding="utf-8"))
    out: dict[str, dict[str, int]] = {}
    for top in data.get("suites", []):
        for _, t in walk_specs(top):
            row = out.setdefault(t.get("projectName", "?"), {})
            row[t.get("status", "?")] = row.get(t.get("status", "?"), 0) + 1
    return out


COOKIE_RE = re.compile(rb"(__Host-mg_[a-z_]+=)[A-Za-z0-9_-]{16,}")   # cookie phiên trong header (log lỗi, trace)


def session_values(st: Stack) -> set[str]:
    """Giá trị cookie của các storage state (phiên của spec — trace của test lỗi có thể mang chúng)."""
    out = set()
    for f in pw_dir(st).glob("state-*.json"):
        try:
            out |= {c["value"] for c in json.loads(f.read_text(encoding="utf-8")).get("cookies", [])
                    if len(c.get("value", "")) >= 16}
        except (OSError, ValueError):
            pass
    return out


def _scrub(data: bytes, values: set[str]) -> bytes:
    for v in values:
        data = data.replace(v.encode(), b"[REDACTED]")
    return COOKIE_RE.sub(rb"\1[REDACTED]", data)


def _scrub_zip(raw: bytes, values: set[str]) -> bytes:
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        members = [(i, z.read(i.filename)) for i in z.infolist()]
    clean = [(i, _scrub(_scrub_embedded(d, values), values)) for i, d in members]
    if all(d == c for (_, d), (_, c) in zip(members, clean)):
        return raw
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for i, d in clean:
            z.writestr(i, d)
    return buf.getvalue()


EMBEDDED_ZIP = re.compile(rb"(data:application/zip;base64,)([A-Za-z0-9+/=]+)")   # dữ liệu nhúng của báo cáo HTML


def _scrub_embedded(data: bytes, values: set[str]) -> bytes:
    return EMBEDDED_ZIP.sub(lambda m: m.group(1) + base64.b64encode(
        _scrub_zip(base64.b64decode(m.group(2)), values)), data)


def _expand(f: pathlib.Path) -> list[tuple[str, bytes]]:
    """Nội dung cần dò của một tệp: chính nó, các mục của .zip, các zip base64 nhúng trong báo cáo HTML (đệ quy)."""
    raw = f.read_bytes()
    out, todo = [], [(f.name, raw)]
    while todo:
        name, data = todo.pop()
        if data[:4] == b"PK\x03\x04":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    todo += [(f"{name}:{n}", z.read(n)) for n in z.namelist()]
                continue
            except zipfile.BadZipFile:
                pass
        out.append((name, data))
        todo += [(f"{name}:base64", base64.b64decode(m.group(2))) for m in EMBEDDED_ZIP.finditer(data)]
    return out


def sanitize(root: pathlib.Path, values: set[str]) -> list[str]:
    """Che cookie phiên (và mọi giá trị secret) trong artifact — kể cả trong trace .zip và dữ liệu zip nhúng của báo
    cáo HTML; trả về các tệp đã sửa."""
    changed: list[str] = []
    for f in sorted(x for x in root.rglob("*") if x.is_file()):
        raw = f.read_bytes()
        try:
            clean = _scrub_zip(raw, values) if raw[:4] == b"PK\x03\x04" else _scrub(_scrub_embedded(raw, values), values)
        except (zipfile.BadZipFile, ValueError):
            continue
        if clean != raw:
            f.write_bytes(clean)
            changed.append(str(f.relative_to(root)))
    return changed


def leak_scan(root: pathlib.Path, values: set[str]) -> list[str]:
    """Tệp dưới root (kể cả mục .zip và zip nhúng của báo cáo HTML) còn chứa một giá trị secret hay cookie phiên."""
    hits = []
    for f in sorted(x for x in root.rglob("*") if x.is_file()):
        for name, data in _expand(f):
            if any(v.encode() in data for v in values) or COOKIE_RE.search(data.replace(b"[REDACTED]", b"")):
                hits.append(str(f.relative_to(root)) + ("" if name == f.name else f" ({name.split(':', 1)[1]})"))
    return hits


def run_all(st: Stack, r: checks.Results, cfg: dict) -> None:
    runs = int(os.environ.get("PW_RUNS", "2"))
    fwd = Forwarder(st)
    try:
        stats = [run_once(st, i, fwd) for i in range(1, runs + 1)]
    finally:
        fwd.stop()
    for i, s in enumerate(stats, start=1):
        ok = (s.get("exit") == 0 and s.get("unexpected", 1) == 0 and s.get("flaky", 1) == 0
              and s.get("expected", 0) > 0)
        r.add(f"PW-{i}", f"P4-T14: bộ Playwright lượt {i} (setup đăng nhập 4 vai trò + spec × vi/en; axe WCAG 2.1 AA, i18n, "
              "CSP, lưu trữ trình duyệt, cách ly tenant) — mọi test PASS, 0 flaky", ok,
              f"{s.get('expected')} pass, {s.get('unexpected')} fail, {s.get('flaky')} flaky, {s.get('skipped')} skip "
              f"(fixme enrollment), {s.get('seconds')} s; theo project {s.get('counts')}; lỗi {s.get('failed_titles')[:12]}",
              limit=2000)
    root = st.out / "playwright"
    values = secret_set(st, cfg) | session_values(st)
    scrubbed = sanitize(root, values)
    hits = leak_scan(root, values)
    r.add("PW-S", "P4-T14: artifact Playwright (báo cáo HTML, results.json, log, trace .zip) không chứa secret của lượt "
          "(mật khẩu, khóa TOTP, secret của stack) — cookie phiên trong trace/log lỗi đã được che trước khi dò",
          not hits, f"{sum(1 for x in root.rglob('*') if x.is_file())} tệp, đã che giá trị phiên trong {scrubbed}; "
          f"còn trúng {hits[:10]}", limit=900)


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode not in ("all", "prepare", "run"):
        print(__doc__)
        return 2
    st = Stack()
    st.users = {}
    r = checks.Results(st)
    error = None
    try:
        if mode in ("all", "prepare"):
            cfg = prepare(st)
        else:
            cfg = json.loads((pw_dir(st) / "config.json").read_text(encoding="utf-8"))
        if mode in ("all", "run"):
            run_all(st, r, cfg)
    except (StackError, OSError, ValueError, KeyError, subprocess.SubprocessError) as e:
        error = f"{type(e).__name__}: {st.redact(str(e))[-1500:]}"
        log("LỖI: " + error)
    lines = [f"{x['result']:4} {x['id']:8} [{x['label']}] {x['name']}\n{'':14}{x['detail']}" for x in r.rows]
    passed = sum(x["result"] == "PASS" for x in r.rows)
    text = "\n".join(lines) + f"\n\n{passed}/{len(r.rows)} ca PASS (functional)" + (f"\nLỖI: {error}" if error else "") + "\n"
    (st.out / "playwright").mkdir(parents=True, exist_ok=True)
    (st.out / "playwright" / f"summary-{mode}.txt").write_text(text, encoding="utf-8")
    print(text, flush=True)
    return 1 if error or r.failed else 0


if __name__ == "__main__":
    sys.exit(main())
