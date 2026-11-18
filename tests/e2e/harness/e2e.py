#!/usr/bin/env python3
"""Stack dev/CI của P2-T01a + kiểm thử functional (`make e2e-functional` = `all`).

  python3 tests/e2e/harness/e2e.py all      up → test → down (down chạy cả khi lỗi); exit 0 ⇔ mọi ca PASS
  python3 tests/e2e/harness/e2e.py up       build api/worker/web/probe/node-exporter từ cây, render, secret, CA, network, khởi
                                            động stack (gồm backend mg-app: db-bootstrap, migrate, api, worker, web; mg-obs:
                                            prober, prometheus, alertmanager, node-exporter, alertsink), enroll 4 client
  python3 tests/e2e/harness/e2e.py test     chạy các ca trên stack đang chạy (chạy lại được)
  python3 tests/e2e/harness/e2e.py down     lưu log (đã che secret) rồi gỡ mọi đối tượng mang tiền tố
  python3 tests/e2e/harness/e2e.py render   chỉ render (không cần Docker) vào <work>/render để xem

Tham số chạy (E2E_PREFIX, E2E_WORK, E2E_OUT, DOCKER, E2E_KEEP_CACHE, E2E_HEADSCALE_LOCK_KEY, MG_*): xem stack.py.
Mọi kết quả chỉ được ghi "functional" (§22.1): client, Headscale và edge cùng một host Docker (HS-24).
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time

try:
    import fcntl
except ImportError:            # Windows: only `render` is useful there
    fcntl = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import backend  # noqa: E402 — E2E-17 … E2E-25 (P2-T16)
import checks  # noqa: E402
import dualcontrol  # noqa: E402 — E2E-37 … E2E-39 (P3-T05a, P3-T04a)
import idpadmin  # noqa: E402 — E2E-40 … E2E-43 (P3-T15)
import lifecycle  # noqa: E402 — E2E-56 … E2E-58 (P3-T08)
import mailrelay  # noqa: E402 — E2E-82, E2E-83 (P3-T05b-mail: relay thư ra, Worker giả)
import members  # noqa: E402 — E2E-92, E2E-93 (P4-T09: offboard V-23, quy tắc 3a, group sensitive)
import monitoring  # noqa: E402 — E2E-76 … E2E-78 (P3-T16)
import phase3  # noqa: E402 — E2E-32 … E2E-36 (P3-T14a, P3-T03a, P3-T08a)
import portal  # noqa: E402 — E2E-87 (P4-T04: hộp thông báo, lọc rà soát tagged node)
import postrestore  # noqa: E402 — E2E-70, E2E-71 (P3-T17)
import restore  # noqa: E402 — E2E-59, E2E-60 (P3-T11: V-11)
import spa  # noqa: E402 — E2E-85, E2E-86 (P4-T01a: SPA sau edge template v9)
import tagcatalog  # noqa: E402 — E2E-91 (P4-T15: danh mục tag)
from stack import CLIENTS, SECRET_RE, TENANTS, Stack, StackError, log  # noqa: E402

PHASES: dict[str, float] = {}


def timed(name: str):
    class T:
        def __enter__(self):
            self.t0 = time.time()
            log(f"── {name}")

        def __exit__(self, *exc):
            PHASES[name] = round(time.time() - self.t0, 1)
    return T()


def ensure_images(st: Stack) -> None:
    for ref in sorted(set(st.images.values())):
        if st.docker("image", "inspect", ref, check=False).returncode != 0:
            st.docker("pull", "-q", ref, timeout=900)
            log(f"pull {ref.split('@')[0]}")


def ensure_users(st: Stack) -> None:
    st.users = {}
    for slug in TENANTS:
        users = json.loads(st.headscale(slug, "users", "list", "-o", "json").stdout or "[]") or []
        u = next((x for x in users if x.get("name") == "e2e"), None)
        if u is None:
            u = json.loads(st.headscale(slug, "users", "create", "e2e", "-o", "json").stdout)
        st.users[slug] = str(u["id"])


def up(st: Stack) -> None:
    with timed("build image api/worker/web/idp/probe/node-exporter từ cây (infrastructure/docker/app, web, idp, probe, "
               "node-exporter)"):
        st.teardown(quiet=True)
        st.build_app_images()
        st.build_idp_image()
        st.build_probe_image()
        st.build_node_exporter_image()
    with timed("chuẩn bị (render, secret, CA nội bộ, network)"):
        shutil.rmtree(st.out, ignore_errors=True)       # kết quả của lượt trước
        st.work.mkdir(parents=True, exist_ok=True)
        (st.work / "state").mkdir(exist_ok=True)
        st.render()
        st.make_secrets()
        st.make_ca()
        st.write_stack_env()
        st.create_networks()
        st.own_files()
        log(f"Headscale: [images.{st.headscale_lock_key}] {st.images['headscale']}")
    with timed("image (pull nếu thiếu) + file của relay thư (infrastructure/host/mail-secrets.sh — P3-T05b-mail)"):
        ensure_images(st)
        st.make_mail_secrets()
    with timed("IdP (khởi động nền) + build dbinit, helper enrollment (P3-T14a)"):
        st.compose("up", "-d", "idp-db", "idp")
        st.build_dbinit()
        st.build_enroll()
    with timed("PostgreSQL + migration"):
        st.compose("up", "-d", "--wait", "--wait-timeout", "120", "postgres")
        p = st.compose("run", "--rm", "--no-TTY", "db-init", check=False, timeout=300)
        if p.returncode != 0:
            raise StackError("db-init thất bại:\n" + st.redact(p.stderr + p.stdout)[-2000:])
        line = next(ln for ln in reversed(p.stdout.strip().splitlines()) if ln.startswith("{"))
        (st.work / "state" / "dbinit.json").write_text(line, encoding="utf-8")
        log(f"db-init: {line}")
    with timed("Headscale tenant-a, tenant-b + policy deny-all"):
        st.compose("up", "-d", "--wait", "--wait-timeout", "120", "hs-tenant-a", "hs-tenant-b")
        for slug in TENANTS:       # §11.3 bước 12: deny-all TRƯỚC khi instance có đường mạng nào (edge chưa gắn)
            st.headscale(slug, "policy", "set", "-f", "/etc/headscale/bootstrap-policy.hujson")
        log("bootstrap-policy (deny-all) đã áp cho cả hai tenant")
    with timed("edge + stund + prober, gắn edge vào network tenant lúc chạy"):
        st.compose("up", "-d", "--wait", "--wait-timeout", "120", "edge", "stund", "prober")
        for slug in TENANTS:
            st.docker("network", "connect", st.name(f"t-{slug}"), st.name("edge"))
        log("edge gắn vào " + ", ".join(st.name(f"t-{s}") for s in TENANTS) + " (không reload Caddy)")
    with timed("backend mg-app: db-bootstrap, migrate (job một lần), api + worker + web"):
        state = {}
        for job, profile in (("db-bootstrap", "bootstrap"), ("migrate", "migrate")):
            p = st.compose("--profile", profile, "run", "--rm", "--no-TTY", job, check=False, timeout=600)
            if p.returncode != 0:
                raise StackError(f"{job} thất bại:\n" + st.redact(p.stderr + p.stdout)[-2000:])
            line = next(ln for ln in reversed(p.stdout.strip().splitlines()) if ln.startswith("{"))
            state[profile] = json.loads(line)
            log(f"{job}: {line[:300]}")
        (st.work / "state" / "backend.json").write_text(json.dumps(state), encoding="utf-8")
        st.compose("up", "-d", "--wait", "--wait-timeout", "240", "api", "worker", "web", "mail-bridge", "fakeworker",
                   timeout=300)
        log("api, worker, web, mailrelay healthy (/readyz: postgres, secretstore, edge_admin; healthprobe GET /; "
            "smtp_listener, hmac_key, tls_certificate) + Worker giả (devserver của infrastructure/mail/cf-worker)")
    with timed("monitoring mg-obs (P3-T16): prometheus, alertmanager, node-exporter, alertsink"):
        st.compose("up", "-d", "--wait", "--wait-timeout", "120", "prometheus", "alertmanager", "node-exporter", "alertsink",
                   timeout=180)
        (st.work / "state" / "obs.json").write_text(json.dumps({"started": time.time()}), encoding="utf-8")
        log("mg-obs healthy; Prometheus scrape mỗi 5 s, rule mỗi 5 s (môi trường ci)")
    with timed("chờ IdP healthy"):
        st.compose("up", "-d", "--wait", "--wait-timeout", "420", "idp-db", "idp", timeout=480)
    with timed("enroll 4 client (pre-auth key một lần)"):
        ensure_users(st)
        for c, slug in CLIENTS.items():
            key = json.loads(st.headscale(slug, "preauthkeys", "create", "-u", st.users[slug], "-e", "30m",
                                          "-o", "json").stdout)["key"]
            st.secret_values.add(key)
            st.write_private(st.work / "secrets" / "clients" / f"{c}.authkey", key)
        st.own_client_keys([f"clients/{c}.authkey" for c in CLIENTS])
        st.compose("up", "-d", "--no-deps", *(f"ts-{c}" for c in CLIENTS))
        stat = checks.wait_running(st, CLIENTS, 180)
        log("client Running: " + ", ".join(f"{c}={checks.ip4(s['Self'])}" for c, s in stat.items()))


def guarded(r: checks.Results, tid: str, fn, *args):
    """Run one check; an error inside it is that check's FAIL, the next checks still run."""
    try:
        return fn(r, *args)
    except (StackError, OSError, ValueError, KeyError, StopIteration, IndexError, TypeError, AttributeError) as e:
        r.add(tid, f"{fn.__name__}: lỗi khi chạy ca", False, f"{type(e).__name__}: {e}")
        return False


def test(st: Stack, r: checks.Results) -> None:
    ensure_users(st)
    with timed("ca E2E-01, E2E-02 (PostgreSQL, IdP)"):
        f = st.work / "state" / "dbinit.json"
        guarded(r, "E2E-01", checks.check_db, st, json.loads(f.read_text(encoding="utf-8")) if f.exists() else {})
        guarded(r, "E2E-02", checks.check_idp, st)
    with timed("ca E2E-03, E2E-04 (deny-all, enrollment)"):
        for slug in TENANTS:     # chạy lại `test` được: luôn bắt đầu từ baseline deny-all
            st.headscale(slug, "policy", "set", "-f", "/etc/headscale/bootstrap-policy.hujson")
        stat = {c: checks.wait_peer_count(st, c, 0, 60) or checks.status(st, c) for c in CLIENTS}
        guarded(r, "E2E-03", checks.check_baseline, st, stat)
        guarded(r, "E2E-04", checks.check_nodes, st, stat)
    with timed("ca E2E-05 … E2E-11 (test-allow-intra: cô lập, DERP, STUN, TCP, đường đi)"):
        for slug in TENANTS:
            st.headscale(slug, "policy", "set", "-f", "/etc/mg-e2e/test-allow-intra.hujson")
        stat = guarded(r, "E2E-05", checks.check_isolation, st) or {c: checks.status(st, c) for c in CLIENTS}
        ips = {c: checks.ip4(s["Self"]) for c, s in stat.items()}
        guarded(r, "E2E-06", checks.check_derp_map, st)
        guarded(r, "E2E-07", checks.check_stun, st)
        guarded(r, "E2E-08", checks.check_tcp, st, ips)
        guarded(r, "E2E-10", checks.check_paths, st, ips)
    with timed("ca E2E-12, E2E-13 (edge public + admin)"):
        api_keys = {}
        for slug in TENANTS:
            k = json.loads(st.headscale(slug, "apikeys", "create", "-e", "1h", "-o", "json").stdout)
            st.secret_values.add(k)
            api_keys[slug] = k
        try:
            guarded(r, "E2E-12", checks.check_edge_public, st, api_keys)
            guarded(r, "E2E-13", checks.check_edge_admin, st, api_keys)
        finally:
            for slug, k in api_keys.items():
                st.headscale(slug, "apikeys", "expire", "--prefix", k[len("hskey-api-"):][:12], check=False)  # prefix may hold "-"
    with timed("ca E2E-14 (pre-auth key chéo tenant)"):
        guarded(r, "E2E-14", checks.check_cross_tenant_key, st)
    with timed("ca E2E-15 (policy deny)"):
        guarded(r, "E2E-15", checks.check_deny, st, ips)
    with timed("ca E2E-17 … E2E-25, E2E-46, E2E-47, E2E-63, E2E-64, E2E-79 … E2E-81 (backend P2-T16: api/worker, edge "
               "app./admin./auth., OIDC + TOTP, adopt, thiết bị, audit; P3-T05: tạo tenant, /cancel; P3-T13: reconfigure; "
               "P3-T13a: restart/upgrade + upgrade-wave)"):
        backend.run_all(r, st, guarded)
    with timed("ca E2E-85, E2E-86 (P4-T01a: SPA sau edge v9 — app./admin. trả SPA, /api/* vẫn tới api, header một nguồn, "
               "conformance platform; web dừng ⇒ 503 có header, api không ảnh hưởng)"):
        spa.run_all(r, st, guarded)
    with timed("ca E2E-32 … E2E-36 (Phase 3: helper enrollment P3-T14a, prober P3-T03a, lõi policy P3-T08a)"):
        phase3.run_all(r, st, guarded)
    with timed("ca E2E-37 … E2E-39 (Phase 3: lời mời P3-T05a, dual control P3-T04a — Keycloak + TOTP thật)"):
        dualcontrol.run_all(r, st, guarded)
    with timed("ca E2E-40 … E2E-43 (Phase 3: quản trị IdP P3-T15 — idp.audit_sync, console Keycloak sau 2P)"):
        idpadmin.run_all(r, st, guarded)
    with timed("ca E2E-87 (P4-T04: Tenant Portal API — đánh dấu thông báo đã đọc qua edge, lọc tagged/has_expiry)"):
        portal.run_all(r, st, guarded)
    with timed("ca E2E-82, E2E-83 (P3-T05b-mail: relay thư ra — thông báo + thư Keycloak qua mailrelay STARTTLS tới Worker "
               "giả, HMAC đúng/sai, Worker từ chối timestamp cũ/chữ ký sai, không gửi lại)"):
        mailrelay.run_all(r, st, guarded)
    with timed("ca E2E-59, E2E-60 (P3-T11: V-11 — restore bản chụp cũ, Noise key bị thay; restart Headscale của tenant-a)"):
        restore.run_all(r, st, guarded)
    with timed("ca E2E-56 … E2E-58 (Phase 3: suspend/resume P3-T08 — policy suspension, TCP thật, 403 tenant_suspended)"):
        lifecycle.run_all(r, st, guarded)
    with timed("ca E2E-76 … E2E-78 (P3-T16: mg-obs, MG_PROBER_URL của worker, diễn tập mọi rule cảnh báo tới alertsink)"):
        monitoring.run_all(r, st, guarded)
    with timed("ca E2E-92, E2E-93 (P4-T09: offboard hai pha + V-23 với Keycloak/Headscale thật, quy tắc 3a, group sensitive)"):
        members.run_all(r, st, guarded)
    with timed("ca E2E-91 (P4-T15: danh mục tag — CRUD, policy.apply tag_change ⇒ tagOwners, tag chưa khai báo bị từ chối, "
               "xóa tag còn tham chiếu ⇒ 409)"):
        tagcatalog.run_all(r, st, guarded)
    # last: E2E-71 replaces the stack's database by an older dump (restore runbook) — nothing may run after it
    with timed("ca E2E-70, E2E-71 (Phase 3: chế độ bảo trì + đối soát sau restore PostgreSQL P3-T17 — pg_dump/pg_restore thật)"):
        postrestore.run_all(r, st, guarded)


def versions(st: Stack) -> dict[str, str]:
    def first(*cmd: str) -> str:
        p = st.docker(*cmd, check=False)
        return (p.stdout.strip().splitlines() or ["?"])[0][:80]
    return {"headscale": first("exec", st.name("hs-tenant-a"), "headscale", "version"),
            "tailscale": first("exec", st.name("ts-b1"), "tailscale", "version"),
            "caddy (edge)": first("exec", st.name("edge"), "caddy", "version"),
            "api": st.app_images[0][:19], "worker": st.app_images[1][:19], "web": st.app_images[2][:19],
            "probe": st.images["probe"][:19],
            "node-exporter": st.images["node-exporter"][:19],
            "prometheus": first("exec", st.name("prometheus"), "prometheus", "--version"),
            "alertmanager": first("exec", st.name("alertmanager"), "alertmanager", "--version"),
            "postgres": first("exec", st.name("postgres"), "postgres", "--version"),
            "docker": first("version", "--format", "{{.Server.Version}}"),
            "compose": first("compose", "version", "--short")}


def collect(st: Stack) -> None:
    """Redacted logs and the merged compose model into E2E_OUT (artifact of CI)."""
    (st.out / "logs").mkdir(parents=True, exist_ok=True)
    if not (st.work / "stack.env").exists():
        return
    p = st.compose("logs", "--no-color", "--timestamps", check=False, timeout=120)
    (st.out / "logs" / "compose.log").write_text(st.redact(p.stdout + p.stderr), encoding="utf-8")
    p = st.compose("--profile", "tools", "config", check=False)
    (st.out / "compose.config.yaml").write_text(st.redact(p.stdout or p.stderr), encoding="utf-8")
    caddy = st.work / "render" / "edge" / "caddy" / "Caddyfile"
    if caddy.exists():
        (st.out / "Caddyfile.ci").write_text(caddy.read_text(encoding="utf-8"), encoding="utf-8")
    fmt = ("{{.Name}} user={{.Config.User}} read_only={{.HostConfig.ReadonlyRootfs}} cap_drop={{.HostConfig.CapDrop}} "
           "security_opt={{.HostConfig.SecurityOpt}} ports={{.HostConfig.PortBindings}} "
           "networks={{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}")
    ids = st.compose("ps", "-aq", check=False).stdout.split()
    if ids:
        p = st.docker("inspect", "-f", fmt, *ids, check=False)
        (st.out / "containers.txt").write_text(st.redact(p.stdout), encoding="utf-8")


def leak_scan(st: Stack) -> list[str]:
    """Files of E2E_OUT that still hold a secret of this run (value or hskey-/Bearer pattern); such a file is emptied."""
    leaks = []
    for f in sorted(p for p in st.out.rglob("*") if p.is_file()):
        text = f.read_text(encoding="utf-8", errors="replace")
        hit = any(v in text for v in st.secret_values) or any(m.group(0) != "[REDACTED]" for m in SECRET_RE.finditer(text))
        if hit:
            f.write_text("[đã xóa: tệp chứa secret]\n", encoding="utf-8")
            leaks.append(str(f.relative_to(st.out)))
    return leaks


def summary(st: Stack, r: checks.Results | None, total: float, error: str | None, ver: dict[str, str]) -> None:
    rows = r.rows if r else []
    lines = [f"P2-T01a — stack dev/CI, kiểm thử FUNCTIONAL (không phải network E2E verified) — {time.strftime('%Y-%m-%d %H:%M:%S %Z')}",
             f"prefix {st.prefix}; Headscale [images.{st.headscale_lock_key}] {st.images['headscale']}",
             "phiên bản: " + "; ".join(f"{k} {v}" for k, v in ver.items()), ""]
    lines += [f"{x['result']:4} {x['id']:8} [{x['label']}] {x['name']}\n{'':14}{x['detail']}" for x in rows]
    passed = sum(x["result"] == "PASS" for x in rows)
    lines += ["", f"{passed}/{len(rows)} ca PASS (functional); tổng thời gian {total:.0f} s",
              "thời gian từng pha: " + "; ".join(f"{k} {v:.0f} s" for k, v in PHASES.items())]
    if error:
        lines.append(f"LỖI: {st.redact(error)[-1500:]}")
    text = "\n".join(lines) + "\n"
    st.out.mkdir(parents=True, exist_ok=True)
    (st.out / "summary.txt").write_text(text, encoding="utf-8")
    (st.out / "results.json").write_text(json.dumps({"label": "functional", "prefix": st.prefix,
                                                     "headscale_image": st.images["headscale"], "versions": ver,
                                                     "phases_s": PHASES, "total_s": round(total, 1), "error": bool(error),
                                                     "results": rows}, ensure_ascii=False, indent=2), encoding="utf-8")
    print("\n" + text, flush=True)


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    cmd = argv[1] if len(argv) == 2 else ""
    if cmd not in ("all", "up", "test", "down", "render"):
        print(__doc__)
        return 2
    st = Stack()
    st.users = {}
    # one run per prefix at a time: two runs on one stack would change each other's policy mid-check
    lock_path = f"{st.work}.lock"
    lock = open(lock_path, "w")  # noqa: SIM115 — held for the whole process
    if fcntl:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            print(f"đang có một lượt khác dùng tiền tố {st.prefix} ({lock_path}) — dừng", file=sys.stderr)
            return 3
    t0, r, error, ver = time.time(), checks.Results(st), None, {}
    try:
        if cmd == "render":
            st.work.mkdir(parents=True, exist_ok=True)
            st.render()
            log(f"đã render vào {st.work / 'render'}")
            return 0
        if cmd == "down":
            collect(st)
            leaks = leak_scan(st)
            st.teardown()
            os.unlink(lock_path)
            if leaks:
                log(f"LỖI: secret còn trong {leaks} (đã xóa nội dung)")
            return 1 if leaks else 0
        if cmd in ("all", "up"):
            up(st)
        if cmd == "test":
            st.reuse_app_images()   # `up` ran in another process: re-renders (E2E-77) must keep the built images
        if cmd in ("all", "test"):
            test(st, r)
            ver = versions(st)
    except (StackError, OSError, ValueError, KeyError) as e:
        error = f"{type(e).__name__}: {e}"
        log("LỖI: " + st.redact(error)[-3000:])
    finally:
        if cmd == "all":
            if not ver:
                ver = versions(st)
            with timed("lưu log + gỡ stack"):
                collect(st)
                leaks = leak_scan(st)
                r.add("E2E-16", "Artifact (log compose đã che, cấu hình compose đã ghép, Caddyfile) không chứa secret "
                      "nào của lượt chạy", not leaks, f"tệp bị xóa nội dung: {leaks}" if leaks else
                      f"{sum(1 for p in st.out.rglob('*') if p.is_file())} tệp, {len(st.secret_values)} giá trị secret đã dò")
                st.teardown()
            os.unlink(lock_path)
    if cmd in ("all", "test") or error:
        summary(st, r, time.time() - t0, error, ver)
    return 1 if error or (r and r.failed) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
