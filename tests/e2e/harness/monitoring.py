"""P3-T16 on the dev/CI stack — project mg-obs (tools/render_monitoring.py for the ci environment, merged into the stack):

  E2E-76  the monitoring stack: every service non-root, read-only, cap_drop ALL, no-new-privileges, no published port,
          on the networks of §14.3 (prometheus, node-exporter, alertsink only obs; alertmanager obs + egress; prober edge,
          admin, obs, egress); every scrape target up (api, worker, node, prober, alertmanager, alertsink, Prometheus,
          both Headscale instances through the edge's metrics listener with the token file, /key and TLS probes through
          the prober); tenant labels from the target list; 16 alert rules loaded and healthy; /probe refused to any
          caller but Prometheus, the edge's metrics listener refused without the token; Alertmanager routes to the sink
  E2E-77  MG_PROBER_URL: compose.app.yaml re-rendered with the prober's static address on the admin network
          (render_monitoring.prober_url — render_app refuses anything else), worker recreated ⇒ relay.probe runs by its
          schedule against it (both regions probed, A healthy, B unhealthy from E2E-66's closed STUN port), and from the
          worker's own network namespace the RPC of provisioning steps 18 (edge check) and 17 (relay) are accepted
  E2E-78  alert drills: every rule fires once and its notification reaches the alert channel (the alertsink): real
          sources — tenant-b's Headscale stopped (TenantInstanceDown + TenantControlProbeFailed, then resolved), api
          stopped (PlatformTargetDown), tenant-a's instance without a backup for 3 h (TenantBackupOverdue from the
          worker's gauge), the run's 1-day certificates (CertificateExpiringSoon), PostgreSQL's status.prom 30 h old and
          IdP's missing (PlatformBackupOverdue, PlatformBackupStatusMissing); every other rule through the drill files of
          tools/render_monitoring.py (the staging procedure), whose HostRebooted drill must not inhibit the real alerts.
"""
from __future__ import annotations

import datetime
import json
import secrets
import time
import urllib.parse

import render_monitoring
from backend import container, psql
from relayread import _region
from stack import TENANTS, ENV_DIR, Stack, log

DRILL_SINCE_SLACK = 5   # seconds: a drill's notification must arrive after the drill started


def _sync_addresses(st: Stack) -> None:
    """The stack's static addresses in render_monitoring (render() did it in an `all` run; `test` alone did not)."""
    render_monitoring.OBS_IPS.update(st.obs_ips)
    render_monitoring.PROBER_IPS.update(prober_admin_ip=st.prober_admin_ip)


def obs_get(st: Stack, url: str, timeout: float = 60) -> tuple[int, str, str]:
    """GET from a throwaway container (pinned alpine, busybox wget) on the obs network: (exit code, body, stderr)."""
    p = st.docker("run", "--rm", "--name", st.name(f"obs-get-{secrets.token_hex(3)}"), "--network", st.name("obs"),
                  "--read-only", "--cap-drop", "ALL", st.images["alpine"], "wget", "-S", "-T", "15", "-O", "-", url,
                  check=False, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def prom(st: Stack, path: str) -> dict:
    rc, body, _ = obs_get(st, f"http://{st.obs_ips['prometheus_ip']}:9090{path}")
    try:
        return json.loads(body) if rc == 0 else {}
    except ValueError:
        return {}


def query(st: Stack, expr: str) -> list[dict]:
    return prom(st, "/api/v1/query?query=" + urllib.parse.quote(expr, safe="")).get("data", {}).get("result", [])


def notifications(st: Stack) -> list[dict]:
    rc, body, _ = obs_get(st, f"http://{st.obs_ips['alertsink_ip']}:8080/v1/notifications")
    try:
        return json.loads(body).get("notifications", []) if rc == 0 else []
    except ValueError:
        return []


def _ts(v: str) -> float:
    try:
        return datetime.datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return 0.0


def received(notes: list[dict], alertname: str, labels: dict[str, str], status: str = "firing", since: float = 0) -> bool:
    """A notification received after `since` holds an alert `alertname` with `status` and these labels."""
    for n in notes:
        if _ts(n.get("received_at", "")) < since:
            continue
        for a in n.get("alerts", []):
            lab = a.get("labels", {})
            if a.get("status") == status and lab.get("alertname") == alertname and all(lab.get(k) == v for k, v in labels.items()):
                return True
    return False


def _inspect(st: Stack, name: str) -> dict:
    fmt = ("{{json .Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|"
           "{{len .HostConfig.PortBindings}}|{{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}|"
           "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.HostConfig.PidMode}}")
    out = st.docker("inspect", "-f", fmt, st.name(name), check=False).stdout.strip()
    parts = out.split("|")
    if len(parts) != 8:
        return {}
    user, ro, caps, sec, ports, nets, health, pid = parts
    return {"user": json.loads(user), "ro": ro, "caps": json.loads(caps), "sec": json.loads(sec) or [], "ports": ports,
            "nets": dict(x.split("=", 1) for x in nets.split()), "health": health, "pid": pid}


# ---------------------------------------------------------------------------------------------------- E2E-76
def check_stack(r, st: Stack) -> None:
    want = {"prometheus": ("65534:65534", {"obs": st.obs_ips["prometheus_ip"]}),
            "alertmanager": ("65534:65534", {"obs": st.obs_ips["alertmanager_ip"], "egress": None}),
            "node-exporter": ("65534:65534", {"obs": st.obs_ips["node_exporter_ip"]}),
            "alertsink": ("65532:65532", {"obs": st.obs_ips["alertsink_ip"]}),
            "prober": ("65532:65532", {"edge": None, "admin": st.prober_admin_ip, "obs": st.obs_ips["prober_obs_ip"],
                                       "egress": None})}
    rows, ok = [], True
    for svc, (user, nets) in want.items():
        i = _inspect(st, svc)
        got_nets = {k.removeprefix(st.prefix + "-"): v for k, v in i.get("nets", {}).items()}
        good = (bool(i) and i["user"] == user and i["ro"] == "true" and i["caps"] == ["ALL"]
                and "no-new-privileges:true" in i["sec"] and i["ports"] == "0" and set(got_nets) == set(nets)
                and all(v is None or got_nets.get(k) == v for k, v in nets.items())
                and i["health"] in (("none",) if svc == "node-exporter" else ("healthy",))
                and (i["pid"] == "host") == (svc == "node-exporter"))
        ok &= good
        rows.append(f"{svc} {i.get('user')} nets {sorted(got_nets)} {i.get('health')}{' pid host' if i.get('pid') == 'host' else ''}"
                    + ("" if good else " ✗"))
    jobs: dict[str, list[dict]] = {}
    deadline = time.time() + 90
    while True:
        targets = prom(st, "/api/v1/targets?state=active").get("data", {}).get("activeTargets", [])
        jobs = {}
        for t in targets:
            jobs.setdefault(t.get("labels", {}).get("job", "?"), []).append(t)
        if targets and all(t.get("health") == "up" for t in targets) or time.time() > deadline:
            break
        time.sleep(5)
    want_jobs = {"prometheus": 1, "alertmanager": 1, "node": 1, "prober": 1, "alertsink": 1, "api": 1, "worker": 1,
                 "headscale": 2, "probe-key-edge": 2, "probe-tls": 3}
    counts = {j: len(v) for j, v in jobs.items()}
    down = [f"{j}/{t.get('labels', {}).get('instance')}: {t.get('lastError', '')[:80]}" for j, v in jobs.items()
            for t in v if t.get("health") != "up"]
    ok &= counts == want_jobs and not down
    rows.append(f"targets {sum(counts.values())} up, {len(down)} down {down[:3]}")
    params = {s: json.loads((ENV_DIR / "tenants" / f"{s}.json").read_text(encoding="utf-8")) for s in TENANTS}
    hs = {t["labels"].get("slug"): t["labels"] for t in jobs.get("headscale", [])}
    labels_ok = all(hs.get(s, {}).get("tenant_id") == params[s]["tenant_id"] and
                    hs.get(s, {}).get("instance_id") == params[s]["instance_id"] for s in TENANTS)
    ok &= labels_ok
    keys = {x["metric"].get("slug"): x["value"][1] for x in query(st, 'probe_success{module="key"}')}
    up_hs = {x["metric"].get("slug"): x["value"][1] for x in query(st, 'up{job="headscale"}')}
    certs = query(st, "probe_ssl_earliest_cert_expiry")
    left = min((float(x["value"][1]) - time.time() for x in certs), default=-1)
    probes_ok = keys == {"tenant-a": "1", "tenant-b": "1"} and up_hs == {"tenant-a": "1", "tenant-b": "1"} \
        and len(certs) == 5 and 0 < left < 2 * 86400
    ok &= probes_ok
    rows.append(f"labels from targets {labels_ok}; /key {keys}; up headscale {up_hs}; {len(certs)} certificates, "
                f"earliest in {left / 3600:.1f} h")
    groups = prom(st, "/api/v1/rules?type=alert").get("data", {}).get("groups", [])
    rules = [x for g in groups for x in g.get("rules", [])]
    rules_ok = len(rules) == 16 and all(x.get("health") == "ok" for x in rules)
    ok &= rules_ok
    rows.append(f"{len(rules)} alert rules, health {sorted({x.get('health') for x in rules})}")
    edge = f"{st.edge_ip}:443"
    rc, body, err = obs_get(st, f"http://{st.obs_ips['prober_obs_ip']}:9090/probe?module=key&target={edge}"
                                f"&host=tenant-a.{st.mesh}")
    refused_probe = rc != 0 and "403" in err and "probe_success" not in body
    rc2, body2, err2 = obs_get(st, f"http://{st.obs_ip}:9091/instance/tenant-a/metrics")
    refused_metrics = rc2 != 0 and "403" in err2 and "headscale" not in body2
    # Alertmanager's status API redacts webhook URLs (<secret>): the route is proven by what reached the sink — the
    # run's 1-day certificates fire CertificateExpiringSoon within minutes of mg-obs starting
    rc3, body3, _ = obs_get(st, f"http://{st.obs_ips['alertmanager_ip']}:9093/api/v2/status")
    try:
        am = json.loads(body3).get("config", {}).get("original", "") if rc3 == 0 else ""
    except ValueError:
        am = ""
    sunk = query(st, "sum(meshguard_alertsink_notifications_total)")
    delivered = float(sunk[0]["value"][1]) if sunk else 0.0
    routed = "receiver: meshguard" in am and "webhook_configs:" in am and delivered > 0
    textfile_ok = [x["value"][1] for x in query(st, "node_textfile_scrape_error")] == ["0"]
    ok &= refused_probe and refused_metrics and routed and textfile_ok
    rows.append(f"/probe from another caller refused {refused_probe}; metrics listener without token refused "
                f"{refused_metrics}; Alertmanager receiver meshguard → alertsink, {delivered:.0f} notification(s) "
                f"received; textfile collector error-free {textfile_ok}")
    r.add("E2E-76", "P3-T16 mg-obs: hardening + network §14.3 của 5 service, mọi đích scrape up (api, worker, node, prober, "
          "alertmanager, alertsink, 2 Headscale qua listener metrics của edge có token, /key và chứng chỉ qua prober), nhãn "
          "tenant từ danh sách đích, 16 rule hợp lệ, /probe chỉ cho Prometheus, listener metrics từ chối khi thiếu token, "
          "Alertmanager gửi tới alertsink", ok, "; ".join(rows), limit=1200)


# ---------------------------------------------------------------------------------------------------- E2E-77
def check_prober_url(r, st: Stack) -> None:
    url = render_monitoring.prober_url()
    rows, ok = [f"MG_PROBER_URL {url}"], True
    admin_ip = _inspect(st, "prober").get("nets", {}).get(st.name("admin"))
    ok &= admin_ip == st.prober_admin_ip and url == f"http://{st.prober_admin_ip}:8080"
    regions = {s: _region(st, s) for s in TENANTS}
    if not all(regions.values()):
        r.add("E2E-77", "P3-T16 MG_PROBER_URL của worker", False, "không có hàng relay của E2E-65 — chạy cả chuỗi")
        return
    psql(st, "UPDATE relay_regions SET last_probe = NULL, last_probe_at = NULL WHERE code IN ('mg-tenant-a', 'mg-tenant-b') "
             "RETURNING id")
    t0 = psql(st, "SELECT now()::text")[0][0]
    st.env["MG_PROBER_URL"] = url
    try:
        st.render_app()
        st.compose("up", "-d", "--wait", "--wait-timeout", "180", "worker", timeout=240)
    finally:
        st.env.pop("MG_PROBER_URL", None)
    wid = container(st, "worker")
    env = st.docker("inspect", "-f", "{{json .Config.Env}}", wid).stdout
    wired = f'"MG_PROBER_URL={url}"' in env and f'"MG_PROVISION_EDGE_ADDR={st.edge_ip}:443"' in env
    ok &= wired
    deadline = time.time() + 150
    while time.time() < deadline:
        regions = {s: _region(st, s) for s in TENANTS}
        if all(x.get("probe_at") for x in regions.values()):
            break
        time.sleep(5)
    a, b = (regions["tenant-a"].get("probe") or {}), (regions["tenant-b"].get("probe") or {})
    jobs = psql(st, "SELECT count(*) FROM provisioning_jobs WHERE kind = 'relay.probe' AND status = 'succeeded' "
                    f"AND created_at > '{t0}'::timestamptz")[0][0]
    scheduled = (a.get("status") == "healthy" and b.get("status") == "unhealthy" and b.get("reason") == "stun_probe_failed"
                 and int(jobs) >= 2)
    ok &= scheduled
    rows.append(f"worker recreated, env wired {wired}; schedule: A {a.get('status')}, B {b.get('status')}/{b.get('reason')}, "
                f"{jobs} relay.probe job(s) succeeded")

    def call(kind: str, req: dict, via: str = url) -> tuple[int, dict]:
        p = st.docker("run", "--rm", "-i", "--name", st.name(f"probe-wk-{secrets.token_hex(3)}"), "--network", f"container:{wid}",
                      "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--user", "65532:65532",
                      st.images["probe"], "call", "--url", via, kind, input=json.dumps(req), check=False, timeout=120)
        try:
            return p.returncode, json.loads(p.stdout)
        except ValueError:
            return p.returncode, {}
    host = f"tenant-a.{st.mesh}"
    rc18, d18 = call("edge", {"address": f"{st.edge_ip}:443", "host": host})
    rc17, d17 = call("relay", {"address": f"{st.edge_ip}:443", "host": host, "stun": f"{st.edge_ip}:3478"})
    steps = rc18 == 0 and d18.get("ok") is True and d18.get("blocked") == 22 and rc17 == 0 and d17.get("ok") is True
    ok &= steps
    rcn, dn = call("stun", {"target": f"{st.edge_ip}:3478"}, via=f"http://{st.name('prober')}:8080")
    rows.append(f"from the worker's network namespace: step 18 edge exit {rc18} ok {d18.get('ok')} blocked "
                f"{d18.get('blocked')}/22, step 17 relay exit {rc17} ok {d17.get('ok')}; by container name (informational): "
                f"exit {rcn} {((dn.get('error') or {}).get('code')) or ('ok' if dn.get('ok') else '?')}")
    r.add("E2E-77", "P3-T16 MG_PROBER_URL = địa chỉ tĩnh của prober trên network admin (render_app chỉ nhận giá trị này): "
          "worker render lại + recreate ⇒ relay.probe chạy theo lịch qua prober (A healthy, B unhealthy/stun), RPC bước 18 "
          "(edge, 22/22 path cấm 404) và bước 17 (relay) từ đúng network namespace của worker được chấp nhận",
          ok, "; ".join(rows), limit=1000)


# ---------------------------------------------------------------------------------------------------- E2E-78
def check_drills(r, st: Stack) -> None:
    mon = st.work / "render" / "obs" / "monitoring"
    started = json.loads((st.work / "state" / "obs.json").read_text(encoding="utf-8")).get("started", 0) \
        if (st.work / "state" / "obs.json").exists() else 0
    inst = psql(st, "SELECT ti.id::text, ti.tenant_id::text FROM tenant_instances ti JOIN tenants t ON t.id = ti.tenant_id "
                    "WHERE t.slug = 'tenant-a' AND ti.status = 'running' LIMIT 1")
    a_inst, a_ten = (inst[0][0], inst[0][1]) if inst else ("", "")
    t0 = time.time()
    log("E2E-78: dừng hs-tenant-b và api, tenant-a không backup 3 giờ, ghi mọi file diễn tập")
    st.docker("stop", "-t", "5", st.name("hs-tenant-b"), check=False)
    st.compose("stop", "-t", "10", "api", check=False, timeout=120)
    if a_inst:
        psql(st, f"UPDATE tenant_instances SET created_at = now() - interval '3 hours' WHERE id = '{a_inst}' RETURNING id")
    render_monitoring.run_drill(list(render_monitoring.DRILLS), mon, 12)
    t_drill = t0 - DRILL_SINCE_SLACK
    real = [("TenantInstanceDown", {"slug": "tenant-b", "job": "headscale"}, t_drill),
            ("TenantControlProbeFailed", {"slug": "tenant-b", "via": "edge"}, t_drill),
            ("PlatformTargetDown", {"job": "api"}, t_drill),
            ("TenantBackupOverdue", {"job": "worker", "instance_id": a_inst, "tenant_id": a_ten}, t_drill),
            ("CertificateExpiringSoon", {"job": "probe-key-edge", "instance": "tenant-a"}, started),
            ("CertificateExpiringSoon", {"job": "probe-tls", "instance": f"app.{st.domain}"}, started),
            ("PlatformBackupOverdue", {"job": "node", "target": "postgres"}, started),
            ("PlatformBackupStatusMissing", {"target": "idp"}, started)]
    drills = [(name, {"drill": "1"}, t_drill) for names in render_monitoring.DRILL_ALERTS.values() for name in names]
    want = real + drills
    # PlatformBackupStatusMissing needs 10 min of absence after mg-obs started
    deadline = max(time.time() + 330, started + 11 * 60 + 30)
    missing = want
    while time.time() < deadline:
        notes = notifications(st)
        missing = [w for w in want if not received(notes, w[0], w[1], since=w[2])]
        if not missing:
            break
        time.sleep(10)
    fired = time.time() - t0
    log(f"E2E-78: {len(want) - len(missing)}/{len(want)} cảnh báo tới alertsink sau {fired:.0f} s — khôi phục")
    st.docker("start", st.name("hs-tenant-b"), check=False)
    st.compose("up", "-d", "--wait", "--wait-timeout", "180", "api", check=False, timeout=240)
    render_monitoring.clear_drills(mon)
    t1 = time.time()
    resolved = False
    while time.time() < t1 + 150:
        notes = notifications(st)
        if received(notes, "TenantInstanceDown", {"slug": "tenant-b"}, status="resolved", since=t0) and \
                received(notes, "PlatformTargetDown", {"job": "api"}, status="resolved", since=t0):
            resolved = True
            break
        time.sleep(10)
    notes = notifications(st)
    real_login = received(notes, "IdPConsoleLogin", {"job": "worker"}, since=started)
    rule_names = sorted({w[0] for w in want})
    total_alerts = sum(len(n.get("alerts", [])) for n in notes)
    ok = not missing and resolved and len(rule_names) == 16 and bool(a_inst)
    r.add("E2E-78", "P3-T16 diễn tập: mỗi rule (16) bắn và thông báo tới alertsink — nguồn thật: Headscale tenant-b dừng "
          "(TenantInstanceDown, TenantControlProbeFailed rồi resolved), api dừng (PlatformTargetDown rồi resolved), instance "
          "A 3 giờ không backup (TenantBackupOverdue từ gauge của worker), chứng chỉ 1 ngày của lượt chạy, status.prom "
          "PostgreSQL quá hạn + IdP thiếu; các rule còn lại bằng file diễn tập của render_monitoring (drill=1; HostRebooted "
          "diễn tập không nén cảnh báo thật)", ok,
          f"{len(want) - len(missing)}/{len(want)} expected alerts received ({len(rule_names)} rules) in {fired:.0f} s; "
          f"missing {[(m[0], m[1]) for m in missing]}; resolved tenant-b + api {resolved}; IdPConsoleLogin from the real "
          f"console login of E2E-43 {real_login}; sink: {len(notes)} notification(s), {total_alerts} alert(s)", limit=1200)


def run_all(r, st: Stack, guarded) -> None:
    """E2E-76 … E2E-78 in order (E2E-78 stops tenant-b and api, then restores them)."""
    if not (st.work / "state" / "obs.json").exists():
        return
    _sync_addresses(st)
    guarded(r, "E2E-76", check_stack, st)
    guarded(r, "E2E-77", check_prober_url, st)
    guarded(r, "E2E-78", check_drills, st)
