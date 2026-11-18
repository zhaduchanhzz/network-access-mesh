"""Relay read model and relay probe (P3-T05c) on the dev/CI stack — FUNCTIONAL only (§22.1). The stack's tenants A and
B are ADOPTED (E2E-21, `admin adopt-instance`), not provisioned: they have no relay_regions / relay_assignments row
(step 17 relay.assign of the orchestrator is the only writer — the stack has no Host Agent, so no tenant is provisioned
here). E2E-65 checks that, then writes the rows step 17 would write as database fixtures (superuser — the same shape as
orchestrator.DBStore.AssignRelay: embedded region mg-<slug>, DERP 901, hostname = the instance's control hostname, the
public entry = the edge's address, STUN 3478, verify in_process, active; the instance's assignment).

  E2E-65  GET /tenants/{A}/relay (Tenant Owner of A, app.) before the fixtures ⇒ 200, no assignment, the 5 figures of
          §10.6 listed unavailable with a reason; after them ⇒ exactly A's relay (mg-tenant-a, its hostname, DERP 901,
          STUN 3478), health unknown/never_checked with checked_at null — nothing of B; a tenant in the query or a header
          is ignored; B's relay on A's session ⇒ 404; GET /platform/relay-regions on app. ⇒ refused; the Super Admin
          (admin.) lists both regions, each with its tenant and assignment
  E2E-66  `meshguard-worker admin relay-probe --tenant tenant-a` in the running worker with the stack's prober
          (MG_PROBER_URL + MG_PROVISION_EDGE_ADDR, the prober-only configuration — the worker of the stack has no
          prober configured): the real prober (apps/probe) probes GET /derp/probe of tenant-a through the real Caddyfile
          (Headscale's embedded DERP) and STUN of the stack's stund ⇒ recorded healthy, checked_at = last_probe_at of the
          database; then GET /tenants/{A}/relay shows that verdict, time and checks; tenant-b's region pointed at a closed
          STUN port (3479) ⇒ recorded unhealthy/stun_probe_failed with the prober's code; the platform list shows both
          verdicts; the command output names no address; B's probe never wrote A's row and vice versa
Standard library only; no credential printed.
"""
from __future__ import annotations

import calendar
import json
from datetime import datetime

from backend import container, psql
from stack import Stack

SLUGS = ("tenant-a", "tenant-b")
UNMEASURED = {"traffic_bytes", "throughput", "connections", "auth_failures", "client_latency"}


def _one(st: Stack, sql: str) -> str:
    rows = psql(st, sql)
    return rows[0][0] if rows and rows[0] else ""


def _relay_rows(st: Stack) -> str:
    return _one(st, "SELECT (SELECT count(*) FROM relay_regions r JOIN tenants t ON t.id = r.tenant_id WHERE t.slug IN "
                    "('tenant-a', 'tenant-b')) || '/' || (SELECT count(*) FROM relay_assignments a JOIN tenants t ON "
                    "t.id = a.tenant_id WHERE t.slug IN ('tenant-a', 'tenant-b'))")


def _seed(st: Stack) -> None:
    """The rows of step 17 for the adopted tenants (idempotent: a rerun of `test` keeps them)."""
    psql(st, "INSERT INTO relay_regions (tenant_id, code, name, kind, derp_region_id, hostname, ipv4, stun_port, derp_port, "
             "verify_mode, host_id, status) SELECT i.tenant_id, 'mg-' || t.slug, 'MeshGuard ' || t.slug, 'embedded', 901, "
             f"i.control_hostname, '{st.edge_ip}', 3478, 443, 'in_process', i.host_id, 'active' FROM tenant_instances i "
             "JOIN tenants t ON t.id = i.tenant_id WHERE t.slug IN ('tenant-a', 'tenant-b') AND i.status <> 'removed' "
             "ON CONFLICT (tenant_id, code) DO NOTHING")
    psql(st, "INSERT INTO relay_assignments (tenant_id, instance_id, relay_region_id, priority, status) SELECT r.tenant_id, "
             "i.id, r.id, 0, 'active' FROM relay_regions r JOIN tenant_instances i ON i.tenant_id = r.tenant_id AND "
             "i.status <> 'removed' WHERE r.code IN ('mg-tenant-a', 'mg-tenant-b') "
             "ON CONFLICT (instance_id, relay_region_id) DO NOTHING")


def _region(st: Stack, slug: str) -> dict:
    row = psql(st, "SELECT r.id, r.hostname, coalesce(r.last_probe_at::text, ''), coalesce(r.last_probe::text, '') "
                   f"FROM relay_regions r JOIN tenants t ON t.id = r.tenant_id WHERE t.slug = '{slug}' AND r.code = 'mg-{slug}'")
    if not row:
        return {}
    rid, host, at, doc = row[0][:4]
    return {"id": rid, "host": host, "probe_at": at, "probe": json.loads(doc) if doc else None}


def _micros(api_value: str | None) -> int | None:
    """An RFC 3339 time of the API (UTC, at most microseconds — the database's precision) in µs since the epoch."""
    if not api_value:
        return None
    t = datetime.fromisoformat(api_value.replace("Z", "+00:00"))
    return calendar.timegm(t.utctimetuple()) * 1_000_000 + t.microsecond


def _db_micros(st: Stack, region_id: str) -> int | None:
    v = _one(st, f"SELECT (extract(epoch FROM last_probe_at) * 1000000)::bigint FROM relay_regions WHERE id = '{region_id}'")
    return int(v) if v else None


def check_relay_read(r, st: Stack, state: dict) -> None:
    b = state["browser"]
    ids = state["tenant_ids"]
    a_id, b_id = ids["tenant-a"], ids["tenant-b"]
    app = f"https://app.{st.domain}/api/v1"
    before_rows = _relay_rows(st)
    before = b.get(f"{app}/tenants/{a_id}/relay")
    bdoc = before.json()
    _seed(st)
    after_rows = _relay_rows(st)
    ra, rb = _region(st, "tenant-a"), _region(st, "tenant-b")
    got = b.get(f"{app}/tenants/{a_id}/relay")
    doc = got.json()
    inj = b.get(f"{app}/tenants/{a_id}/relay?tenant_id={b_id}&tenantId={b_id}&tenant=tenant-b",
                {"X-Tenant-Id": b_id, "X-MG-Tenant": b_id})
    cross = b.get(f"{app}/tenants/{b_id}/relay")
    plat_app = b.get(f"{app}/platform/relay-regions")
    sa_b = state["sa"]["browser"]
    plat = sa_b.get(f"https://admin.{st.domain}/api/v1/platform/relay-regions?limit=200")
    items = {it.get("region", {}).get("id"): it for it in plat.json().get("items", [])}
    asg = (doc.get("assignments") or [{}])[0]
    reg, health = asg.get("region", {}), asg.get("health", {})
    body = got.body.decode("utf-8", "replace")
    leak = [x for x in (b_id, rb.get("id", "?"), rb.get("host", "?"), "tenant-b") if x and x in body]
    ok = (before.status == 200 and bdoc.get("assignments") == []
          and {u.get("metric") for u in bdoc.get("unavailable", [])} == UNMEASURED
          and all(u.get("reason") in ("unsupported", "no_source") for u in bdoc.get("unavailable", []))
          and after_rows == "2/2" and got.status == 200 and len(doc.get("assignments", [])) == 1
          and reg.get("id") == ra.get("id") and reg.get("code") == "mg-tenant-a" and reg.get("hostname") == ra.get("host")
          and reg.get("derp_region_id") == 901 and reg.get("stun_port") == 3478 and reg.get("kind") == "embedded"
          and health.get("status") == "unknown" and health.get("reason") == "never_checked" and health.get("checked_at") is None
          and not leak and inj.status == 200 and inj.json() == doc and cross.status == 404
          and plat_app.status == 403 and plat.status == 200
          and items.get(ra.get("id"), {}).get("tenant_id") == a_id and items.get(rb.get("id"), {}).get("tenant_id") == b_id
          and len(items.get(ra.get("id"), {}).get("assignments", [])) == 1)
    r.add("E2E-65", "P3-T05c: tenant A/B adopt chưa có hàng relay (0/0) ⇒ GET /tenants/{A}/relay 200, rỗng + 5 số đo "
          "§10.6 'không khả dụng'; sau fixture DB như bước 17 ⇒ đúng relay của A (mg-tenant-a, DERP 901, STUN 3478), "
          "unknown/never_checked, checked_at null, không có gì của B; tham số/header tenant bị bỏ qua; relay của B ⇒ 404; "
          "/platform/relay-regions trên app. ⇒ 403; Super Admin thấy cả hai region", ok,
          f"rows before {before_rows} after {after_rows}; before {before.status} {len(bdoc.get('assignments', []) or [])} "
          f"assignment(s), unavailable {sorted(u.get('metric') for u in bdoc.get('unavailable', []))}; A {got.status} "
          f"{reg.get('code')} {reg.get('hostname')} {health.get('status')}/{health.get('reason')} checked_at "
          f"{health.get('checked_at')}; leak {leak}; injected same={inj.json() == doc}; B {cross.status}; platform on app "
          f"{plat_app.status}; SA {plat.status} {len(items)} region(s)")
    state["relay"] = {"a": ra, "b": rb}


def relay_probe(st: Stack, slug: str):
    """`meshguard admin relay-probe` in the running worker, with the stack's prober (the prober-only configuration)."""
    p = st.docker("exec", "-e", f"MG_PROBER_URL=http://{st.name('prober')}:8080", "-e",
                  f"MG_PROVISION_EDGE_ADDR={st.edge_ip}:443", container(st, "worker"), "/usr/local/bin/meshguard", "admin",
                  "relay-probe", "--tenant", slug, check=False, timeout=180)
    lines = [json.loads(ln) for ln in p.stdout.splitlines() if ln.startswith("{")]
    return p, lines


def check_relay_probe(r, st: Stack, state: dict) -> None:
    b = state["browser"]
    a_id = state["tenant_ids"]["tenant-a"]
    app = f"https://app.{st.domain}/api/v1"
    pa, la = relay_probe(st, "tenant-a")
    ra = _region(st, "tenant-a")
    rb0 = _region(st, "tenant-b")
    got = b.get(f"{app}/tenants/{a_id}/relay")
    asg = (got.json().get("assignments") or [{}])[0]
    health = asg.get("health", {})
    psql(st, "UPDATE relay_regions SET stun_port = 3479 WHERE code = 'mg-tenant-b'")   # a closed port of the entry
    pb, lb = relay_probe(st, "tenant-b")
    rb = _region(st, "tenant-b")
    ra2 = _region(st, "tenant-a")
    plat = state["sa"]["browser"].get(f"https://admin.{st.domain}/api/v1/platform/relay-regions?limit=200")
    items = {it.get("region", {}).get("id"): it for it in plat.json().get("items", [])}
    ha, hb = items.get(ra.get("id"), {}).get("health", {}), items.get(rb.get("id"), {}).get("health", {})
    out = pa.stdout + pb.stdout
    a_line, b_line = (la or [{}])[0], (lb or [{}])[0]
    db_at_a = _db_micros(st, ra.get("id", ""))
    same_time = db_at_a is not None and _micros(health.get("checked_at")) == db_at_a == _micros(a_line.get("checked_at"))
    ok = (pa.returncode == 0 and len(la) == 1 and a_line.get("status") == "healthy" and a_line.get("recorded") is True
          and (a_line.get("derp") or {}).get("status") == 200 and (a_line.get("stun") or {}).get("ok") is True
          and (ra.get("probe") or {}).get("status") == "healthy" and ra.get("probe_at") and rb0.get("probe_at") in ("", None)
          and got.status == 200 and health.get("status") == "healthy" and health.get("reason") is None and same_time
          and (health.get("derp") or {}).get("status") == 200 and (health.get("stun") or {}).get("ok") is True
          and pb.returncode == 3 and len(lb) == 1 and b_line.get("status") == "unhealthy"
          and b_line.get("reason") == "stun_probe_failed" and (b_line.get("stun") or {}).get("code") in ("refused", "timeout")
          and (rb.get("probe") or {}).get("reason") == "stun_probe_failed" and ra2.get("probe_at") == ra.get("probe_at")
          and plat.status == 200 and ha.get("status") == "healthy" and hb.get("status") == "unhealthy"
          and hb.get("reason") == "stun_probe_failed" and ha.get("checked_at") and hb.get("checked_at")
          and st.edge_ip not in out and "prober:8080" not in out)
    r.add("E2E-66", "P3-T05c: `meshguard-worker admin relay-probe` (prober thật của stack, cấu hình chỉ-prober) ⇒ "
          "/derp/probe của tenant-a qua Caddyfile thật (DERP nhúng của Headscale) + STUN của stund ⇒ ghi healthy, "
          "checked_at = last_probe_at; GET /tenants/{A}/relay hiển thị đúng kết luận/thời điểm/phép kiểm; region của B "
          "trỏ STUN cổng đóng 3479 ⇒ unhealthy/stun_probe_failed kèm mã của prober; danh sách platform có cả hai; output "
          "không nêu địa chỉ; probe của B không ghi hàng của A", ok,
          f"A exit {pa.returncode} {a_line.get('status')} derp {(a_line.get('derp') or {}).get('status')} stun "
          f"{(a_line.get('stun') or {}).get('ok')} recorded {a_line.get('recorded')}; db {ra.get('probe_at')}; api "
          f"{health.get('status')} at {health.get('checked_at')} (same {same_time}); B before {rb0.get('probe_at') or 'null'}; "
          f"B exit {pb.returncode} {b_line.get('status')}/{b_line.get('reason')} stun "
          f"{(b_line.get('stun') or {}).get('code')}; platform A {ha.get('status')} B {hb.get('status')}/{hb.get('reason')}")


def run_all(r, st: Stack, guarded, state: dict) -> None:
    """E2E-65, E2E-66 in order (E2E-66 probes the regions E2E-65 seeded); needs the sessions of E2E-22 and E2E-24."""
    if "browser" not in state or "sa" not in state or "tenant_ids" not in state:
        return
    if guarded(r, "E2E-65", check_relay_read, st, state) is None and state.get("relay", {}).get("a"):
        guarded(r, "E2E-66", check_relay_probe, st, state)
