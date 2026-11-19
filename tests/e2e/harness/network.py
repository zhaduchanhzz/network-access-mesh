"""P4-T12 network on the dev/CI stack — FUNCTIONAL only (§22.1): the api and worker built from the tree, a real
Keycloak login with TOTP through the edge, the real Headscale of tenant-a and real tailscale clients (a1, a2, b1).

  E2E-102 routes (PL-10 double opt-in, T-08): a1 advertises 10.77.0.0/24 and 10.78.0.0/24 (`tailscale set
          --advertise-routes`), a policy grants the members those prefixes; after POST /devices/sync, GET /routes shows
          them pending (with the untagged-router warning) and a2's netmap holds NO route of a1 — advertised but not
          approved is not usable; approve without If-Match ⇒ 428, without confirmation of the exit node ⇒ 422, a prefix
          not advertised ⇒ 422; approve 10.77.0.0/24 ⇒ 200, Headscale's approved set read back = the new set, the
          register's routes_etag = the response's, a2's netmap now holds 10.77.0.0/24 as a primary route of a1; two
          concurrent approvals (10.78.0.0/24, one with a stale ETag each time) ⇒ exactly one 200 and one 412, no prefix
          lost (Headscale holds both); revoke ⇒ the route leaves a2's netmap; audit route.approve / route.revoke paired;
          one route.approved / route.revoked per applied change for the Owners/Admins, none for a refusal (follow-up).
  E2E-103 DNS records (T-09, HS-FC-21/OPS-17): GET /dns (MagicDNS, base domain); a record outside the tailnet ⇒ 422
          field value; a record e2e-db.<base domain> → a2's address ⇒ 201 + job dns.records_write (the stack has no
          Host Agent: the job stays queued — like instance.reconfigure in E2E-63 — and the harness writes the same file
          the agent's driver writes, tmp + rename in the records/ directory the container mounts read-only); a1 resolves
          the name (Headscale reloaded the file, no restart: same container start time), b1 does not (IT-07 slice);
          DELETE without If-Match ⇒ 428, with the record's etag ⇒ 202; the file back to "[]" ⇒ the name stops resolving
          on a1; PUT /dns/settings without If-Match ⇒ 428, with the etag on the adopted instance (no configuration
          version recorded by the orchestrator) ⇒ 409; audit dns.record.create / dns.record.delete.
  E2E-104 Network Resource Catalog: POST (Idempotency-Key — the same key ⇒ the same resource; a tag outside the catalog
          ⇒ 422) ⇒ 201 and a policy.apply job with trigger resource_change that succeeds on the worker; PATCH without
          If-Match ⇒ 428, with ⇒ 200 and a new etag; DELETE with the old etag ⇒ 412, with the current ⇒ 204; audit
          resource.create / update / delete.

Standard library only. Passwords, TOTP keys, cookies and CSRF tokens stay in this process (and its redaction set).
"""
from __future__ import annotations

import json
import secrets
import threading
import time

import checks
from backend import psql
from dualcontrol import psql_one, tenant_id
from lifecycle import admin_session
from phase3 import policy_apply
from stack import ROOT, Stack, log

SLUG = "tenant-a"
P1, P2, P3 = "10.77.0.0/24", "10.78.0.0/24", "10.79.0.0/24"


def _h(st: Stack, sess: dict, idem: str | None = None, if_match: str | None = None) -> dict:
    h = {"Origin": f"https://app.{st.domain}", "X-CSRF-Token": sess["csrf_token"], "Content-Type": "application/json"}
    if idem:
        h["Idempotency-Key"] = idem
    if if_match:
        h["If-Match"] = if_match
    return h


def _key() -> str:
    return "e2e-net-" + secrets.token_hex(8)


def _job_status(st: Stack, job: str, timeout: float = 120) -> str:
    end, status = time.time() + timeout, ""
    while time.time() < end:
        status = psql_one(st, f"SELECT status FROM provisioning_jobs WHERE id = '{job}'")
        if status in ("succeeded", "failed", "cancelled", "rolled_back"):
            return status
        time.sleep(1)
    return status or "none"


def _report(r, case: str, title: str, rows: list, conds: list) -> None:
    failed = [n for n, good in conds if not good]
    for row in rows:
        log(f"  {case} {row}")
    r.add(case, title, not failed, (f"FAILED: {', '.join(failed)} — " if failed else "") + "; ".join(rows), limit=2500)


def _node(st: Stack, part: str) -> dict:
    for n in json.loads(st.headscale(SLUG, "nodes", "list", "-o", "json").stdout or "[]") or []:
        if part in (n.get("given_name") or n.get("name") or ""):
            return n
    return {}


def _peer_routes(st: Stack, viewer: str, peer_ip: str) -> list:
    for p in checks.peers(checks.status(st, viewer)):
        if peer_ip in (p.get("TailscaleIPs") or []):
            return sorted(p.get("PrimaryRoutes") or [])
    return []


def _device(b, api: str, part: str) -> dict:
    devs = b.get(f"{api}/devices?limit=50").json().get("items", [])
    return next((d for d in devs if part in (d.get("given_name") or d.get("name") or "")), {})


def _route(b, api: str, device_id: str) -> dict:
    items = b.get(f"{api}/routes").json().get("items", [])
    return next((d for d in items if d.get("device_id") == device_id), {})


def _sync(st: Stack, b, sess: dict, api: str) -> str:
    res = b.request("POST", f"{api}/devices/sync", None, _h(st, sess, _key()))
    return _job_status(st, res.json().get("id", "")) if res.status == 202 else f"HTTP {res.status}"


# ---------------------------------------------------------------------------------------------------- E2E-102
def check_routes(r, st: Stack) -> None:
    a_id = tenant_id(st, SLUG)
    api = f"https://app.{st.domain}/api/v1/tenants/{a_id}"
    rows, conds = [], []

    def cond(name: str, good: bool, row: str) -> None:
        conds.append((name, good))
        rows.append(f"[{'ok' if good else 'FAIL'} {name}] {st.redact(row)}")

    base = (ROOT / "infrastructure" / "headscale" / "templates" / "bootstrap-policy.hujson").read_text(encoding="utf-8")
    grant = {"grants": [
        {"src": ["autogroup:member", "autogroup:tagged"], "dst": ["autogroup:member", "autogroup:tagged"], "ip": ["tcp:8000"]},
        {"src": ["autogroup:member"], "dst": [P1, P2, P3], "ip": ["tcp:8000"]}], "ssh": []}
    code, out, _ = policy_apply(st, json.dumps(grant))
    stat = checks.wait_running(st, ["a1", "a2"])
    a1_ip, a2_ip = checks.ip4(stat["a1"]["Self"]), checks.ip4(stat["a2"]["Self"])
    adv = checks.ts(st, "a1", "set", f"--advertise-routes={P1},{P2}")
    cond("setup", code == 0 and adv.returncode == 0, f"policy granting the prefixes: exit {code} {out.get('state')}; "
         f"a1 advertises {P1},{P2}: exit {adv.returncode}")
    b, sess = admin_session(st)
    dev = _device(b, api, "a1")
    routes = checks.wait(lambda: (lambda d: d if P1 in (d.get("pending_routes") or []) else None)(
        (_sync(st, b, sess, api), _route(b, api, dev.get("id", "")))[1]), 60, 3) or {}
    warn = sorted({w.get("code") for w in routes.get("warnings") or []})
    unapproved = _peer_routes(st, "a2", a1_ip)
    cond("pending", P1 in (routes.get("pending_routes") or []) and not routes.get("approved_routes")
         and "untagged_router" in warn and P1 not in unapproved,
         f"GET routes a1 pending {routes.get('pending_routes')} approved {routes.get('approved_routes')} warnings {warn}; "
         f"a2 sees routes of a1: {unapproved} (advertised, not approved ⇒ none)")

    etag = routes.get("routes_etag", "")
    body = lambda *p, **kw: json.dumps({"device_id": dev.get("id"), "prefixes": list(p), **kw}).encode()  # noqa: E731
    no_match = b.request("POST", f"{api}/routes/approve", body(P1), _h(st, sess, _key()))
    exit_nc = b.request("POST", f"{api}/routes/approve", body("0.0.0.0/0"), _h(st, sess, _key(), etag))
    not_adv = b.request("POST", f"{api}/routes/approve", body(P3), _h(st, sess, _key(), etag))
    cond("refusals", no_match.status == 428 and exit_nc.status == 422 and not_adv.status == 422,
         f"without If-Match {no_match.status}; exit node without confirmation {exit_nc.status}; not advertised {not_adv.status}")

    ok = b.request("POST", f"{api}/routes/approve", body(P1), _h(st, sess, _key(), etag))
    okj = ok.json() if ok.status == 200 else {}
    hs = sorted(_node(st, "a1").get("approved_routes") or [])
    reg = _route(b, api, dev.get("id", ""))
    seen = checks.wait(lambda: P1 in _peer_routes(st, "a2", a1_ip), 60, 2)
    cond("approve", ok.status == 200 and hs == [P1] and okj.get("approved_routes") == [P1]
         and ok.header("ETag") == okj.get("routes_etag") == reg.get("routes_etag") and okj.get("routes_etag") != etag and bool(seen),
         f"approve {ok.status}; Headscale approved {hs}; ETag {ok.header('ETag') == okj.get('routes_etag')} register "
         f"{reg.get('routes_etag') == okj.get('routes_etag')}; a2 sees {P1} via a1: {bool(seen)}")

    # two concurrent approvals on the same ETag: one wins, the other gets 412 — no prefix lost
    etag2, res = okj.get("routes_etag", ""), {}

    def go(name: str, prefix: str) -> None:
        res[name] = b.request("POST", f"{api}/routes/approve", body(prefix), _h(st, sess, _key(), etag2)).status

    ths = [threading.Thread(target=go, args=("x", P2)), threading.Thread(target=go, args=("y", P2))]
    for th in ths:
        th.start()
    for th in ths:
        th.join()
    hs2 = sorted(_node(st, "a1").get("approved_routes") or [])
    cond("concurrent", sorted(res.values()) == [200, 412] and hs2 == sorted([P1, P2]),
         f"two approvals on one ETag: {sorted(res.values())}; Headscale approved {hs2}")

    cur = _route(b, api, dev.get("id", ""))
    rv = b.request("POST", f"{api}/routes/revoke", body(P1, P2), _h(st, sess, None, cur.get("routes_etag")))
    gone = checks.wait(lambda: not _peer_routes(st, "a2", a1_ip), 60, 2)
    cond("revoke", rv.status == 200 and not (_node(st, "a1").get("approved_routes") or []) and bool(gone),
         f"revoke {rv.status}; Headscale approved {_node(st, 'a1').get('approved_routes')}; a2 sees no route of a1: {bool(gone)}")
    audit = psql_one(st, "SELECT string_agg(action, ',' ORDER BY occurred_at, id) FROM audit_events WHERE "
                     f"tenant_id = '{a_id}' AND resource_id = '{dev.get('id')}' AND action LIKE 'route.%'")
    cond("audit", "route.approve.requested" in audit and "route.approve.succeeded" in audit and "route.approve.failed" in audit
         and "route.revoke.succeeded" in audit, f"audit {audit}")
    # T-08 "audit + thông báo" (follow-up P4-T12): one notification per APPLIED change — approve P1, the winner of the
    # concurrent pair (P2), the revoke of both — for the Tenant Owners/Admins; the refusals and the 412 notify nothing
    notes = psql_one(st, "SELECT string_agg(kind || ' ' || (payload->>'prefixes'), '; ' ORDER BY kind, payload->>'prefixes') "
                     "FROM (SELECT DISTINCT kind, payload FROM notification_outbox WHERE "
                     f"tenant_id = '{a_id}' AND kind LIKE 'route.%' AND payload->>'device_id' = '{dev.get('id')}') x")
    dups = psql_one(st, "SELECT count(*) FROM (SELECT 1 FROM notification_outbox WHERE "
                    f"tenant_id = '{a_id}' AND kind LIKE 'route.%' GROUP BY recipient_membership_id, kind, payload->>'ref' "
                    "HAVING count(*) > 1) x")
    want_notes = f"route.approved {P1}; route.approved {P2}; route.revoked {', '.join(sorted([P1, P2]))}"
    cond("notified", notes == want_notes and dups == "0", f"route notifications: {notes}; duplicated per recipient: {dups}")
    checks.ts(st, "a1", "set", "--advertise-routes=")
    code, _, _ = policy_apply(st, base, "--trigger", "bootstrap")
    rows.append(f"cleanup: a1 advertises nothing, baseline again exit {code}")
    _report(r, "E2E-102", "P4-T12 routes: quảng bá chưa duyệt không vào netmap của peer; duyệt đọc–sửa–ghi có kiểm (428/422/412), "
            "đọc lại Headscale khớp, peer thấy route; hai lần duyệt đồng thời ⇒ 200 + 412, không mất prefix; gỡ duyệt", rows, conds)


# ---------------------------------------------------------------------------------------------------- E2E-103
def _records_dir(st: Stack) -> str:
    mounts = json.loads(st.docker("inspect", st.name(f"hs-{SLUG}"), "--format", "{{json .Mounts}}").stdout or "[]")
    return next((m.get("Source", "") for m in mounts if m.get("Destination") == "/etc/headscale-records"), "")


def _write_records(st: Stack, items: list) -> None:
    """The file the Host Agent's driver writes (compose.RenderRecords): sorted, Headscale's keys, "[]" when empty —
    tmp + rename in the mounted directory."""
    recs = sorted(({"name": i["name"], "type": i["type"], "value": i["value"]} for i in items),
                  key=lambda x: (x["name"], x["type"], x["value"]))
    content = (json.dumps(recs, indent=2) + "\n") if recs else "[]\n"
    st.docker("run", "--rm", "-i", "--network", "none", "-v", f"{_records_dir(st)}:/r", st.images["alpine"], "sh", "-ec",
              "cat > /r/.extra-records.json.tmp-e2e && chmod 0644 /r/.extra-records.json.tmp-e2e && "
              "mv /r/.extra-records.json.tmp-e2e /r/extra-records.json", input=content)


def _resolves(st: Stack, c: str, name: str, ip: str) -> bool:
    p = checks.ts(st, c, "dns", "query", name, "A", timeout=30)
    return ip in (p.stdout or "")


def check_dns(r, st: Stack) -> None:
    a_id = tenant_id(st, SLUG)
    api = f"https://app.{st.domain}/api/v1/tenants/{a_id}"
    rows, conds = [], []

    def cond(name: str, good: bool, row: str) -> None:
        conds.append((name, good))
        rows.append(f"[{'ok' if good else 'FAIL'} {name}] {st.redact(row)}")

    b, sess = admin_session(st)
    view = b.get(f"{api}/dns")
    v = view.json() if view.status == 200 else {}
    stat = checks.wait_running(st, ["a1", "a2", "b1"])
    a2_ip = checks.ip4(stat["a2"]["Self"])
    name = "e2e-db." + v.get("base_domain", "")
    cond("view", view.status == 200 and v.get("magic_dns") is True and v.get("base_domain", "").startswith(SLUG + ".")
         and view.header("ETag") == v.get("etag"), f"GET dns {view.status} magic_dns {v.get('magic_dns')} base {v.get('base_domain')}")
    outside = b.request("POST", f"{api}/dns/records", json.dumps({"name": name, "type": "A", "value": "192.0.2.10"}).encode(),
                        _h(st, sess, _key()))
    fields = [e.get("field") for e in (outside.json().get("errors") or [])] if outside.status == 422 else []
    started = st.docker("inspect", st.name(f"hs-{SLUG}"), "--format", "{{.State.StartedAt}}").stdout.strip()
    created = b.request("POST", f"{api}/dns/records", json.dumps({"name": name, "type": "A", "value": a2_ip}).encode(),
                        _h(st, sess, _key()))
    c = created.json() if created.status == 201 else {}
    rec, job = c.get("record") or {}, c.get("job") or {}
    cond("create", outside.status == 422 and "value" in fields and created.status == 201 and rec.get("name") == name
         and job.get("kind") == "dns.records_write",
         f"outside the tailnet {outside.status} fields {fields}; create {created.status} job {job.get('kind')} {job.get('status')}")
    _write_records(st, b.get(f"{api}/dns/records").json().get("items", []))
    ok = checks.wait(lambda: _resolves(st, "a1", name, a2_ip), 60, 2)
    again = st.docker("inspect", st.name(f"hs-{SLUG}"), "--format", "{{.State.StartedAt}}").stdout.strip()
    cond("hot_reload", bool(ok) and again == started and not _resolves(st, "b1", name, a2_ip),
         f"a1 resolves {name} → {a2_ip}: {bool(ok)}; Headscale not restarted: {again == started}; "
         f"b1 (tenant-b) does not: {not _resolves(st, 'b1', name, a2_ip)}")
    no_match = b.request("DELETE", f"{api}/dns/records/{rec.get('id')}", None, _h(st, sess))
    dele = b.request("DELETE", f"{api}/dns/records/{rec.get('id')}", None, _h(st, sess, None, rec.get("etag")))
    left = b.get(f"{api}/dns/records").json().get("items", [])
    _write_records(st, left)
    gone = checks.wait(lambda: not _resolves(st, "a1", name, a2_ip), 60, 2)
    cond("delete", no_match.status == 428 and dele.status == 202 and dele.header("Location") and not left and bool(gone),
         f"DELETE without If-Match {no_match.status}; with etag {dele.status}; records left {len(left)}; file [] ⇒ "
         f"a1 no longer resolves: {bool(gone)}")
    s_nm = b.request("PUT", f"{api}/dns/settings", json.dumps({"nameservers": ["1.1.1.1"]}).encode(), _h(st, sess))
    s_ok = b.request("PUT", f"{api}/dns/settings", json.dumps({"nameservers": ["1.1.1.1"]}).encode(),
                     _h(st, sess, None, v.get("etag")))
    cond("settings", s_nm.status == 428 and s_ok.status == 409,
         f"PUT dns/settings without If-Match {s_nm.status}; with etag on the adopted instance {s_ok.status} "
         f"({(s_ok.json() or {}).get('detail', '')[:80]})")
    audit = psql_one(st, "SELECT string_agg(action, ',' ORDER BY occurred_at, id) FROM audit_events WHERE "
                     f"tenant_id = '{a_id}' AND resource_id = '{rec.get('id')}' AND outcome = 'success'")
    cond("audit", audit == "dns.record.create,dns.record.delete", f"audit {audit}")
    queued = psql(st, "SELECT status FROM provisioning_jobs WHERE kind = 'dns.records_write' AND "
                      f"tenant_id = '{a_id}' ORDER BY created_at")
    rows.append(f"dns.records_write jobs (no Host Agent in the stack): {[q[0] for q in queued]}")
    _report(r, "E2E-103", "P4-T12 DNS: lint T-09 (422), bản ghi mới phân giải được từ client sau ghi tmp + rename (không restart), "
            "tenant khác không phân giải; xóa (If-Match) ⇒ file [] ⇒ hết phân giải; PUT dns/settings 428/409", rows, conds)


# ---------------------------------------------------------------------------------------------------- E2E-104
def check_resources(r, st: Stack) -> None:
    a_id = tenant_id(st, SLUG)
    api = f"https://app.{st.domain}/api/v1/tenants/{a_id}"
    rows, conds = [], []

    def cond(name: str, good: bool, row: str) -> None:
        conds.append((name, good))
        rows.append(f"[{'ok' if good else 'FAIL'} {name}] {st.redact(row)}")

    b, sess = admin_session(st)
    key = _key()
    body = json.dumps({"name": "e2e-db", "kind": "service", "address": "10.77.0.5", "ports": ["5432"], "protocol": "tcp"}).encode()
    first = b.request("POST", f"{api}/resources", body, _h(st, sess, key))
    res = first.json() if first.status == 201 else {}
    replay = b.request("POST", f"{api}/resources", body, _h(st, sess, key))
    bad_tag = b.request("POST", f"{api}/resources", json.dumps({"name": "e2e-x", "kind": "host", "address": "10.77.0.6",
                                                                  "tags": ["tag:e2e-undeclared"]}).encode(), _h(st, sess, _key()))
    job = psql(st, "SELECT id, input->>'trigger' FROM provisioning_jobs WHERE kind = 'policy.apply' AND "
                   f"tenant_id = '{a_id}' ORDER BY created_at DESC LIMIT 1")
    status = _job_status(st, job[0][0]) if job else "none"
    cond("create", first.status == 201 and res.get("etag") == '"1"' and replay.status == 201
         and replay.json().get("id") == res.get("id") and bad_tag.status == 422 and job and job[0][1] == "resource_change"
         and status == "succeeded",
         f"POST {first.status} etag {res.get('etag')}; replay same={replay.json().get('id') == res.get('id')}; undeclared tag "
         f"{bad_tag.status}; policy.apply trigger {job[0][1] if job else '-'} {status}")
    rid = res.get("id")
    nm = b.request("PATCH", f"{api}/resources/{rid}", json.dumps({"description": "e2e"}).encode(), _h(st, sess))
    up = b.request("PATCH", f"{api}/resources/{rid}", json.dumps({"description": "e2e"}).encode(), _h(st, sess, None, res.get("etag")))
    new = up.header("ETag") or ""
    stale = b.request("DELETE", f"{api}/resources/{rid}", None, _h(st, sess, None, res.get("etag")))
    gone = b.request("DELETE", f"{api}/resources/{rid}", None, _h(st, sess, None, new))
    cond("change", nm.status == 428 and up.status == 200 and new == '"2"' and stale.status == 412 and gone.status == 204,
         f"PATCH without If-Match {nm.status}; with {up.status} etag {new}; DELETE old etag {stale.status}; current {gone.status}")
    audit = psql_one(st, "SELECT string_agg(action, ',' ORDER BY occurred_at, id) FROM audit_events WHERE "
                     f"tenant_id = '{a_id}' AND resource_id = '{rid}' AND action LIKE 'resource.%' AND outcome = 'success'")
    cond("audit", audit == "resource.create,resource.update,resource.delete",
         f"audit {audit}")
    _report(r, "E2E-104", "P4-T12 Network Resource Catalog: tạo (Idempotency-Key, tag ngoài danh mục 422) ⇒ policy.apply "
            "resource_change chạy xong; PATCH/DELETE If-Match 428/412; audit", rows, conds)


def run_all(r, st: Stack, guarded) -> None:
    guarded(r, "E2E-102", check_routes, st)
    guarded(r, "E2E-103", check_dns, st)
    guarded(r, "E2E-104", check_resources, st)
