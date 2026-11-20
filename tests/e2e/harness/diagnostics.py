"""P5-T08 Connectivity Diagnostics on the dev/CI stack — FUNCTIONAL only (§22.1): the api and worker built from the tree,
a real Keycloak login with TOTP through the edge, the real Headscale of tenant-a and real tailscale clients (a1, a2, b1).

  E2E-123 a Tenant Admin of tenant-a; the policy test-allow-intra (tcp:8000 + icmp inside a tenant) applied through the
          core (`admin policy-apply` — a recorded application with its read-back sha256) and the register synced (POST
          /devices/sync): GET /tenants/{a}/diagnostics/instance ⇒ 200 with checked_at, the instance health with its
          checked_at, the applied policy whose applied_sha256 = the sha256 of the policy Headscale stores, device counts
          with synced_at, the API key as a status + time only (no hskey-/secret in the body), p2p_path in `unavailable`
          (not_observable); POST …/diagnostics/connectivity a1 → a2 tcp/8000 ⇒ 200, path_observable false, verdict
          allowed (policy_grant pass, both devices online), a checklist per OS whose Linux TCP step is `nc -vz -w 5
          <a2> 8000` — and the real TCP connection a1 → a2:8000 over the tailnet answers; a1 → a2 tcp/8001 ⇒ verdict
          blocked, policy_grant fail port_not_allowed — and the real TCP connection to 8001 does not answer (the server's
          verdict agrees with the data plane on both ports, HS-25/CL-09: never `tailscale ping`); a device of tenant-b as
          the target on A's path ⇒ 404; the same device twice ⇒ 422; no CSRF token ⇒ 403. Cleanup: the deny-all baseline
          applied again through the core (the state the earlier cases leave — E2E-118 lesson: nothing of this case stays).

Standard library only. Passwords, TOTP keys, cookies and CSRF tokens stay in this process (and its redaction set).
"""
from __future__ import annotations

import json
import secrets
import time

import checks
from dualcontrol import psql_one, tenant_id
from lifecycle import admin_session
from phase3 import policy_apply, stored_sha
from stack import ROOT, Stack, log

SLUG = "tenant-a"


def _h(st: Stack, sess: dict, idem: str | None = None, csrf: bool = True) -> dict:
    h = {"Origin": f"https://app.{st.domain}", "Content-Type": "application/json"}
    if csrf:
        h["X-CSRF-Token"] = sess["csrf_token"]
    if idem:
        h["Idempotency-Key"] = idem
    return h


def _job_status(st: Stack, job: str, timeout: float = 120) -> str:
    end, status = time.time() + timeout, ""
    while time.time() < end:
        status = psql_one(st, f"SELECT status FROM provisioning_jobs WHERE id = '{job}'")
        if status in ("succeeded", "failed", "cancelled", "rolled_back"):
            return status
        time.sleep(1)
    return status or "none"


def _device(b, api: str, part: str) -> dict:
    devs = b.get(f"{api}/devices?limit=50").json().get("items", [])
    return next((d for d in devs if part in (d.get("given_name") or d.get("name") or "")), {})


def _checks(res: dict) -> dict:
    return {c.get("id"): (c.get("status"), c.get("reason")) for c in res.get("checks") or []}


def check_diagnostics(r, st: Stack) -> None:
    a_id, b_id = tenant_id(st, SLUG), tenant_id(st, "tenant-b")
    api = f"https://app.{st.domain}/api/v1/tenants/{a_id}"
    rows, conds = [], []

    def cond(name: str, good: bool, row: str) -> None:
        conds.append((name, good))
        rows.append(f"[{'ok' if good else 'FAIL'} {name}] {st.redact(row)}")

    templates = ROOT / "infrastructure" / "headscale" / "templates"
    allow = (templates / "test-allow-intra.hujson").read_text(encoding="utf-8")
    base = (templates / "bootstrap-policy.hujson").read_text(encoding="utf-8")
    before = stored_sha(st)
    try:
        code, out, _ = policy_apply(st, allow)
        stat = checks.wait_running(st, ["a1", "a2"])
        a2_ip = checks.ip4(stat["a2"]["Self"])
        checks.start_listeners(st, "a2")  # nc on 8000 (allowed) and 8001 (denied); already running ⇒ no-op
        checks.wait_peer_count(st, "a1", 1, 90)
        b, sess = admin_session(st)
        sync = b.request("POST", f"{api}/devices/sync", None, _h(st, sess, "e2e-diag-" + secrets.token_hex(6)))
        synced = _job_status(st, sync.json().get("id", "")) if sync.status == 202 else f"HTTP {sync.status}"
        a1, a2 = _device(b, api, "a1"), _device(b, api, "a2")
        cond("setup", code == 0 and out.get("state") == "applied" and synced == "succeeded" and a1.get("id") and a2.get("id"),
             f"policy-apply test-allow-intra exit {code} {out.get('state')}; devices/sync {synced}; a1 {bool(a1)} a2 {bool(a2)}")

        # control-plane state
        inst = b.get(f"{api}/diagnostics/instance")
        ij = inst.json() if inst.status == 200 else {}
        pol, dev, key = ij.get("policy") or {}, ij.get("devices") or {}, (ij.get("instance") or {}).get("api_key") or {}
        sections = {u.get("section"): u.get("reason") for u in ij.get("unavailable") or []}
        raw = inst.body.decode("utf-8", "replace")
        cond("instance", inst.status == 200 and bool(ij.get("checked_at")) and ij.get("tenant_status") == "active"
             and "checked_at" in ((ij.get("instance") or {}).get("health") or {})
             and pol.get("applied") is True and pol.get("applied_sha256") == stored_sha(st)
             and dev.get("synced_at") and dev.get("total", 0) >= 2 and dev.get("online", 0) >= 2
             and key.get("status") in ("valid", "expiring", "expired", "unknown") and set(key) <= {"status", "expires_at"}
             and sections.get("p2p_path") == "not_observable" and "hskey" not in raw,
             f"GET diagnostics/instance {inst.status}: health {(ij.get('instance') or {}).get('health')}; policy v"
             f"{pol.get('version')} sha matches Headscale {pol.get('applied_sha256') == stored_sha(st)}; devices {dev}; "
             f"api key {key.get('status')}; edge {(ij.get('edge') or {}).get('status')}; relays "
             f"{[x.get('code') for x in ij.get('relays') or []]}; unavailable {sections}")

        def diagnose(target: str, port: int | None, csrf: bool = True):
            body = {"source_device_id": a1.get("id"), "target_device_id": target}
            if port:
                body["port"] = port
            return b.request("POST", f"{api}/diagnostics/connectivity", json.dumps(body).encode(), _h(st, sess, csrf=csrf))

        ok = diagnose(a2.get("id"), checks.ALLOWED_PORT)
        oj = ok.json() if ok.status == 200 else {}
        cs = _checks(oj)
        linux_tcp = [c.get("command") for c in oj.get("commands") or [] if c.get("os") == "linux" and c.get("id") == "tcp_connect"]
        os_seen = sorted({c.get("os") for c in oj.get("commands") or []})
        real_ok = checks.tcp(st, "a1", a2_ip, checks.ALLOWED_PORT)
        cond("allowed", ok.status == 200 and oj.get("path_observable") is False and oj.get("verdict") == "allowed"
             and cs.get("policy_grant", ("",))[0] == "pass" and cs.get("target_online", ("",))[0] == "pass"
             and linux_tcp == [f"nc -vz -w 5 {a2_ip} {checks.ALLOWED_PORT}"] and os_seen == ["linux", "macos", "windows"]
             and bool(real_ok),
             f"a1→a2 tcp/{checks.ALLOWED_PORT}: {ok.status} verdict {oj.get('verdict')} checks {cs}; linux tcp step "
             f"{linux_tcp}; os {os_seen}; real TCP answer: {real_ok or 'none'}")

        no = diagnose(a2.get("id"), checks.DENIED_PORT)
        nj = no.json() if no.status == 200 else {}
        real_no = checks.tcp(st, "a1", a2_ip, checks.DENIED_PORT)
        cond("blocked", no.status == 200 and nj.get("verdict") == "blocked"
             and _checks(nj).get("policy_grant") == ("fail", "port_not_allowed") and not real_no,
             f"a1→a2 tcp/{checks.DENIED_PORT}: {no.status} verdict {nj.get('verdict')} policy_grant "
             f"{_checks(nj).get('policy_grant')}; real TCP answer: {real_no or 'none (blocked)'}")

        b1 = psql_one(st, f"SELECT id FROM device_inventory_cache WHERE tenant_id = '{b_id}' AND removed_at IS NULL "
                          "ORDER BY first_seen_at LIMIT 1")
        cross = diagnose(b1 or "0190ffff-0000-7000-8000-000000000001", checks.ALLOWED_PORT)
        same = diagnose(a1.get("id"), None)
        nocsrf = diagnose(a2.get("id"), None, csrf=False)
        cond("refusals", cross.status == 404 and same.status == 422 and nocsrf.status == 403,
             f"target of tenant-b ({'register' if b1 else 'random id'}) {cross.status}; same device {same.status}; "
             f"no CSRF {nocsrf.status}")
    finally:
        code, out, _ = policy_apply(st, base, "--trigger", "bootstrap")
        after = stored_sha(st)
    cond("cleanup", code == 0 and out.get("state") == "applied" and after == out.get("applied_sha256"),
         f"baseline again through the core: exit {code} {out.get('state')}, Headscale holds it "
         f"{after == out.get('applied_sha256')}; same policy as before the case: {after == before}")

    failed = [n for n, good in conds if not good]
    for row in rows:
        log(f"  E2E-123 {row}")
    r.add("E2E-123", "P5-T08 Connectivity Diagnostics: trạng thái control plane kèm checked_at (policy sha khớp Headscale, "
          "không secret, p2p_path không quan sát được); kết luận a1→a2 khớp TCP thật (8000 allowed ⇒ thông, 8001 blocked ⇒ "
          "chặn), checklist theo OS; thiết bị tenant khác ⇒ 404, cùng thiết bị ⇒ 422, thiếu CSRF ⇒ 403; dọn về baseline",
          not failed, (f"FAILED: {', '.join(failed)} — " if failed else "") + "; ".join(rows), limit=2500)


def run_all(r, st: Stack, guarded) -> None:
    guarded(r, "E2E-123", check_diagnostics, st)
