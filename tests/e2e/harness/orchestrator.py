"""Checks of the Tenant Orchestrator (P3-T05) through the real API on the dev/CI stack — FUNCTIONAL only (§22.1). The
stack has no Host Agent, so its worker runs without the orchestrator (no MG_PROVISION_*/MG_AGENT_*): a tenant.provision
job stays queued, which is exactly the state the API side of steps 1–2 and the job controls act on.

  E2E-46  POST /platform/tenants by a Super Admin on admin. (CSRF + Idempotency-Key) ⇒ 202 + Location of the platform
          job; the job is tenant.provision, queued, with steps 1 validate and 2 registry.create succeeded; the tenant
          is `provisioning` with a subscription; audit platform.tenant.create.requested; the same request again ⇒ the
          same job; the same slug under another key ⇒ 409; a reserved slug ⇒ 422; without CSRF ⇒ 403
  E2E-47  POST /platform/jobs/{id}/cancel on that queued job ⇒ 202, `cancelled`, the tenant `failed`, audit
          platform.tenant.create.failed + platform.job.cancel; /retry and /rollback of the cancelled job ⇒ 409
          (state machine); an unknown job ⇒ 404

E2E-48 … E2E-51 are reserved for the provisioning of a tenant on Docker with the Host Agent (P3-T07 / P3-T14).
Standard library only; no credential printed.
"""
from __future__ import annotations

import json
import secrets
import uuid

from backend import psql
from stack import Stack


def _headers(st: Stack, sess: dict, key: str | None = None) -> dict:
    h = {"Origin": f"https://admin.{st.domain}", "X-CSRF-Token": sess["csrf_token"], "Content-Type": "application/json"}
    if key:
        h["Idempotency-Key"] = key
    return h


def _one(st: Stack, sql: str) -> str:
    rows = psql(st, sql)
    return rows[0][0] if rows and rows[0] else ""


def check_create(r, st: Stack, state: dict) -> None:
    b, sess = state["sa"]["browser"], state["sa"]["session"]
    api = f"https://admin.{st.domain}/api/v1"
    slug = "e2e-orch-" + secrets.token_hex(3)
    body = json.dumps({"slug": slug, "name": "E2E orchestrator", "plan_key": "standard",
                       "owner_email": f"owner@{slug}.example.test", "identity_provider": {"driver": "keycloak"},
                       "settings": {"dns": {"magic_dns": True}}}).encode()
    key = "e2e-orch-" + secrets.token_hex(8)
    first = b.request("POST", f"{api}/platform/tenants", body, _headers(st, sess, key))
    job = first.json()
    again = b.request("POST", f"{api}/platform/tenants", body, _headers(st, sess, key))
    dup = b.request("POST", f"{api}/platform/tenants", body, _headers(st, sess, key + "-other"))
    reserved = b.request("POST", f"{api}/platform/tenants",
                         body.replace(slug.encode(), b"admin"), _headers(st, sess, key + "-reserved"))
    nocsrf = b.request("POST", f"{api}/platform/tenants", body,
                       {"Origin": f"https://admin.{st.domain}", "Content-Type": "application/json", "Idempotency-Key": key})
    tid = job.get("tenant_id", "")
    steps = [(s.get("name"), s.get("status")) for s in job.get("steps", [])]
    tenant = _one(st, f"SELECT status FROM tenants WHERE slug = '{slug}'")
    sub = _one(st, f"SELECT count(*) FROM subscriptions s JOIN tenants t ON t.id = s.tenant_id WHERE t.slug = '{slug}'")
    audit = _one(st, "SELECT count(*) FROM audit_events WHERE action = 'platform.tenant.create.requested' "
                     f"AND resource_id = '{tid}'") if tid else "0"
    state["orch"] = {"job": job.get("id", ""), "tenant": tid, "slug": slug}
    ok = (first.status == 202 and first.header("Location") == f"/api/v1/platform/jobs/{job.get('id')}"
          and job.get("kind") == "tenant.provision" and job.get("status") == "queued"
          and steps == [("validate", "succeeded"), ("registry.create", "succeeded")]
          and again.status == 202 and again.json().get("id") == job.get("id")
          and dup.status == 409 and dup.json().get("code") == "conflict"
          and reserved.status == 422 and nocsrf.status == 403
          and tenant == "provisioning" and sub == "1" and audit == "1")
    r.add("E2E-46", "P3-T05: POST /platform/tenants (admin., CSRF + Idempotency-Key) ⇒ 202 + Location job; job "
          "tenant.provision queued, bước validate + registry.create succeeded; tenant provisioning + subscription; audit "
          ".requested; lặp lại cùng khóa ⇒ cùng job; slug trùng ⇒ 409; slug cấm ⇒ 422; thiếu CSRF ⇒ 403", ok,
          f"post {first.status} {first.header('Location')}, kind {job.get('kind')} status {job.get('status')}, steps "
          f"{steps}, replay {again.status} same={again.json().get('id') == job.get('id')}, dup {dup.status} "
          f"{dup.json().get('code')}, reserved {reserved.status}, no CSRF {nocsrf.status}, tenant {tenant}, "
          f"subscriptions {sub}, audit {audit}")


def check_cancel(r, st: Stack, state: dict) -> None:
    b, sess = state["sa"]["browser"], state["sa"]["session"]
    api = f"https://admin.{st.domain}/api/v1"
    o = state["orch"]
    jid = o["job"]
    cancel = b.request("POST", f"{api}/platform/jobs/{jid}/cancel", None, _headers(st, sess, "e2e-cancel-" + jid[:8]))
    retry = b.request("POST", f"{api}/platform/jobs/{jid}/retry", None, _headers(st, sess, "e2e-retry-" + jid[:8]))
    rollback = b.request("POST", f"{api}/platform/jobs/{jid}/rollback", None, _headers(st, sess, "e2e-rb-" + jid[:8]))
    unknown = b.request("POST", f"{api}/platform/jobs/{uuid.uuid4()}/cancel", None, _headers(st, sess, "e2e-unk-" + jid[:8]))
    detail = b.get(f"{api}/platform/jobs/{jid}")
    tenant = _one(st, f"SELECT status FROM tenants WHERE id = '{o['tenant']}'")
    events = _one(st, "SELECT string_agg(action, ',' ORDER BY occurred_at) FROM audit_events WHERE "
                      f"(action LIKE 'platform.tenant.create%' AND resource_id = '{o['tenant']}') OR "
                      f"(action = 'platform.job.cancel' AND resource_id = '{jid}')")
    ok = (cancel.status == 202 and cancel.json().get("status") == "cancelled"
          and cancel.json().get("error", {}).get("code") == "cancelled"
          and retry.status == 409 and rollback.status == 409 and unknown.status == 404
          and detail.status == 200 and detail.json().get("status") == "cancelled" and tenant == "failed"
          and events == "platform.tenant.create.requested,platform.tenant.create.failed,platform.job.cancel")
    r.add("E2E-47", "P3-T05: /cancel của job tenant.provision chưa chạy ⇒ 202 cancelled, tenant failed, audit "
          ".failed + platform.job.cancel; /retry, /rollback của job cancelled ⇒ 409; job lạ ⇒ 404", ok,
          f"cancel {cancel.status} {cancel.json().get('status')}, retry {retry.status}, rollback {rollback.status}, "
          f"unknown {unknown.status}, job {detail.status} {detail.json().get('status')}, tenant {tenant}, audit {events}")


def run_all(r, st: Stack, guarded, state: dict) -> None:
    """E2E-46, E2E-47 in order (E2E-47 cancels the job E2E-46 created)."""
    if "sa" not in state:
        return
    if guarded(r, "E2E-46", check_create, st, state) is None and state.get("orch", {}).get("job"):
        guarded(r, "E2E-47", check_cancel, st, state)
