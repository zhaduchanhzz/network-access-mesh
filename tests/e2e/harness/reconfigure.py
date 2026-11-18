"""Checks of instance.reconfigure (P3-T13) through the real API on the dev/CI stack — FUNCTIONAL only (§22.1). The stack
has no Host Agent, so its worker does not run instance.reconfigure (no MG_AGENT_*): a job stays queued, which is the
state the API side acts on. The instance of tenant-a was adopted by hand (E2E-21: no configuration version recorded by
the orchestrator); the case first meets that refusal, then records a version the way provisioning step 8 does (as
the cluster superuser, removed again at the end) to reach the queued job.

  E2E-63  POST /platform/instances/{id}/reconfigure by a Super Admin on admin. (CSRF + Idempotency-Key): the adopted
          instance ⇒ 409 (no configuration version); with a version ⇒ 202 + Location of the platform job, job
          instance.reconfigure queued on the instance; the same request again ⇒ the same job; the same change under
          another key ⇒ the same job; another change ⇒ 409; the same key with another body ⇒ 422; an invalid value ⇒ 422;
          an unknown instance ⇒ 404; without CSRF ⇒ 403; audit platform.instance.reconfigure.requested (platform scope)
  E2E-64  POST /platform/jobs/{id}/cancel on that queued job ⇒ 202 cancelled, audit .failed (reason cancelled) closes
          the operation; /retry ⇒ 409; then a new reconfiguration of the instance is accepted again (no job left
          holding its key) and cancelled; the recorded version is removed (the stack is as before)

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


SHA = "e" * 64
PARAMS = json.dumps({"image_digest": "sha256:" + "d" * 64, "run_uid": 30001, "net_cidr": "10.250.0.0/29", "memory_mib": 512,
                     "cpu_millis": 1000, "pids": 256, "node_expiry_days": 90, "nameservers": ["1.1.1.1"],
                     "derp_region_id": 901, "public_entry_ipv4": "192.0.2.10", "log_level": "LOG_LEVEL_INFO"})


def check_reconfigure(r, st: Stack, state: dict) -> None:
    b, sess = state["sa"]["browser"], state["sa"]["session"]
    api = f"https://admin.{st.domain}/api/v1"
    inst = _one(st, "SELECT i.id FROM tenant_instances i JOIN tenants t ON t.id = i.tenant_id "
                    "WHERE t.slug = 'tenant-a' AND i.status = 'running'")
    url = f"{api}/platform/instances/{inst}/reconfigure"
    body = json.dumps({"log_level": "warn", "node_expiry_days": 30}).encode()
    key = "e2e-rcfg-" + secrets.token_hex(8)
    adopted = b.request("POST", url, body, _headers(st, sess, key + "-adopted"))
    # a configuration version as provisioning step 8 records it (removed again by E2E-64)
    vid = str(uuid.uuid4())
    psql(st, "INSERT INTO instance_config_versions (id, tenant_id, instance_id, version, template_version, params, "
             f"rendered_config, config_sha256, status) SELECT '{vid}', tenant_id, id, "
             "(SELECT COALESCE(max(version), 0) + 1 FROM instance_config_versions WHERE instance_id = i.id), '2', "
             f"'{PARAMS}'::jsonb, 'e2e (P3-T13)', '{SHA}', 'applied' FROM tenant_instances i WHERE i.id = '{inst}' "
             "RETURNING id")
    psql(st, f"UPDATE tenant_instances SET config_version_id = '{vid}' WHERE id = '{inst}' RETURNING id")
    state["rcfg"] = {"instance": inst, "version": vid}
    first = b.request("POST", url, body, _headers(st, sess, key))
    job = first.json()
    state["rcfg"]["job"] = job.get("id", "")
    again = b.request("POST", url, body, _headers(st, sess, key))
    same = b.request("POST", url, body, _headers(st, sess, key + "-same"))
    other = b.request("POST", url, json.dumps({"log_level": "error"}).encode(), _headers(st, sess, key + "-other"))
    reuse = b.request("POST", url, json.dumps({"log_level": "error"}).encode(), _headers(st, sess, key))
    bad = b.request("POST", url, json.dumps({"nameservers": ["127.0.0.1"]}).encode(), _headers(st, sess, key + "-bad"))
    unknown = b.request("POST", f"{api}/platform/instances/{uuid.uuid4()}/reconfigure", body, _headers(st, sess, key + "-unk"))
    nocsrf = b.request("POST", url, body, {"Origin": f"https://admin.{st.domain}", "Content-Type": "application/json",
                                           "Idempotency-Key": key + "-nocsrf"})
    row = psql(st, f"SELECT kind, status, instance_id, input->'change'->>'log_level', input->'change'->>'node_expiry_days' "
                   f"FROM provisioning_jobs WHERE id = '{job.get('id', uuid.uuid4())}'")
    audit = _one(st, "SELECT count(*) FROM audit_events WHERE action = 'platform.instance.reconfigure.requested' "
                     f"AND tenant_id IS NULL AND resource_id = '{inst}'")
    ok = (bool(inst) and adopted.status == 409 and adopted.json().get("code") == "conflict"
          and first.status == 202 and first.header("Location") == f"/api/v1/platform/jobs/{job.get('id')}"
          and job.get("kind") == "instance.reconfigure" and job.get("status") == "queued"
          and job.get("resource", {}).get("id") == inst
          and again.status == 202 and again.json().get("id") == job.get("id")
          and same.status == 202 and same.json().get("id") == job.get("id")
          and other.status == 409 and reuse.status == 422 and reuse.json().get("code") == "idempotency_key_reuse"
          and bad.status == 422 and unknown.status == 404 and nocsrf.status == 403
          and row == [["instance.reconfigure", "queued", inst, "warn", "30"]] and audit == "1")
    r.add("E2E-63", "P3-T13: POST /platform/instances/{id}/reconfigure (admin., CSRF + Idempotency-Key): instance dựng tay "
          "(chưa có version cấu hình) ⇒ 409; có version ⇒ 202 + Location job instance.reconfigure queued; lặp lại cùng khóa "
          "⇒ cùng job; cùng thay đổi khóa khác ⇒ cùng job; thay đổi khác ⇒ 409; cùng khóa khác body ⇒ 422; giá trị sai ⇒ "
          "422; instance lạ ⇒ 404; thiếu CSRF ⇒ 403; audit .requested phạm vi platform", ok,
          f"adopted {adopted.status} {adopted.json().get('detail')!r}, post {first.status} {first.header('Location')}, kind "
          f"{job.get('kind')} status {job.get('status')}, replay {again.status} same={again.json().get('id') == job.get('id')}, "
          f"same change {same.status} same={same.json().get('id') == job.get('id')}, other {other.status}, reuse "
          f"{reuse.status} {reuse.json().get('code')}, invalid {bad.status}, unknown {unknown.status}, no CSRF "
          f"{nocsrf.status}, job row {row}, audit {audit}")


def check_cancel(r, st: Stack, state: dict) -> None:
    b, sess = state["sa"]["browser"], state["sa"]["session"]
    api = f"https://admin.{st.domain}/api/v1"
    o = state["rcfg"]
    jid, inst = o["job"], o["instance"]
    try:
        cancel = b.request("POST", f"{api}/platform/jobs/{jid}/cancel", None, _headers(st, sess, "e2e-rcfg-cancel-" + jid[:8]))
        retry = b.request("POST", f"{api}/platform/jobs/{jid}/retry", None, _headers(st, sess, "e2e-rcfg-retry-" + jid[:8]))
        events = _one(st, "SELECT string_agg(action || '/' || COALESCE(details->>'reason', '-'), ',' ORDER BY occurred_at) "
                          "FROM audit_events WHERE operation_id = (SELECT (input->'operation'->>'id')::uuid "
                          f"FROM provisioning_jobs WHERE id = '{jid}')")
        url = f"{api}/platform/instances/{inst}/reconfigure"
        again = b.request("POST", url, json.dumps({"derp_region_id": 950}).encode(),
                          _headers(st, sess, "e2e-rcfg-again-" + jid[:8]))
        aj = again.json().get("id", "")
        undo = b.request("POST", f"{api}/platform/jobs/{aj}/cancel", None, _headers(st, sess, "e2e-rcfg-cancel2-" + jid[:8])) \
            if aj else None
        ok = (cancel.status == 202 and cancel.json().get("status") == "cancelled"
              and cancel.json().get("error", {}).get("code") == "cancelled" and retry.status == 409
              and events == "platform.instance.reconfigure.requested/-,platform.instance.reconfigure.failed/cancelled"
              and again.status == 202 and aj and aj != jid and undo is not None and undo.status == 202
              and undo.json().get("status") == "cancelled")
        r.add("E2E-64", "P3-T13: /cancel của job instance.reconfigure chưa chạy ⇒ 202 cancelled, audit .failed (cancelled) "
              "đóng operation; /retry ⇒ 409; yêu cầu mới sau đó được nhận (không job nào còn giữ khóa)", ok,
              f"cancel {cancel.status} {cancel.json().get('status')}, retry {retry.status}, audit {events}, new request "
              f"{again.status} new job={bool(aj) and aj != jid}, cancel it {undo.status if undo else None}")
    finally:
        psql(st, f"UPDATE tenant_instances SET config_version_id = NULL WHERE id = '{inst}' RETURNING id")
        psql(st, f"DELETE FROM instance_config_versions WHERE id = '{o['version']}' RETURNING id")


def run_all(r, st: Stack, guarded, state: dict) -> None:
    """E2E-63, E2E-64 in order (E2E-64 cancels the job E2E-63 queued and removes the version it recorded)."""
    if "sa" not in state:
        return
    guarded(r, "E2E-63", check_reconfigure, st, state)
    if state.get("rcfg", {}).get("job"):
        guarded(r, "E2E-64", check_cancel, st, state)
    elif state.get("rcfg"):
        o = state["rcfg"]
        psql(st, f"UPDATE tenant_instances SET config_version_id = NULL WHERE id = '{o['instance']}' RETURNING id")
        psql(st, f"DELETE FROM instance_config_versions WHERE id = '{o['version']}' RETURNING id")
