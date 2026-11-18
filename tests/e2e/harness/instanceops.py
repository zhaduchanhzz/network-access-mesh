"""Checks of instance.restart and instance.upgrade (P3-T13a) through the real API and the real worker command on the
dev/CI stack — FUNCTIONAL only (§22.1). The stack has no Host Agent, so its worker does not run the two kinds (no
MG_AGENT_*): a job stays queued, which is the state the API side acts on (the state machines themselves run against a
real Agent and real Headscale images in agent-it TestUpgradeEndToEnd). The instances of the stack were adopted by hand
(E2E-21: no configuration version recorded by the orchestrator); the upgrade case first meets that refusal, then
records a version the way provisioning step 8 does (as the cluster superuser, removed again at the end).

  E2E-79  POST /platform/instances/{id}/restart by a Super Admin on admin. (CSRF + Idempotency-Key, no body) ⇒ 202 +
          Location of the platform job, job instance.restart queued on the instance; the same request again ⇒ the same
          job; another key while it waits ⇒ the same job (two requests in a row are one restart — §13.5); an unknown
          instance ⇒ 404; without CSRF ⇒ 403; audit platform.instance.restart.requested (platform scope) written once
  E2E-80  POST /platform/instances/{id}/upgrade: the adopted instance (no configuration version) ⇒ 409; with a version:
          a tag instead of a digest ⇒ 422; the digest it already runs ⇒ 409; another digest ⇒ 202 + job instance.upgrade
          queued (input = the target digest); the same request again ⇒ the same job; the same target under another key
          ⇒ the same job; another target while it waits ⇒ 409; the same key with another body ⇒ 422; audit
          platform.instance.upgrade.requested with the target and the previous digest, written once
  E2E-81  /cancel of both queued jobs ⇒ 202 cancelled, each audit operation closed .failed (cancelled), /retry ⇒ 409;
          `meshguard-worker admin upgrade-wave` in the running worker: --all --dry-run plans the instance with a version
          and not the one without (exit 0, nothing enqueued); a wave whose canary cannot be enqueued (the instance of
          tenant-b, no version) ⇒ exit 1 STOPPED, the canary refused (no_config_version), the instance after it never
          enqueued; the recorded version is removed (the stack is as before)

Standard library only; no credential printed.
"""
from __future__ import annotations

import json
import secrets
import uuid

from backend import container, psql
from stack import Stack

SHA = "e" * 64
TARGET = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
PARAMS = json.dumps({"image_digest": "sha256:" + "d" * 64, "run_uid": 30001, "net_cidr": "10.250.0.0/29", "memory_mib": 512,
                     "cpu_millis": 1000, "pids": 256, "node_expiry_days": 90, "nameservers": ["1.1.1.1"],
                     "derp_region_id": 901, "public_entry_ipv4": "192.0.2.10", "log_level": "LOG_LEVEL_INFO"})


def _headers(st: Stack, sess: dict, key: str | None = None) -> dict:
    h = {"Origin": f"https://admin.{st.domain}", "X-CSRF-Token": sess["csrf_token"], "Content-Type": "application/json"}
    if key:
        h["Idempotency-Key"] = key
    return h


def _one(st: Stack, sql: str) -> str:
    rows = psql(st, sql)
    return rows[0][0] if rows and rows[0] else ""


def _instance(st: Stack, slug: str) -> str:
    return _one(st, "SELECT i.id FROM tenant_instances i JOIN tenants t ON t.id = i.tenant_id "
                    f"WHERE t.slug = '{slug}' AND i.status = 'running'")


def _events(st: Stack, job: str) -> str:
    return _one(st, "SELECT string_agg(action || '/' || COALESCE(details->>'reason', '-'), ',' ORDER BY occurred_at) "
                    "FROM audit_events WHERE operation_id = (SELECT (input->'operation'->>'id')::uuid "
                    f"FROM provisioning_jobs WHERE id = '{job}')")


def check_restart(r, st: Stack, state: dict) -> None:
    b, sess = state["sa"]["browser"], state["sa"]["session"]
    api = f"https://admin.{st.domain}/api/v1"
    inst = _instance(st, "tenant-a")
    url = f"{api}/platform/instances/{inst}/restart"
    key = "e2e-rst-" + secrets.token_hex(8)
    first = b.request("POST", url, None, _headers(st, sess, key))
    job = first.json()
    state["ops"] = {"instance": inst, "restart": job.get("id", "")}
    again = b.request("POST", url, None, _headers(st, sess, key))
    other = b.request("POST", url, None, _headers(st, sess, key + "-other"))
    unknown = b.request("POST", f"{api}/platform/instances/{uuid.uuid4()}/restart", None, _headers(st, sess, key + "-unk"))
    nocsrf = b.request("POST", url, None, {"Origin": f"https://admin.{st.domain}", "Content-Type": "application/json",
                                           "Idempotency-Key": key + "-nocsrf"})
    row = psql(st, f"SELECT kind, status, instance_id, input->>'source' FROM provisioning_jobs "
                   f"WHERE id = '{job.get('id', uuid.uuid4())}'")
    audit = _one(st, "SELECT count(*) FROM audit_events WHERE action = 'platform.instance.restart.requested' "
                     f"AND tenant_id IS NULL AND resource_id = '{inst}'")
    ok = (bool(inst) and first.status == 202 and first.header("Location") == f"/api/v1/platform/jobs/{job.get('id')}"
          and job.get("kind") == "instance.restart" and job.get("status") == "queued"
          and job.get("resource", {}).get("id") == inst
          and again.status == 202 and again.json().get("id") == job.get("id")
          and other.status == 202 and other.json().get("id") == job.get("id")
          and unknown.status == 404 and nocsrf.status == 403
          and row == [["instance.restart", "queued", inst, "platform_api"]] and audit == "1")
    r.add("E2E-79", "P3-T13a: POST /platform/instances/{id}/restart (admin., CSRF + Idempotency-Key) ⇒ 202 + Location job "
          "instance.restart queued; lặp lại cùng khóa ⇒ cùng job; khóa khác khi job còn chờ ⇒ cùng job (hai yêu cầu liền "
          "nhau là một lần restart); instance lạ ⇒ 404; thiếu CSRF ⇒ 403; audit .requested phạm vi platform ghi một lần", ok,
          f"post {first.status} {first.header('Location')}, kind {job.get('kind')} status {job.get('status')}, replay "
          f"{again.status} same={again.json().get('id') == job.get('id')}, other key {other.status} "
          f"same={other.json().get('id') == job.get('id')}, unknown {unknown.status}, no CSRF {nocsrf.status}, job row "
          f"{row}, audit {audit}")


def check_upgrade(r, st: Stack, state: dict) -> None:
    b, sess = state["sa"]["browser"], state["sa"]["session"]
    api = f"https://admin.{st.domain}/api/v1"
    o = state["ops"]
    inst = o["instance"]
    url = f"{api}/platform/instances/{inst}/upgrade"
    key = "e2e-upg-" + secrets.token_hex(8)

    def body(d: str) -> bytes:
        return json.dumps({"image_digest": d}).encode()

    adopted = b.request("POST", url, body(TARGET), _headers(st, sess, key + "-adopted"))
    # a configuration version as provisioning step 8 records it (removed again by E2E-81)
    vid = str(uuid.uuid4())
    psql(st, "INSERT INTO instance_config_versions (id, tenant_id, instance_id, version, template_version, params, "
             f"rendered_config, config_sha256, status) SELECT '{vid}', tenant_id, id, "
             "(SELECT COALESCE(max(version), 0) + 1 FROM instance_config_versions WHERE instance_id = i.id), '2', "
             f"'{PARAMS}'::jsonb, 'e2e (P3-T13a)', '{SHA}', 'applied' FROM tenant_instances i WHERE i.id = '{inst}' "
             "RETURNING id")
    psql(st, f"UPDATE tenant_instances SET config_version_id = '{vid}' WHERE id = '{inst}' RETURNING id")
    o["version"] = vid
    running = _one(st, f"SELECT image_digest FROM tenant_instances WHERE id = '{inst}'")
    tag = b.request("POST", url, body("headscale:0.29.7"), _headers(st, sess, key + "-tag"))
    same = b.request("POST", url, body(running), _headers(st, sess, key + "-running"))
    first = b.request("POST", url, body(TARGET), _headers(st, sess, key))
    job = first.json()
    o["upgrade"] = job.get("id", "")
    again = b.request("POST", url, body(TARGET), _headers(st, sess, key))
    other_key = b.request("POST", url, body(TARGET), _headers(st, sess, key + "-same"))
    other_target = b.request("POST", url, body(OTHER), _headers(st, sess, key + "-other"))
    reuse = b.request("POST", url, body(OTHER), _headers(st, sess, key))
    row = psql(st, f"SELECT kind, status, instance_id, input->>'image_digest' FROM provisioning_jobs "
                   f"WHERE id = '{job.get('id', uuid.uuid4())}'")
    audit = psql(st, "SELECT details->>'image_digest', details->>'previous_image_digest' FROM audit_events "
                     f"WHERE action = 'platform.instance.upgrade.requested' AND resource_id = '{inst}'")
    ok = (bool(inst) and adopted.status == 409 and "configuration version" in (adopted.json().get("detail") or "")
          and tag.status == 422 and bool(running) and running != TARGET and same.status == 409
          and "already runs" in (same.json().get("detail") or "")
          and first.status == 202 and first.header("Location") == f"/api/v1/platform/jobs/{job.get('id')}"
          and job.get("kind") == "instance.upgrade" and job.get("status") == "queued"
          and again.status == 202 and again.json().get("id") == job.get("id")
          and other_key.status == 202 and other_key.json().get("id") == job.get("id")
          and other_target.status == 409 and reuse.status == 422 and reuse.json().get("code") == "idempotency_key_reuse"
          and row == [["instance.upgrade", "queued", inst, TARGET]] and audit == [[TARGET, running]])
    r.add("E2E-80", "P3-T13a: POST /platform/instances/{id}/upgrade (admin., CSRF + Idempotency-Key): instance dựng tay "
          "(chưa có version cấu hình) ⇒ 409; có version: tag thay cho digest ⇒ 422; digest đang chạy ⇒ 409; digest khác ⇒ "
          "202 + job instance.upgrade queued (input = digest đích); lặp lại ⇒ cùng job; cùng đích khóa khác ⇒ cùng job; "
          "đích khác khi job còn chờ ⇒ 409; cùng khóa khác body ⇒ 422; audit .requested có digest đích và digest trước", ok,
          f"adopted {adopted.status} {adopted.json().get('detail')!r}, tag {tag.status}, running digest {same.status}, post "
          f"{first.status} kind {job.get('kind')} status {job.get('status')}, replay {again.status} "
          f"same={again.json().get('id') == job.get('id')}, other key {other_key.status} "
          f"same={other_key.json().get('id') == job.get('id')}, other target {other_target.status}, reuse {reuse.status} "
          f"{reuse.json().get('code')}, job row {row}, audit {len(audit)} row(s) target ok={audit[:1] == [[TARGET, running]]}")


def _wave(st: Stack, *args: str):
    p = st.docker("exec", container(st, "worker"), "/usr/local/bin/meshguard", "admin", "upgrade-wave", *args,
                  check=False, timeout=180)
    lines = [json.loads(ln) for ln in p.stdout.splitlines() if ln.startswith("{")]
    return p, lines


def check_cancel_wave(r, st: Stack, state: dict) -> None:
    b, sess = state["sa"]["browser"], state["sa"]["session"]
    api = f"https://admin.{st.domain}/api/v1"
    o = state["ops"]
    inst, rj, uj = o["instance"], o.get("restart", ""), o.get("upgrade", "")
    try:
        cr = b.request("POST", f"{api}/platform/jobs/{rj}/cancel", None, _headers(st, sess, "e2e-ops-cr-" + rj[:8]))
        cu = b.request("POST", f"{api}/platform/jobs/{uj}/cancel", None, _headers(st, sess, "e2e-ops-cu-" + uj[:8]))
        retry = b.request("POST", f"{api}/platform/jobs/{uj}/retry", None, _headers(st, sess, "e2e-ops-ru-" + uj[:8]))
        er, eu = _events(st, rj), _events(st, uj)
        inst_b = _instance(st, "tenant-b")
        jobs_before = _one(st, f"SELECT count(*) FROM provisioning_jobs WHERE kind = 'instance.upgrade' AND instance_id = '{inst}'")
        dry, dl = _wave(st, "--image", TARGET, "--all", "--dry-run")
        planned = [ln.get("instance_id") for ln in dl if ln.get("event") == "planned"]
        stop, sl = _wave(st, "--image", TARGET, "--canary", inst_b, "--instances", inst, "--job-timeout", "1m")
        refused = [ln for ln in sl if ln.get("event") == "refused"]
        report = next((ln["report"] for ln in sl if "report" in ln), {})
        jobs_after = _one(st, f"SELECT count(*) FROM provisioning_jobs WHERE kind = 'instance.upgrade' AND instance_id = '{inst}'")
        ok = (cr.status == 202 and cr.json().get("status") == "cancelled" and cu.status == 202
              and cu.json().get("status") == "cancelled" and cu.json().get("error", {}).get("code") == "cancelled"
              and retry.status == 409
              and er == "platform.instance.restart.requested/-,platform.instance.restart.failed/cancelled"
              and eu == "platform.instance.upgrade.requested/-,platform.instance.upgrade.failed/cancelled"
              and dry.returncode == 0 and inst in planned and bool(inst_b) and inst_b not in planned
              and stop.returncode == 1 and "STOPPED" in stop.stderr and len(refused) == 1
              and refused[0].get("instance_id") == inst_b and refused[0].get("code") == "no_config_version"
              and report.get("stopped") is True and report.get("canary") == inst_b and jobs_after == jobs_before
              and not any(ln.get("event") == "enqueued" for ln in sl + dl))
        r.add("E2E-81", "P3-T13a: /cancel của job restart và upgrade chưa chạy ⇒ 202 cancelled, audit .failed (cancelled) "
              "đóng từng operation; /retry ⇒ 409; `meshguard-worker admin upgrade-wave` trong worker đang chạy: --all "
              "--dry-run lên kế hoạch cho instance có version, không có instance thiếu version, không enqueue; canary không "
              "enqueue được (tenant-b, chưa có version) ⇒ exit 1 STOPPED, instance sau canary không bị enqueue", ok,
              f"cancel restart {cr.status} {cr.json().get('status')}, cancel upgrade {cu.status} {cu.json().get('status')}, "
              f"retry {retry.status}, audit restart {er}, audit upgrade {eu}; dry-run exit {dry.returncode} planned "
              f"{len(planned)} (A {inst in planned}, B {inst_b in planned}); wave exit {stop.returncode} refused "
              f"{[x.get('code') for x in refused]} stopped {report.get('stopped')}, upgrade jobs of A {jobs_before}→{jobs_after}")
    finally:
        if o.get("version"):
            psql(st, f"UPDATE tenant_instances SET config_version_id = NULL WHERE id = '{inst}' RETURNING id")
            psql(st, f"DELETE FROM instance_config_versions WHERE id = '{o['version']}' RETURNING id")


def run_all(r, st: Stack, guarded, state: dict) -> None:
    """E2E-79 … E2E-81 in order (E2E-81 cancels the jobs E2E-79/E2E-80 queued and removes the version E2E-80 recorded)."""
    if "sa" not in state:
        return
    guarded(r, "E2E-79", check_restart, st, state)
    if not state.get("ops"):
        return
    guarded(r, "E2E-80", check_upgrade, st, state)
    if state["ops"].get("restart") or state["ops"].get("upgrade"):
        guarded(r, "E2E-81", check_cancel_wave, st, state)
    elif state["ops"].get("version"):
        o = state["ops"]
        psql(st, f"UPDATE tenant_instances SET config_version_id = NULL WHERE id = '{o['instance']}' RETURNING id")
        psql(st, f"DELETE FROM instance_config_versions WHERE id = '{o['version']}' RETURNING id")
