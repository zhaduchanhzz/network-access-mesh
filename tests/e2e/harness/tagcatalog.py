"""P4-T15 tag catalog on the dev/CI stack — FUNCTIONAL only (§22.1): the api and worker built from the tree, a real
Keycloak login with TOTP through the edge, the real Headscale of tenant-a behind the edge admin listener.

  E2E-91  (provisional number — the coordinator renumbers) a Tenant Admin of tenant-a: GET /tenants/{a}/tags ⇒ 200;
          POST tag:e2e-web (CSRF + Idempotency-Key) ⇒ 201, the same request again ⇒ the same tag, the name again ⇒ 409,
          purpose router ⇒ 422; the policy.apply job (trigger tag_change) succeeds and Headscale stores the desired
          baseline with "tagOwners": {"tag:e2e-web": []} — the application recorded applied with the sha256 Headscale
          holds. An undeclared tag is refused on the two paths that exist on this stack: PUT /devices/{a1}/tags ⇒ 422
          (field tags, Headscale's node unchanged) and the policy core (`admin policy-apply` with a grant on it) ⇒ exit 3
          lint L6, Headscale's policy unchanged; the third path (requested_tags of an enrollment) has no API before
          P4-T06 — its catalog check is internal/policies' DB test. PATCH without If-Match ⇒ 428, with the etag ⇒ 200; a
          policy granting tag:e2e-web applied through the core ⇒ DELETE ⇒ 409 (tag in use); the deny-all baseline again ⇒
          DELETE ⇒ 204 and the next policy.apply leaves Headscale with the baseline without "tagOwners"; audit tag.create,
          tag.update, tag.delete by the Tenant Admin.

Standard library only. Passwords, TOTP keys, cookies and CSRF tokens stay in this process (and its redaction set).
"""
from __future__ import annotations

import json
import secrets
import time

from dualcontrol import psql_one, tenant_id
from lifecycle import admin_session
from phase3 import policy_apply, stored_sha
from stack import ROOT, Stack, log

SLUG = "tenant-a"
TAG = "tag:e2e-web"


def _headers(st: Stack, sess: dict, idem: str | None = None, if_match: str | None = None) -> dict:
    h = {"Origin": f"https://app.{st.domain}", "X-CSRF-Token": sess["csrf_token"], "Content-Type": "application/json"}
    if idem:
        h["Idempotency-Key"] = idem
    if if_match:
        h["If-Match"] = if_match
    return h


def _wait_apply(st: Stack, a_id: str, since: str, timeout: float = 120) -> str:
    """Status of the newest policy.apply job of tenant a created after `since` (DB clock), once it is finished."""
    end, status = time.time() + timeout, ""
    while time.time() < end:
        status = psql_one(st, "SELECT status FROM provisioning_jobs WHERE kind = 'policy.apply' AND "
                          f"tenant_id = '{a_id}' AND created_at > '{since}' ORDER BY created_at DESC LIMIT 1")
        if status in ("succeeded", "failed", "cancelled"):
            return status
        time.sleep(1)
    return status or "none"


def _last_application(st: Stack, a_id: str) -> str:
    return psql_one(st, "SELECT trigger || '|' || state || '|' || applied_sha256 FROM policy_applications "
                    f"WHERE tenant_id = '{a_id}' ORDER BY created_at DESC LIMIT 1")


def _node_tags(st: Stack, name_part: str) -> list:
    for n in json.loads(st.headscale(SLUG, "nodes", "list", "-o", "json").stdout or "[]") or []:
        if name_part in (n.get("given_name") or n.get("name") or ""):
            return n.get("tags") or []
    return ["?"]


def check_catalog(r, st: Stack) -> None:
    a_id = tenant_id(st, SLUG)
    api = f"https://app.{st.domain}/api/v1/tenants/{a_id}"
    rows, conds = [], []

    def cond(name: str, good: bool, row: str) -> None:
        conds.append((name, good))
        rows.append(f"[{'ok' if good else 'FAIL'} {name}] {row}")

    b, sess = admin_session(st)
    lst = b.get(f"{api}/tags?limit=50")
    cond("list", lst.status == 200 and isinstance(lst.json().get("items"), list), f"GET tags {lst.status}")

    since = psql_one(st, "SELECT now()::text")
    idem = "e2e-tag-" + secrets.token_hex(6)
    body = json.dumps({"name": TAG, "description": "E2E web"}).encode()
    first = b.request("POST", f"{api}/tags", body, _headers(st, sess, idem))
    tag = first.json() if first.status == 201 else {}
    replay = b.request("POST", f"{api}/tags", body, _headers(st, sess, idem))
    dup = b.request("POST", f"{api}/tags", body, _headers(st, sess, "e2e-tag-" + secrets.token_hex(6)))
    router = b.request("POST", f"{api}/tags", json.dumps({"name": "tag:e2e-router", "purpose": "router"}).encode(),
                       _headers(st, sess, "e2e-tag-" + secrets.token_hex(6)))
    cond("create", first.status == 201 and tag.get("name") == TAG and tag.get("etag") == '"1"'
         and replay.status == 201 and replay.json().get("id") == tag.get("id") and dup.status == 409
         and router.status == 422,
         f"POST {first.status} etag {tag.get('etag')}; replay {replay.status} same={replay.json().get('id') == tag.get('id')}; "
         f"duplicate {dup.status}; router {router.status}")
    status = _wait_apply(st, a_id, since)
    stored = st.headscale(SLUG, "policy", "get").stdout
    app = _last_application(st, a_id).split("|")
    owned = ('"' + TAG + '": []') in stored
    cond("rendered", status == "succeeded" and owned and '"tagOwners"' in stored
         and app[:2] == ["tag_change", "applied"] and app[-1] == stored_sha(st),
         f"policy.apply {status}; Headscale tagOwners has {TAG} with no owner: {owned}; last application {app[:2]}, "
         f"sha matches Headscale: {app[-1] == stored_sha(st)}")
    jobs = b.get(f"{api}/jobs?kind=policy.apply&limit=5")
    cond("jobs_api", jobs.status == 200 and any(j.get("kind") == "policy.apply" for j in jobs.json().get("items", [])),
         f"GET jobs?kind=policy.apply {jobs.status}")

    # undeclared tag — path 1: PUT /devices/{id}/tags
    devs = b.get(f"{api}/devices?limit=50").json().get("items", [])
    dev = next((d for d in devs if "a1" in (d.get("given_name") or d.get("name") or "")), devs[0] if devs else {})
    before_tags = _node_tags(st, "a1")
    put = b.request("PUT", f"{api}/devices/{dev.get('id')}/tags", json.dumps({"tags": ["tag:e2e-undeclared"]}).encode(),
                    _headers(st, sess, if_match=dev.get("tags_etag", "")))
    perr = put.json() if put.status == 422 else {}
    fields = [e.get("field") for e in perr.get("errors") or []]
    no_match = b.request("PUT", f"{api}/devices/{dev.get('id')}/tags", json.dumps({"tags": [TAG]}).encode(), _headers(st, sess))
    cond("device_undeclared", put.status == 422 and "tags" in fields and _node_tags(st, "a1") == before_tags
         and no_match.status == 428,
         f"PUT devices/{{a1}}/tags undeclared {put.status} fields {fields}; node tags {before_tags} → {_node_tags(st, 'a1')}; "
         f"without If-Match {no_match.status}")
    # undeclared tag — path 2: the policy core (lint L6)
    sha0 = stored_sha(st)
    code, out, _ = policy_apply(st, '{"grants": [{"src": ["autogroup:member"], "dst": ["tag:e2e-undeclared"], '
                                    '"ip": ["tcp:443"]}], "ssh": []}')
    cond("policy_l6", code == 3 and out.get("lint_rule") == "L6" and stored_sha(st) == sha0,
         f"policy-apply grant on an undeclared tag: exit {code} lint {out.get('lint_rule')}; Headscale unchanged "
         f"{stored_sha(st) == sha0}")

    # PATCH: If-Match required
    nomatch = b.request("PATCH", f"{api}/tags/{tag.get('id')}", json.dumps({"description": "web"}).encode(), _headers(st, sess))
    patched = b.request("PATCH", f"{api}/tags/{tag.get('id')}", json.dumps({"description": "web"}).encode(),
                        _headers(st, sess, if_match=tag.get("etag")))
    etag = patched.header("ETag") or ""
    cond("patch", nomatch.status == 428 and patched.status == 200 and etag == '"2"'
         and patched.json().get("description") == "web", f"PATCH without If-Match {nomatch.status}; with {patched.status} etag {etag}")

    # DELETE while a policy that can be applied grants the tag ⇒ 409; the baseline again ⇒ 204
    code, out, _ = policy_apply(st, '{"grants": [{"src": ["autogroup:member"], "dst": ["' + TAG + '"], "ip": ["tcp:443"]}], '
                                    '"ssh": []}')
    held = b.request("DELETE", f"{api}/tags/{tag.get('id')}", None, _headers(st, sess, if_match=etag))
    cond("delete_in_use", code == 0 and out.get("state") == "applied" and held.status == 409
         and "policy" in (held.json().get("detail") or ""),
         f"policy granting {TAG}: exit {code} {out.get('state')}; DELETE {held.status} {held.json().get('detail', '')[:120]}")
    base = (ROOT / "infrastructure" / "headscale" / "templates" / "bootstrap-policy.hujson").read_text(encoding="utf-8")
    code, out, _ = policy_apply(st, base, "--trigger", "bootstrap")
    since = psql_one(st, "SELECT now()::text")
    gone = b.request("DELETE", f"{api}/tags/{tag.get('id')}", None, _headers(st, sess, if_match=etag))
    status = _wait_apply(st, a_id, since)
    stored = st.headscale(SLUG, "policy", "get").stdout
    cond("delete", code == 0 and gone.status == 204 and status == "succeeded" and "tagOwners" not in stored
         and _last_application(st, a_id).split("|")[-1] == stored_sha(st),
         f"baseline again exit {code}; DELETE {gone.status}; policy.apply {status}; Headscale without tagOwners "
         f"{'tagOwners' not in stored}")
    audit = psql_one(st, "SELECT string_agg(action, ',' ORDER BY occurred_at, id) FROM audit_events WHERE "
                     f"tenant_id = '{a_id}' AND resource_id = '{tag.get('id')}' AND action LIKE 'tag.%' "
                     "AND actor_type = 'identity' AND outcome = 'success'")
    cond("audit", audit.startswith("tag.create") and "tag.update" in audit and audit.endswith("tag.delete"), f"audit {audit}")

    failed = [n for n, good in conds if not good]
    for row in rows:
        log(f"  E2E-91 {st.redact(row)}")
    r.add("E2E-91", "P4-T15 danh mục tag: CRUD qua API (Idempotency-Key, 409 trùng, 422 purpose nền tảng, If-Match 428); "
          "đổi danh mục ⇒ policy.apply tag_change ⇒ Headscale lưu tagOwners owner rỗng; tag chưa khai báo bị từ chối ở PUT "
          "devices/{id}/tags (422) và lõi policy (L6); xóa tag còn được policy tham chiếu ⇒ 409, hết tham chiếu ⇒ 204", not failed,
          (f"FAILED: {', '.join(failed)} — " if failed else "") + "; ".join(rows), limit=2500)


def run_all(r, st: Stack, guarded) -> None:
    guarded(r, "E2E-91", check_catalog, st)

