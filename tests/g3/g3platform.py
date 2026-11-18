"""The Platform API of the G3 tool (P3-T14) as a person would use it: the harness's browser and Keycloak login
(tests/e2e/harness/backend.py — Browser, portal_login with password + TOTP, step-up by a fresh login) through the
edge on admin.<domain>, CSRF + Idempotency-Key on every unsafe call, 429 waited out (Retry-After).

  create_tenant   POST /platform/tenants (platform.tenant:create — one Super Admin, §8.5) ⇒ 202 + job tenant.provision
  suspend/resume  POST /platform/tenants/{id}/suspend|resume ⇒ 202 + job (P3-T08)
  deprovision     DELETE /platform/tenants/{id} (P3-T09, always 2P — §8.5): requester A ⇒ 202 + approval; A approving
                  its own request ⇒ 403 (checked); approver B (another Super Admin, step-up) POST
                  /platform/approvals/{id}/approve with the payload_sha256 it read ⇒ 200 + job_id of tenant.deprovision
Standard library only; passwords, TOTP keys, cookies and CSRF tokens stay in this process and its redaction set.
"""
from __future__ import annotations

import json
import secrets
import ssl
import time

from g3stats import FINISHED
from g3target import G3Error, Target

import backend  # noqa: E402 — tests/e2e/harness (sys.path set by g3target)
from stack import StackError  # noqa: E402

STEP_UP_S = 15 * 60          # §8.5: approvals need a login of the last 15 minutes
FRESH_S = 10 * 60            # the tool signs in again before that


class TargetBrowser(backend.Browser):
    """backend.Browser dialling Target.connect with the SNI of each host; TLS verified against the target's CA file or
    the system roots (staging: Let's Encrypt)."""

    def __init__(self, t: Target):  # noqa: D107 — same fields as backend.Browser
        self.st = t
        self.ctx = ssl.create_default_context(cafile=t.cfg["ca_file"] or None)
        self.jar = {}


class Staff:
    def __init__(self, t: Target, user: dict, label: str):
        self.t, self.user, self.label = t, user, label
        self.otp = backend.TOTP()
        self.otp.key = user["totp_key"]
        self.browser: TargetBrowser | None = None
        self.session: dict = {}
        self.login_at = 0.0

    def login(self) -> None:
        self.browser = TargetBrowser(self.t)
        try:
            self.session, _ = backend.portal_login(self.t, self.browser, f"admin.{self.t.domain}", "scope=platform",
                                                   {"username": self.user["username"], "password": self.user["password"]},
                                                   self.otp)
        except StackError as e:
            raise G3Error(f"đăng nhập {self.label}: {self.t.redact(str(e))}") from e
        self.login_at = time.time()

    def fresh(self, max_age: float = FRESH_S) -> "Staff":
        if self.browser is None or time.time() - self.login_at > max_age:
            self.login()
        return self


class Platform:
    def __init__(self, t: Target, creds: list[dict]):
        self.t = t
        self.api = f"https://admin.{t.domain}/api/v1"
        self.a = Staff(t, creds[0], "Super Admin A")
        self.b = Staff(t, creds[1], "Super Admin B")

    # ------------------------------------------------------------------------------------------------ http
    def _headers(self, s: Staff, key: str | None) -> dict:
        h = {"Origin": f"https://admin.{self.t.domain}", "X-CSRF-Token": s.session.get("csrf_token", ""),
             "Content-Type": "application/json"}
        if key:
            h["Idempotency-Key"] = key
        return h

    def call(self, s: Staff, method: str, path: str, body: dict | None = None, key: str | None = None,
             tries: int = 6) -> backend.Resp:
        """One API call as s (signed in when needed), 429 waited out (Retry-After, at most 60 s each)."""
        s.fresh()
        data = json.dumps(body).encode() if body is not None else None
        for _ in range(tries):
            r = s.browser.request(method, f"{self.api}{path}", data,
                                  self._headers(s, key) if method != "GET" else None)
            if r.status == 401 and r.json().get("code") in ("reauth_required", "unauthenticated"):
                s.login()
                continue
            if r.status != 429:
                return r
            try:
                wait = min(60.0, float(r.header("Retry-After") or 5))
            except ValueError:
                wait = 5.0
            time.sleep(wait)
        return r

    def get(self, path: str, s: Staff | None = None) -> dict:
        r = self.call(s or self.a, "GET", path)
        if r.status != 200:
            raise G3Error(f"GET {path}: HTTP {r.status} {r.json().get('code', '')}")
        return r.json()

    # ------------------------------------------------------------------------------------------------ operations
    def create_tenant(self, slug: str, owner_email: str) -> tuple[backend.Resp, dict]:
        body = {"slug": slug, "name": f"G3 {slug}", "plan_key": "standard", "owner_email": owner_email,
                "identity_provider": {"driver": "keycloak"}, "settings": {"dns": {"magic_dns": True}}}
        r = self.call(self.a, "POST", "/platform/tenants", body, key=f"g3-create-{slug}")
        return r, r.json()

    def job(self, job_id: str) -> dict:
        return self.get(f"/platform/jobs/{job_id}")

    def wait_job(self, job_id: str, timeout: float = 900, every: float = 2.0) -> dict:
        """GET /platform/jobs/{id} until it is finished (or the timeout: the last view, status unchanged)."""
        end, doc = time.time() + timeout, {}
        while time.time() < end:
            r = self.call(self.a, "GET", f"/platform/jobs/{job_id}")
            doc = r.json() if r.status == 200 else {"status": f"HTTP {r.status}"}
            if doc.get("status") in FINISHED:
                return doc
            time.sleep(every)
        doc["timed_out"] = True
        return doc

    def tenant(self, tenant_id: str) -> dict:
        return self.get(f"/platform/tenants/{tenant_id}")

    def lifecycle(self, tenant_id: str, action: str) -> tuple[backend.Resp, dict]:
        r = self.call(self.a, "POST", f"/platform/tenants/{tenant_id}/{action}", None,
                      key=f"g3-{action}-{secrets.token_hex(6)}")
        return r, r.json()

    def deprovision(self, tenant_id: str, slug: str, reason: str) -> dict:
        """DELETE /platform/tenants/{id} by A ⇒ approval; A's self-approval ⇒ 403; B approves ⇒ job. Returns
        {request_status, approval_id, self_approval_status, approve_status, job_id, available, error}."""
        out: dict = {"available": True}
        self.a.fresh(STEP_UP_S - 60)
        r = self.call(self.a, "DELETE", f"/platform/tenants/{tenant_id}",
                      {"confirm_slug": slug, "reason": reason, "skip_final_backup": False},
                      key=f"g3-delete-{secrets.token_hex(6)}")
        out["request_status"] = r.status
        if r.status in (404, 405) and r.json().get("code") in ("", "not_found", "method_not_allowed", None) \
                and "approval" not in r.body.decode("utf-8", "replace"):
            # no route: the build has no DELETE /platform/tenants/{id} yet (P3-T09 not merged)
            probe = self.call(self.a, "GET", f"/platform/tenants/{tenant_id}")
            if probe.status == 200:
                out.update(available=False, error=f"DELETE /platform/tenants/{{id}} ⇒ HTTP {r.status}: bản dựng chưa có "
                                                  "deprovision (P3-T09)")
                return out
        if r.status != 202:
            out["error"] = f"DELETE ⇒ HTTP {r.status} {r.json().get('code', '')} {r.json().get('detail', '')}".strip()
            return out
        appr = r.json()
        out["approval_id"] = appr.get("id", "")
        seen_a = self.get(f"/platform/approvals/{out['approval_id']}", self.a)
        self_try = self.call(self.a, "POST", f"/platform/approvals/{out['approval_id']}/approve",
                             {"payload_sha256": seen_a.get("payload_sha256")})
        out["self_approval_status"] = self_try.status
        self.b.fresh(STEP_UP_S - 60)
        seen = self.get(f"/platform/approvals/{out['approval_id']}", self.b)
        out["payload"] = seen.get("payload")
        ok = self.call(self.b, "POST", f"/platform/approvals/{out['approval_id']}/approve",
                       {"payload_sha256": seen.get("payload_sha256")})
        out["approve_status"] = ok.status
        doc = ok.json()
        out["approval_status"] = doc.get("status")
        out["job_id"] = doc.get("job_id") or ""
        if ok.status != 200 or not out["job_id"]:
            out["error"] = f"approve ⇒ HTTP {ok.status} {doc.get('code', '')} status {doc.get('status')}"
        return out
