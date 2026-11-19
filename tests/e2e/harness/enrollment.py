"""P4-T06 device enrollment on the dev/CI stack — FUNCTIONAL only (§22.1): the api and worker built from the tree, real
Keycloak logins with TOTP through the edge on app., the real Headscale 0.29.7 of tenant-a and tenant-b behind the edge
admin listener, official Tailscale clients.

  E2E-99  pre-auth key (§7.4 method B): a Tenant Admin asks POST /enrollment/requests {preauth_key} (CSRF +
          Idempotency-Key) ⇒ 201 with the key shown once; the same Idempotency-Key ⇒ the same key (SecretStore with TTL);
          an official client joins tenant-a with it ⇒ Running, node of mg-<membership> registered by authkey; the same
          key on a second client ⇒ refused (single use); a key of 1 minute after its expiry ⇒ refused; a revoked key
          ⇒ refused (expired at Headscale); enrollment.reconcile (worker schedule) ⇒ the request consumed with its node,
          the short key expired; no table and no pg_dump of the stack holds a key (hskey-auth-) after the case
  E2E-100 web-auth brokered by the Portal (§7.4 flow A): the Tenant Admin asks {web_auth, device_label} ⇒ code + command
          (hostname mg-<code>, 10 minutes); an official client runs `tailscale up --hostname mg-<code>` and prints its
          /register/<auth_id> link; a claim of a link while no request is pending in the session ⇒ 409, Headscale
          unchanged, security event; the claim of the right link in the same session ⇒ 200 verified, the client
          Running, the node renamed to the label under mg-<membership>, the device in the inventory with its enrollment
          link, audit enrollment.claim.requested → .succeeded; a pending request claimed with the link of a client whose
          hostname is not mg-<code> ⇒ failed node_mismatch, the node deleted at once, security event
  E2E-101 approval before the device step and tenant isolation (IT-13): tenant-a requires approval and allows
          self-enrolment; an invited End User asks a pre-auth key ⇒ pending_approval, no key; /start ⇒ 409, a claim ⇒
          409; the Owner approves ⇒ /start by the End User ⇒ the key once (again ⇒ 409); the End User lists only its own
          requests. The key of tenant-a is refused by tenant-b's Headscale; tenant-b's Owner reading tenant-a's request
          through tenant-b's path ⇒ 404, claiming the Auth ID of a client of tenant-a through tenant-b ⇒ 409 and no node
          appears in either tenant

Standard library only. Passwords, TOTP keys, cookies, CSRF tokens, pre-auth keys and enrollment codes stay in this
process (and its redaction set); a key reaches a client container through a 0400 file.
"""
from __future__ import annotations

import json
import re
import secrets
import time

import checks
from backend import psql
from dualcontrol import owner_session, psql_one, tenant_id, unsafe
from lifecycle import admin_session
from members import invited_member
from stack import Stack, StackError, log

SLUG = "tenant-a"
AUTH_RE = re.compile(r"hskey-authreq-[A-Za-z0-9_-]{24}")


def _api(st: Stack, t_id: str) -> str:
    return f"https://app.{st.domain}/api/v1/tenants/{t_id}"


def _ensure_subscription(st: Stack, t_id: str) -> str:
    """The quota of §7.4 step 3 needs a live subscription; the dev stack's tenants were adopted without one. Returns the
    id of the row inserted ("" when the tenant had a live one already): a case running before E2E-99 … E2E-101 deletes
    it again (webauth.py, E2E-118)."""
    return psql_one(st, "WITH ins AS (INSERT INTO subscriptions (tenant_id, plan_id) SELECT '" + t_id + "', id FROM "
                    "subscription_plans WHERE key = 'standard' AND NOT EXISTS (SELECT 1 FROM subscriptions WHERE "
                    "tenant_id = '" + t_id + "' AND status IN ('trialing', 'active', 'past_due')) RETURNING id) "
                    "SELECT id FROM ins")


def _set_enrollment(st: Stack, t_id: str, doc: dict) -> None:
    psql(st, f"UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{{}}'::jsonb), '{{enrollment}}', "
         f"COALESCE(settings->'enrollment', '{{}}'::jsonb) || '{json.dumps(doc)}'::jsonb, true) WHERE id = '{t_id}'")


def _post(st: Stack, b, sess: dict, url: str, body: dict | None, idem: str | None = None):
    extra = {"Idempotency-Key": idem} if idem else {}
    r = b.request("POST", url, json.dumps(body).encode() if body is not None else b"", unsafe(st, sess, **extra))
    cred = (r.json().get("credential") or {}) if r.status in (200, 201) else {}
    for k in ("preauth_key", "enroll_code"):
        if cred.get(k):
            st.secret_values.add(cred[k])
    return r


def _key_file(st: Stack, name: str, key: str) -> str:
    d = st.fresh_dir(f"secrets/e2e-enroll-{name}")
    st.write_private(d / "authkey", key)
    st.helper(f"chown 0:0 /w/secrets/e2e-enroll-{name}/authkey; chmod 0400 /w/secrets/e2e-enroll-{name}/authkey", f"{st.work}:/w")
    return str(d / "authkey")


def _client(st: Stack, host: str, slug: str = SLUG, key_file: str | None = None, hostname: str | None = None) -> str:
    """A long-running official client (userspace, state in memory) running `tailscale up` against slug — with a key
    file, or without one (web-auth: the sign-in link goes to /tmp/up.log)."""
    name = st.name(f"enr-{host}")
    st.docker("rm", "-f", name, check=False)
    auth = '--auth-key=file:/run/mg-e2e/authkey ' if key_file else ''
    script = ('tailscaled --tun=userspace-networking --state=mem: --socket=/tmp/ts.sock --statedir=/tmp/st '
              '>/tmp/tsd.log 2>&1 & i=0; while [ ! -S /tmp/ts.sock ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done; '
              f'(timeout 300 tailscale --socket=/tmp/ts.sock up --login-server="$LOGIN" {auth}--hostname="$HN" '
              '--accept-dns=false --timeout=280s >/tmp/up.log 2>&1 &); exec sleep 900')
    args = ["run", "-d", "--name", name, "--network", st.name("edge"),
            "--add-host", f"tenant-a.{st.mesh}:{st.edge_ip}", "--add-host", f"tenant-b.{st.mesh}:{st.edge_ip}",
            "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "-v", f"{st.work / 'ca'}:/etc/mg-ci-ca:ro", "-e", "SSL_CERT_FILE=/etc/mg-ci-ca/ca.crt",
            "-e", "SSL_CERT_DIR=/etc/mg-ci-ca", "-e", "TS_NO_LOGS_NO_SUPPORT=true", "-e", f"LOGIN=https://{slug}.{st.mesh}",
            "-e", f"HN={hostname or host}"]
    if key_file:
        args += ["-v", f"{key_file}:/run/mg-e2e/authkey:ro"]
    st.docker(*args, "--entrypoint", "sh", st.images["tailscale"], "-c", script)
    return name


def _auth_id(st: Stack, name: str, timeout: float = 60) -> str:
    def find():
        out = st.docker("exec", name, "cat", "/tmp/up.log", check=False).stdout or ""
        m = AUTH_RE.search(out)
        return m.group(0) if m else None
    a = checks.wait(find, timeout) or ""
    if a:
        st.secret_values.add(a)
    return a


def _state(st: Stack, name: str) -> dict:
    p = st.docker("exec", name, "tailscale", "--socket=/tmp/ts.sock", "status", "--json", check=False)
    try:
        return json.loads(p.stdout or "{}")
    except ValueError:
        return {}


def _nodes(st: Stack, slug: str = SLUG) -> list[dict]:
    return json.loads(st.headscale(slug, "nodes", "list", "-o", "json").stdout or "[]") or []


def _request_status(st: Stack, rid: str) -> str:
    return psql_one(st, f"SELECT status FROM enrollment_requests WHERE id = '{rid}'")


def _wait_status(st: Stack, rid: str, want: tuple[str, ...], timeout: float) -> str:
    return checks.wait(lambda: (lambda s: s if s in want else None)(_request_status(st, rid)), timeout) or _request_status(st, rid)


def _membership(st: Stack, b) -> str:
    s = b.get(f"https://app.{st.domain}/api/v1/auth/session").json()
    ident = (s.get("principal") or {}).get("identity_id", "")
    return psql_one(st, f"SELECT m.id FROM tenant_memberships m JOIN tenants t ON t.id = m.tenant_id "
                    f"WHERE t.slug = '{SLUG}' AND m.identity_id = '{ident}'")


class _Conds:
    def __init__(self):
        self.rows, self.conds = [], []

    def __call__(self, name: str, good: bool, row: str) -> None:
        self.conds.append((name, good))
        self.rows.append(f"[{'ok' if good else 'FAIL'} {name}] {row}")

    def report(self, r, st: Stack, tid: str, title: str) -> None:
        failed = [n for n, good in self.conds if not good]
        for row in self.rows:
            log(f"  {tid} {st.redact(row)}")
        r.add(tid, title, not failed, (f"FAILED: {', '.join(failed)} — " if failed else "") + "; ".join(self.rows), limit=3000)


# ---------------------------------------------------------------------------------------------------- E2E-99
def check_preauth(r, st: Stack, state: dict) -> None:
    a_id = tenant_id(st, SLUG)
    _ensure_subscription(st, a_id)
    api, cond, clients = _api(st, a_id), _Conds(), []
    b, sess = admin_session(st)
    state.update(admin_browser=b, admin_session=sess)
    mid = _membership(st, b)
    try:
        # the short key first: its minute runs while the other steps do
        short = _post(st, b, sess, f"{api}/enrollment/requests", {"method": "preauth_key", "ttl_minutes": 1},
                      "e2e99-short-" + secrets.token_hex(4))
        short_key = (short.json().get("credential") or {}).get("preauth_key", "")
        short_id = short.json().get("request", {}).get("id", "")
        short_exp = time.time() + 61
        idem = "e2e99-" + secrets.token_hex(6)
        body = {"method": "preauth_key", "device_label": "e2e99-srv"}
        first = _post(st, b, sess, f"{api}/enrollment/requests", body, idem)
        replay = _post(st, b, sess, f"{api}/enrollment/requests", body, idem)
        fj, rj = first.json(), replay.json()
        key = (fj.get("credential") or {}).get("preauth_key", "")
        rid = fj.get("request", {}).get("id", "")
        cmd = (fj.get("credential") or {}).get("command", "")
        exp_s = (fj.get("credential") or {}).get("expires_at", "")
        cond("issued", first.status == 201 and key.startswith("hskey-auth-") and fj["request"]["status"] == "issued"
             and replay.status == 201 and (rj.get("credential") or {}).get("preauth_key") == key
             and rj["request"]["id"] == rid and key not in cmd and f"tenant-a.{st.mesh}" in cmd and short.status == 201,
             f"POST {first.status} status {fj.get('request', {}).get('status')} expires {exp_s}; replay {replay.status} same key "
             f"{(rj.get('credential') or {}).get('preauth_key') == key}; command has login server, no key; short key {short.status}")
        hs_keys = json.loads(st.headscale(SLUG, "preauthkeys", "list", "-o", "json").stdout or "[]") or []
        mine = [k for k in hs_keys if (k.get("user") or {}).get("name") == f"mg-{mid}"]
        cond("headscale_key", len(mine) >= 2 and not any(k.get("reusable") or k.get("ephemeral") for k in mine),
             f"{len(mine)} keys of mg-<membership>, none reusable/ephemeral")
        # the key registers one client
        c1 = _client(st, "e2e99-a", key_file=_key_file(st, "e2e99a", key), hostname="e2e99-srv")
        clients.append(c1)
        running = checks.wait(lambda: _state(st, c1).get("BackendState") == "Running", 90)
        node = next((n for n in _nodes(st) if (n.get("user") or {}).get("name") == f"mg-{mid}"
                     and n.get("name") == "e2e99-srv"), {})
        cond("joined", bool(running) and bool(node), f"client Running {bool(running)}, node {node.get('id')} of mg-<membership> "
             f"({node.get('register_method')})")
        # the same key again ⇒ refused (single use)
        rc, st2, _ = checks.probe_enroll(st, _key_file(st, "e2e99b", key), SLUG, "e2e99-reuse")
        cond("reuse_refused", rc != 0 and st2 != "Running", f"second client with the used key: rc={rc} state={st2}")
        # a revoked key ⇒ refused
        rev = _post(st, b, sess, f"{api}/enrollment/requests", {"method": "preauth_key"}, "e2e99-rev-" + secrets.token_hex(4))
        rev_key = (rev.json().get("credential") or {}).get("preauth_key", "")
        rev_id = rev.json().get("request", {}).get("id", "")
        done = _post(st, b, sess, f"{api}/enrollment/requests/{rev_id}/revoke", None)
        rc3, st3, _ = checks.probe_enroll(st, _key_file(st, "e2e99c", rev_key), SLUG, "e2e99-revoked")
        cond("revoked_refused", done.status == 200 and done.json().get("status") == "revoked" and rc3 != 0 and st3 != "Running",
             f"revoke {done.status} {done.json().get('status')}; client with the revoked key: rc={rc3} state={st3}")
        # the short key after its expiry ⇒ refused
        time.sleep(max(0.0, short_exp - time.time()) + 4)
        rc4, st4, _ = checks.probe_enroll(st, _key_file(st, "e2e99d", short_key), SLUG, "e2e99-expired")
        cond("expired_refused", rc4 != 0 and st4 != "Running", f"client with the 1-minute key after expiry: rc={rc4} state={st4}")
        # enrollment.reconcile (worker schedule: every 2 minutes per tenant with open requests)
        s1 = _wait_status(st, rid, ("consumed",), 240)
        s2 = _wait_status(st, short_id, ("expired",), 120)
        linked = psql_one(st, f"SELECT count(*) FROM enrollment_requests r JOIN device_inventory_cache d ON "
                          f"d.tenant_id = r.tenant_id AND d.headscale_node_id = r.consumed_node_id WHERE r.id = '{rid}'")
        cond("reconciled", s1 == "consumed" and s2 == "expired",
             f"request {s1} (node in the inventory: {linked}), short key {s2}, revoked {_request_status(st, rev_id)}")
        # no key material in the platform's database (§13.1, §20 P4-T06)
        leaked = psql_one(st, "SELECT (SELECT count(*) FROM enrollment_requests x WHERE x::text LIKE '%hskey-%') + "
                          "(SELECT count(*) FROM idempotency_keys x WHERE x::text LIKE '%hskey-%') + "
                          "(SELECT count(*) FROM audit_events x WHERE x::text LIKE '%hskey-%')")
        dump = st.exec("postgres", "pg_dump", "-U", "postgres", "-d", "meshguard", timeout=300).stdout
        in_dump = sum(dump.count(k) for k in (key, short_key, rev_key) if k) + dump.count("hskey-auth-")
        cond("no_key_in_db", leaked == "0" and in_dump == 0,
             f"rows with hskey- in enrollment_requests/idempotency_keys/audit_events: {leaked}; pg_dump ({len(dump)} bytes) "
             f"occurrences of the keys or hskey-auth-: {in_dump}")
    finally:
        for c in clients:
            st.docker("rm", "-f", c, check=False)
    cond.report(r, st, "E2E-99", "P4-T06 pre-auth key qua API: hiển thị một lần (replay cùng key trong TTL), client chính thức "
                "join được; key đã dùng / hết hạn / đã thu hồi bị từ chối; reconcile ⇒ consumed/expired; không có key trong "
                "bảng và pg_dump")


# ---------------------------------------------------------------------------------------------------- E2E-100
def check_web_auth(r, st: Stack, state: dict) -> None:
    a_id = tenant_id(st, SLUG)
    _ensure_subscription(st, a_id)
    api, cond, clients = _api(st, a_id), _Conds(), []
    b, sess = state.get("admin_browser"), state.get("admin_session")
    if not b:
        b, sess = admin_session(st)
    mid = _membership(st, b)
    try:
        # a client of someone's: its sign-in link claimed while nothing is pending in this session ⇒ 409
        evil = _client(st, "e2e100-evil", hostname="e2e100-evil")
        clients.append(evil)
        evil_auth = _auth_id(st, evil)
        before = len(_nodes(st))
        sec0 = psql_one(st, f"SELECT count(*) FROM security_events WHERE tenant_id = '{a_id}' AND kind = "
                        "'enrollment.claim_without_request'")
        nop = _post(st, b, sess, f"{api}/enrollment/web-auth/claim", {"auth_id": evil_auth})
        sec1 = psql_one(st, f"SELECT count(*) FROM security_events WHERE tenant_id = '{a_id}' AND kind = "
                        "'enrollment.claim_without_request'")
        cond("no_pending", bool(evil_auth) and nop.status == 409 and len(_nodes(st)) == before and int(sec1) == int(sec0) + 1,
             f"link printed {bool(evil_auth)}; claim without a pending request {nop.status}; nodes {before} → {len(_nodes(st))}; "
             f"security events {sec0} → {sec1}")
        # the real flow
        req = _post(st, b, sess, f"{api}/enrollment/requests", {"method": "web_auth", "device_label": "e2e100-web"},
                    "e2e100-" + secrets.token_hex(6))
        rj = req.json()
        cred = rj.get("credential") or {}
        code, rid = cred.get("enroll_code", ""), rj.get("request", {}).get("id", "")
        cond("issued", req.status == 201 and len(code) == 12 and cred.get("hostname") == f"mg-{code}"
             and f"--hostname=mg-{code}" in cred.get("command", "") and rj["request"]["status"] == "issued",
             f"POST {req.status} hostname mg-<12> command ok {f'--hostname=mg-{code}' in cred.get('command', '')}")
        good = _client(st, "e2e100-good", hostname=f"mg-{code}")
        clients.append(good)
        auth = _auth_id(st, good)
        claim = _post(st, b, sess, f"{api}/enrollment/web-auth/claim", {"auth_id": auth})
        cj = claim.json()
        running = checks.wait(lambda: _state(st, good).get("BackendState") == "Running", 90)
        node = next((n for n in _nodes(st) if str(n.get("id")) == str(cj.get("node_id"))), {})
        dev = psql_one(st, f"SELECT count(*) FROM device_inventory_cache WHERE enrollment_request_id = '{rid}' "
                       f"AND owner_membership_id = '{mid}'")
        audit = psql_one(st, "SELECT string_agg(action, ',' ORDER BY occurred_at, id) FROM audit_events WHERE "
                         f"resource_id = '{rid}'")
        cond("verified", claim.status == 200 and cj.get("status") == "verified" and bool(running)
             and node.get("given_name") == "e2e100-web" and (node.get("user") or {}).get("name") == f"mg-{mid}"
             and dev == "1" and "enrollment.claim.succeeded" in audit,
             f"claim {claim.status} {cj.get('status')}; client Running {bool(running)}; node {node.get('id')} "
             f"given_name {node.get('given_name')} user mg-<membership> {(node.get('user') or {}).get('name') == f'mg-{mid}'}; "
             f"inventory row with link {dev}; audit {audit}")
        # a pending request, the link of a client whose hostname is not mg-<code> ⇒ the node deleted, failed
        req2 = _post(st, b, sess, f"{api}/enrollment/requests", {"method": "web_auth"}, "e2e100b-" + secrets.token_hex(6))
        rid2 = req2.json().get("request", {}).get("id", "")
        bad = _post(st, b, sess, f"{api}/enrollment/web-auth/claim", {"auth_id": evil_auth})
        bj = bad.json()
        gone = not any(n.get("name") == "e2e100-evil" for n in _nodes(st))
        sec = psql_one(st, f"SELECT count(*) FROM security_events WHERE tenant_id = '{a_id}' AND kind = 'enrollment.node_mismatch'")
        cond("mismatch", bad.status == 200 and bj.get("status") == "failed" and bj.get("failure_code") == "node_mismatch"
             and gone and int(sec or 0) >= 1 and _request_status(st, rid2) == "failed",
             f"claim {bad.status} {bj.get('status')} {bj.get('failure_code')}; node e2e100-evil gone {gone}; security events {sec}")
    finally:
        for c in clients:
            st.docker("rm", "-f", c, check=False)
    cond.report(r, st, "E2E-100", "P4-T06 web-auth do Portal môi giới với client chính thức: mã trong hostname, claim chỉ khi "
                "có yêu cầu đang chờ trong cùng phiên (không có ⇒ 409 + security event), node được kiểm (đổi tên theo nhãn, "
                "sổ thiết bị có liên kết, audit cặp), hostname sai ⇒ node bị xóa ngay")


# ---------------------------------------------------------------------------------------------------- E2E-101
def check_approval_isolation(r, st: Stack, state: dict) -> None:
    a_id, b_id = tenant_id(st, SLUG), tenant_id(st, "tenant-b")
    for t in (a_id, b_id):
        _ensure_subscription(st, t)
    api_a, api_b, cond, clients = _api(st, a_id), _api(st, b_id), _Conds(), []
    ob, osess, _ = owner_session(st, SLUG)
    _set_enrollment(st, a_id, {"self_enroll": True, "requires_approval": True})
    try:
        _, ub, usess, _ = invited_member(st, ob, osess, a_id, "end_user")
        req = _post(st, ub, usess, f"{api_a}/enrollment/requests", {"method": "preauth_key"}, "e2e101-" + secrets.token_hex(6))
        rj = req.json()
        rid = rj.get("request", {}).get("id", "")
        early = _post(st, ub, usess, f"{api_a}/enrollment/requests/{rid}/start", None)
        claim = _post(st, ub, usess, f"{api_a}/enrollment/web-auth/claim", {"auth_id": "hskey-authreq-" + "e2e101x" * 3 + "abc"})
        cond("pending", req.status == 201 and rj["request"]["status"] == "pending_approval" and not rj.get("credential")
             and early.status == 409 and claim.status == 409,
             f"POST {req.status} {rj.get('request', {}).get('status')} credential {bool(rj.get('credential'))}; /start before "
             f"approval {early.status}; claim {claim.status}")
        appr = _post(st, ob, osess, f"{api_a}/enrollment/requests/{rid}/approve", None)
        start = _post(st, ub, usess, f"{api_a}/enrollment/requests/{rid}/start", None)
        again = _post(st, ub, usess, f"{api_a}/enrollment/requests/{rid}/start", None)
        key = (start.json().get("credential") or {}).get("preauth_key", "")
        time.sleep(6)   # the End User spent its burst of the enrollment rate-limit class (5 per identity, 1 per 5 s)
        lres = ub.get(f"{api_a}/enrollment/requests?limit=50")
        lst = lres.json().get("items", []) if lres.status == 200 else []
        cond("approved", appr.status == 200 and appr.json().get("status") == "approved" and start.status == 200
             and key.startswith("hskey-auth-") and again.status == 409 and lst and all(x.get("id") == rid for x in lst),
             f"approve {appr.status}; /start {start.status} key once; again {again.status}; End User list {lres.status}: {len(lst)} "
             "own request(s)")
        # IT-13: the key of tenant-a is refused by tenant-b's Headscale
        rc, stb, _ = checks.probe_enroll(st, _key_file(st, "e2e101", key), "tenant-b", "e2e101-cross")
        cond("key_cross_tenant", rc != 0 and stb != "Running", f"key of tenant-a on tenant-b: rc={rc} state={stb}")
        # tenant-b's Owner: tenant-a's request through its own path ⇒ 404; tenant-a's Auth ID claimed through tenant-b ⇒ 409
        bb, bsess, _ = owner_session(st, "tenant-b")
        cross_get = bb.get(f"{api_b}/enrollment/requests/{rid}")
        cli = _client(st, "e2e101-a", hostname="e2e101-a")
        clients.append(cli)
        auth = _auth_id(st, cli)
        na, nb = len(_nodes(st, SLUG)), len(_nodes(st, "tenant-b"))
        cross_claim = _post(st, bb, bsess, f"{api_b}/enrollment/web-auth/claim", {"auth_id": auth})
        time.sleep(3)
        cond("claim_cross_tenant", cross_get.status == 404 and bool(auth) and cross_claim.status == 409
             and len(_nodes(st, SLUG)) == na and len(_nodes(st, "tenant-b")) == nb,
             f"GET tenant-a's request via tenant-b {cross_get.status}; claim of tenant-a's Auth ID via tenant-b "
             f"{cross_claim.status}; nodes a {na} → {len(_nodes(st, SLUG))}, b {nb} → {len(_nodes(st, 'tenant-b'))}")
    except StackError:
        raise
    finally:
        _set_enrollment(st, a_id, {"self_enroll": False, "requires_approval": False})
        for c in clients:
            st.docker("rm", "-f", c, check=False)
    cond.report(r, st, "E2E-101", "P4-T06 phê duyệt trước bước thiết bị (pending_approval chưa phát key, /start chỉ sau khi "
                "duyệt, một lần) + cách ly IT-13: key của tenant-a bị Headscale của tenant-b từ chối, tenant-b không đọc/claim "
                "được yêu cầu và Auth ID của tenant-a")


def run_all(r, st: Stack, guarded) -> None:
    state: dict = {}
    guarded(r, "E2E-99", check_preauth, st, state)
    guarded(r, "E2E-100", check_web_auth, st, state)
    guarded(r, "E2E-101", check_approval_isolation, st, state)
