"""Web-auth redirect of the edge (P4-T07, §7.4 flow A step 6, §14.6, edge template v10) on the dev/CI stack —
FUNCTIONAL only (§22.1): official Tailscale clients, the real Headscale of tenant-a and tenant-b, the edge rendered from
the tree (only its tls block differs — stack.ci_tls), the SPA and the api built from the tree.

  E2E-117 the link of a real client: an official client runs `tailscale up --login-server https://<slug>.<mesh>` without
          a key and prints https://<slug>.<mesh>/register/<auth_id>; GET/HEAD of that link through the edge WITHOUT
          via=portal ⇒ 302, Location exactly https://app.<domain>/enroll/claim?tenant=<slug>&auth_id=<auth_id> (the
          Portal's claim page — the contract of P4-T08), Cache-Control no-store, nothing of the request reflected
          (query strings that are not via=portal, X-Forwarded-Host/-Proto, Forwarded); the Location answers the SPA's
          index.html with the edge's security headers; WITH via=portal ⇒ Headscale's own page for that Auth ID
          (native OIDC mode); malformed Auth IDs of the conformance suite (with and without via=portal) ⇒ 404 without
          Location; on both tenants; afterwards the client is still waiting for its login (NeedsLogin): neither the
          redirect nor the proxied page touched the pending registration
  E2E-118 V-07 (functional): a client completes its registration after the claim that starts from the redirect — the
          claim uses ONLY the two parameters of the Location (tenant slug → tenant id through GET /auth/session, auth_id),
          as the claim page of P4-T08 will. With the enrollment API of P4-T06 on the tree (module enrollment.py): a
          Tenant Admin asks a web-auth request (code → hostname mg-<code>), the client prints its link, the redirect,
          POST /tenants/{id}/enrollment/web-auth/claim ⇒ 200 verified, the client Running, the node renamed to the
          label; afterwards the node leaves tenant-a through the product (DELETE /tenants/{id}/devices/{id} ⇒ 202, job
          device.revoke succeeded, no node mg-<code> left at Headscale) and the subscription the case inserted for the
          quota is deleted again — the cases after this one count a1's peers exactly (E2E-36, E2E-56/58, E2E-96: one
          peer, a2) and found tenant-a without a subscription before P4-T06. Without it (P4-T07 alone): the claim step is
          `headscale auth register` of the Auth ID from the Location (CLI of the stack, as in E2E-14) ⇒ the client
          Running; the control node is deleted afterwards.

Standard library only. Auth IDs, codes, cookies and CSRF tokens join the run's redaction set.
"""
from __future__ import annotations

import json
import re
import secrets
import sys
import urllib.parse

import checks
from backend import Browser
from spa import header_issues, is_index
from stack import ROOT, TENANTS, Stack, StackError

sys.path.insert(0, str(ROOT / "tests" / "security" / "edge"))
import conformance  # noqa: E402 — BAD_AUTH_IDS / NOT_VIA_PORTAL of the edge conformance suite (template v10)

try:                    # the enrollment API of P4-T06 (claim through the Portal) — absent on a tree without it
    import enrollment
except ImportError:
    enrollment = None

LINK_RE = re.compile(r"https://([a-z0-9.-]+)/register/(hskey-authreq-[A-Za-z0-9_-]{24})")
SPOOF = {"X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "http", "Forwarded": "host=evil.example"}


def _client(st: Stack, tag: str, slug: str, hostname: str) -> str:
    """A long-running official client (userspace, state in memory) running `tailscale up` against slug without a key:
    its sign-in link goes to /tmp/up.log."""
    name = st.name(f"wa-{tag}")
    st.docker("rm", "-f", name, check=False)
    script = ('tailscaled --tun=userspace-networking --state=mem: --socket=/tmp/ts.sock --statedir=/tmp/st '
              '>/tmp/tsd.log 2>&1 & i=0; while [ ! -S /tmp/ts.sock ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done; '
              '(timeout 300 tailscale --socket=/tmp/ts.sock up --login-server="$LOGIN" --hostname="$HN" '
              '--accept-dns=false --timeout=280s >/tmp/up.log 2>&1 &); exec sleep 900')
    st.docker("run", "-d", "--name", name, "--network", st.name("edge"),
              *[x for s in TENANTS for x in ("--add-host", f"{s}.{st.mesh}:{st.edge_ip}")],
              "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
              "-v", f"{st.work / 'ca'}:/etc/mg-ci-ca:ro", "-e", "SSL_CERT_FILE=/etc/mg-ci-ca/ca.crt",
              "-e", "SSL_CERT_DIR=/etc/mg-ci-ca", "-e", "TS_NO_LOGS_NO_SUPPORT=true",
              "-e", f"LOGIN=https://{slug}.{st.mesh}", "-e", f"HN={hostname}",
              "--entrypoint", "sh", st.images["tailscale"], "-c", script)
    return name


def _link(st: Stack, name: str, timeout: float = 60) -> tuple[str, str]:
    """(host, auth_id) of the sign-in link the client printed."""
    def find():
        out = st.docker("exec", name, "cat", "/tmp/up.log", check=False).stdout or ""
        m = LINK_RE.search(out)
        return (m.group(1), m.group(2)) if m else None
    got = checks.wait(find, timeout) or ("", "")
    if got[1]:
        st.secret_values.add(got[1])
    return got


def _backend_state(st: Stack, name: str) -> str:
    p = st.docker("exec", name, "tailscale", "--socket=/tmp/ts.sock", "status", "--json", check=False)
    try:
        return json.loads(p.stdout or "{}").get("BackendState", "")
    except ValueError:
        return ""


def _nodes(st: Stack, slug: str) -> list[dict]:
    return json.loads(st.headscale(slug, "nodes", "list", "-o", "json").stdout or "[]") or []


def claim_url(st: Stack, slug: str, auth_id: str) -> str:
    """The redirect target of edge template v10 — the URL the claim page of P4-T08 is served at."""
    return f"https://app.{st.domain}/enroll/claim?tenant={slug}&auth_id={auth_id}"


class _Conds:
    def __init__(self):
        self.rows, self.conds = [], []

    def __call__(self, name: str, good: bool, row: str) -> None:
        self.conds.append((name, good))
        self.rows.append(f"[{'ok' if good else 'FAIL'} {name}] {row}")

    def report(self, r, tid: str, title: str) -> None:
        failed = [n for n, good in self.conds if not good]
        r.add(tid, title, not failed, (f"FAILED: {', '.join(failed)} — " if failed else "") + "; ".join(self.rows),
              limit=3000)


# ---------------------------------------------------------------------------------------------------- E2E-117
def check_redirect(r, st: Stack) -> None:
    b, cond, clients = Browser(st), _Conds(), []
    try:
        for slug in TENANTS:
            name = _client(st, f"e2e117-{slug[-1]}", slug, f"e2e117-{slug[-1]}")
            clients.append(name)
            host, auth = _link(st, name)
            cond(f"{slug} link", host == f"{slug}.{st.mesh}" and bool(auth),
                 f"client printed https://<{'own tenant host' if host == f'{slug}.{st.mesh}' else host}>/register/<id>: "
                 f"{bool(auth)}")
            if not auth:
                continue
            link, want = f"https://{host}/register/{auth}", claim_url(st, slug, auth)
            bad = []
            for method in ("GET", "HEAD"):
                for q in conformance.NOT_VIA_PORTAL:
                    resp = b.request(method, link + q, headers=SPOOF)
                    if not (resp.status == 302 and resp.header("Location") == want
                            and resp.header("Cache-Control") == "no-store"):
                        bad.append(f"{method} {q or '(no query)'} ⇒ {resp.status} {resp.header('Location')[:60]!r}")
            cond(f"{slug} redirect", not bad, f"{2 * len(conformance.NOT_VIA_PORTAL)} requests ⇒ 302 to "
                 f"app.<domain>/enroll/claim?tenant={slug}&auth_id=<id>, no-store, nothing reflected {bad[:3]}")
            page = b.get(want)
            cond(f"{slug} claim page", is_index(page) and not header_issues(page),
                 f"Location ⇒ {page.status} index.html of the SPA {is_index(page)}, security headers {header_issues(page)}")
            native = b.get(link + "?via=portal")
            text = native.body.decode("utf-8", "replace")
            cond(f"{slug} via=portal", native.status == 200 and not native.header("Location")
                 and f"headscale auth register --auth-id {auth}" in text,
                 f"?via=portal ⇒ {native.status}, Headscale's page for this Auth ID "
                 f"{f'--auth-id {auth}' in text}")
            refused = []
            for bad_id in conformance.BAD_AUTH_IDS:
                for q in ("", "?via=portal"):
                    resp = b.get(f"https://{host}/register/{bad_id}{q}")
                    if resp.status != 404 or resp.header("Location"):
                        refused.append(f"/register/{bad_id}{q} ⇒ {resp.status}")
            cond(f"{slug} malformed", not refused, f"{2 * len(conformance.BAD_AUTH_IDS)} malformed Auth IDs ⇒ 404 "
                 f"without Location {refused[:3]}")
            state = _backend_state(st, name)
            cond(f"{slug} pending kept", state == "NeedsLogin", f"client still waiting for its login: {state}")
    finally:
        for c in clients:
            st.docker("rm", "-f", c, check=False)
    cond.report(r, "E2E-117", "P4-T07: link /register/<auth_id> của client chính thức ⇒ 302 về trang claim của Portal "
                "(Location cố định app.<domain>/enroll/claim?tenant=<slug>&auth_id=<id>, no-store, không phản chiếu "
                "query/X-Forwarded-*), trang đích là SPA; via=portal ⇒ trang gốc của Headscale; Auth ID sai định dạng "
                "⇒ 404; client vẫn chờ đăng nhập (chuyển hướng không đụng pending registration)")


# ---------------------------------------------------------------------------------------------------- E2E-118
def _follow(st: Stack, b: Browser, host: str, auth: str) -> tuple[str, str, str]:
    """GET the client's link; returns (status/location summary, slug, auth_id) read from the Location ONLY."""
    resp = b.get(f"https://{host}/register/{auth}")
    loc = urllib.parse.urlsplit(resp.header("Location"))
    q = urllib.parse.parse_qs(loc.query)
    ok = resp.status == 302 and f"{loc.scheme}://{loc.netloc}{loc.path}" == f"https://app.{st.domain}/enroll/claim"
    return (f"{resp.status} {'claim page' if ok else resp.header('Location')[:60]!r}", (q.get("tenant") or [""])[0] if ok else "",
            (q.get("auth_id") or [""])[0] if ok else "")


def _remove_device(st: Stack, cond: _Conds, b: Browser, sess: dict, t_id: str, slug: str, rid: str, host: str) -> None:
    """The node the claim registered leaves the tenant through the product — DELETE /devices/{id} ⇒ job device.revoke
    (DeleteNode + read-back, §13.5) —, as a Tenant Admin removes a device; whatever is still left (no inventory row, the
    job failed) is deleted through the CLI of the stack so that the next cases still find a1 and a2 alone, and the
    case fails."""
    from dualcontrol import psql_one, unsafe
    from members import wait_job

    def left() -> list[dict]:
        return [n for n in _nodes(st, slug) if n.get("name") == host]
    dev = psql_one(st, f"SELECT id FROM device_inventory_cache WHERE enrollment_request_id = '{rid}' "
                   "AND removed_at IS NULL") if rid else ""
    if not dev and not left():
        cond("cleanup", True, "no device registered, nothing to remove")
        return
    status, job = "no inventory row", ""
    if dev:
        resp = b.request("DELETE", f"https://app.{st.domain}/api/v1/tenants/{t_id}/devices/{dev}", b"", unsafe(st, sess))
        status = str(resp.status)
        if resp.status == 202 and resp.header("Location"):
            job, _ = wait_job(st, resp.header("Location").rsplit("/", 1)[-1], 120)
    gone = bool(checks.wait(lambda: not left(), 30))
    forced = []
    if not gone:
        for n in left():
            st.headscale(slug, "nodes", "delete", "--identifier", str(n["id"]), "--force", check=False)
            forced.append(str(n["id"]))
    cond("cleanup", status == "202" and job == "succeeded" and gone,
         f"DELETE /devices/<id> ⇒ {status}, job device.revoke {job or '-'}; node mg-<code> gone at Headscale {gone}"
         + (f"; deleted through the CLI instead: nodes {forced}" if forced else ""))


def _drop_subscription(st: Stack, cond: _Conds, sub: str) -> None:
    """The subscription inserted for the quota (enrollment._ensure_subscription) is deleted again: tenant-a stays as it
    was adopted for the cases between this one and E2E-99 … E2E-101 (nothing references subscriptions)."""
    from dualcontrol import psql_one
    psql_one(st, f"DELETE FROM subscriptions WHERE id = '{sub}'")
    left = psql_one(st, f"SELECT count(*) FROM subscriptions WHERE id = '{sub}'")
    cond("subscription", left == "0", f"subscription inserted for the quota deleted again {left == '0'}")


def _claim_api(st: Stack, cond: _Conds, clients: list[str], undo: list) -> None:
    """Claim through the Portal API of P4-T06 with the parameters of the Location (the claim page of P4-T08). What the
    case adds to tenant-a (the node, the subscription) goes into undo, run by check_v07 once the client is gone."""
    from dualcontrol import tenant_id
    from lifecycle import admin_session
    slug = "tenant-a"
    a_id = tenant_id(st, slug)
    sub = enrollment._ensure_subscription(st, a_id)
    if sub:
        undo.append(lambda: _drop_subscription(st, cond, sub))
    b, sess = admin_session(st)
    req = enrollment._post(st, b, sess, f"https://app.{st.domain}/api/v1/tenants/{a_id}/enrollment/requests",
                           {"method": "web_auth", "device_label": "e2e118-web"}, "e2e118-" + secrets.token_hex(6))
    cred = (req.json().get("credential") or {})
    code = cred.get("enroll_code", "")
    rid = (req.json().get("request") or {}).get("id", "")
    cond("request", req.status == 201 and len(code) == 12, f"POST /enrollment/requests web_auth ⇒ {req.status}")
    if not code:
        return
    undo.append(lambda: _remove_device(st, cond, b, sess, a_id, slug, rid, f"mg-{code}"))
    name = _client(st, "e2e118", slug, f"mg-{code}")
    clients.append(name)
    host, auth = _link(st, name)
    summary, t_slug, t_auth = _follow(st, b, host, auth)
    cond("redirect", t_slug == slug and t_auth == auth, f"link ⇒ {summary}; Location carries this tenant and Auth ID "
         f"{t_slug == slug and t_auth == auth}")
    session = b.get(f"https://app.{st.domain}/api/v1/auth/session").json()
    t_id = next((m.get("tenant_id") for m in session.get("memberships") or [] if m.get("tenant_slug") == t_slug), "")
    cond("tenant id", bool(t_id) and t_id == a_id, f"tenant=<slug> ⇒ tenant id through GET /auth/session {t_id == a_id}")
    claim = enrollment._post(st, b, sess, f"https://app.{st.domain}/api/v1/tenants/{t_id}/enrollment/web-auth/claim",
                             {"auth_id": t_auth})
    cj = claim.json()
    running = checks.wait(lambda: _backend_state(st, name) == "Running", 90)
    node = next((n for n in _nodes(st, slug) if str(n.get("id")) == str(cj.get("node_id"))), {})
    cond("claimed", claim.status == 200 and cj.get("status") == "verified" and bool(running)
         and node.get("given_name") == "e2e118-web",
         f"claim ⇒ {claim.status} {cj.get('status')}; client Running {bool(running)}; node renamed to the label "
         f"{node.get('given_name') == 'e2e118-web'}")


def _claim_cli(st: Stack, cond: _Conds, clients: list[str], undo: list) -> None:
    """No enrollment API on this tree: the claim step is the CLI of the stack (headscale auth register) with the Auth ID
    of the Location; proves the client completes after the redirect."""
    b = Browser(st)
    slug = "tenant-b"
    name = _client(st, "e2e118", slug, "e2e118-cli")
    clients.append(name)
    host, auth = _link(st, name)
    summary, t_slug, t_auth = _follow(st, b, host, auth)
    cond("redirect", t_slug == slug and t_auth == auth, f"link ⇒ {summary}; Location carries this tenant and Auth ID "
         f"{t_slug == slug and t_auth == auth}")
    if not t_auth:
        return
    p = st.headscale(t_slug, "auth", "register", "--auth-id", t_auth, "--user", "e2e", check=False)
    running = checks.wait(lambda: _backend_state(st, name) == "Running", 90)
    nodes = [n for n in _nodes(st, t_slug) if n.get("name") == "e2e118-cli"]
    cond("registered", p.returncode == 0 and bool(running) and len(nodes) == 1,
         f"headscale auth register ⇒ rc {p.returncode}; client Running {bool(running)}; node e2e118-cli {len(nodes)}")
    for n in nodes:                                     # the control node leaves the tenant again
        st.headscale(t_slug, "nodes", "delete", "--identifier", str(n["id"]), "--force", check=False)
    gone = checks.wait(lambda: not [n for n in _nodes(st, t_slug) if n.get("name") == "e2e118-cli"], 15)
    cond("cleanup", bool(gone), f"control node deleted {bool(gone)}")


def check_v07(r, st: Stack) -> None:
    cond, clients, undo = _Conds(), [], []
    mode = "API P4-T06" if enrollment is not None else "CLI (API P4-T06 chưa có trên cây)"
    try:
        (_claim_api if enrollment is not None else _claim_cli)(st, cond, clients, undo)
    finally:
        for c in clients:
            st.docker("rm", "-f", c, check=False)
        for step in reversed(undo):         # each step records its own condition; one failing does not skip the next
            try:
                step()
            except (StackError, OSError, ValueError, KeyError) as e:
                cond("cleanup", False, f"cleanup step failed: {type(e).__name__}: {st.redact(str(e))[-200:]}")
    if not cond.conds:
        raise StackError("E2E-118: no step ran")
    cond.report(r, "E2E-118", f"V-07 (functional): client chính thức hoàn tất đăng ký sau claim bắt đầu từ chuyển hướng "
                f"của edge — claim chỉ dùng tenant + auth_id của Location (bước claim: {mode})")


def run_all(r, st: Stack, guarded) -> None:
    guarded(r, "E2E-117", check_redirect, st)
    guarded(r, "E2E-118", check_v07, st)
