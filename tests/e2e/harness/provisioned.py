"""G4b-E1 — inviting members on a tenant JUST PROVISIONED by the Tenant Orchestrator, on the dev/CI stack — FUNCTIONAL
only (§22.1). The realms of the stack's own tenants are rendered (tools/render_idp.py, with SMTP) and their users created
by the harness, so no other case sees a realm the keycloak driver created: G4b-E1 (staging, 2026-11-20) was exactly that
— a realm created by idp.ensure had no smtpServer (the template has none) ⇒ execute-actions-email failed
(`idp_email_failed`), and the Owner invitation of step 16 never created the Owner's IdP account.

  E2E-124  the worker of the stack recreated with the Host Agent and the orchestrator (as tests/g3/g3dev.py: the agent
           built from the tree, hardened like compose mg-agent, its own tenant network pool and run UIDs, a `hosts` row
           of its own region; no backup keys — the case never deprovisions); a Super Admin creates a tenant
           (POST /platform/tenants, driver keycloak) ⇒ tenant.provision succeeds (19 steps) ⇒ the realm the driver
           created has the worker's relay as smtpServer (mailrelay:587, STARTTLS); the Owner invitation of step 16 ran
           member.idp_invite ⇒ Keycloak's e-mail reaches the stand-in Worker through mailrelay ⇒ the Owner follows its
           link (verify e-mail, set a password, enrol TOTP) and signs in on app. ⇒ Tenant Owner of the new tenant; the
           Owner invites an End User through the API ⇒ the same e-mail ⇒ the End User sets up the account and signs in
           ⇒ end_user. Cleaned after the case: the realm deleted, the instance's containers and networks, the agent, its
           root and image removed, the worker recreated without the orchestrator (the database rows go with the stack).

Runs LAST, after E2E-70/71 (it needs only the platform IdP, the Super Admin of E2E-24 and Keycloak, which the restored
database keeps; a provisioning worker before E2E-71 would provision the tenant that case creates in its gap).
Parameters (environment): E2E_AGENT_POOL (tenant networks of the agent, default 10.250.217.0/24 — inside the tenant pool
10.250.0.0/16, outside staging 10.250.0.0/24, e2e 10.250.23x, g3dev 10.250.219.0/24, P3-T07 10.250.224.0/24, agent-it
10.250.240.0/20), E2E_AGENT_RUN_UIDS (39500-39599). Standard library only; passwords, TOTP keys, action-token links,
cookies and the agent token stay in this process (and its redaction set).
"""
from __future__ import annotations

import email
import email.policy
import html
import ipaddress
import json
import os
import pathlib
import re
import secrets
import time
import urllib.parse

import checks
import render_app
from backend import TOTP, Browser, KeycloakAdmin, container, forms, psql
from dualcontrol import invite, psql_one
from idpadmin import admin_unsafe, platform_session
from stack import ALNUM, ROOT, Stack, StackError, log

WORKER_UID, WORKER_GID = 65532, 20003
LINK_RE = re.compile(r"https://auth\.[^\s\"'<>]+/login-actions/action-token\?[^\s\"'<>]+")
# the 'proceed' link of an action-token page — not the language switcher of a realm with i18n (G4b-E14: same path with
# kc_locale=…, which only shows the same page in another language)
PROCEED_RE = re.compile(r'href="((?![^"]*kc_locale=)[^"]*/login-actions/[^"]*)"')
LANG_RE = re.compile(r'<html[^>]*\blang="([^"]+)"')


def params(st: Stack) -> dict:
    pool = ipaddress.ip_network(os.environ.get("E2E_AGENT_POOL", "10.250.217.0/24"))
    taken = [ipaddress.ip_network(n) for n in ("10.250.0.0/24", "10.250.219.0/24", "10.250.224.0/24", "10.250.240.0/20")] + \
            [ipaddress.ip_network(f"10.250.{i}.0/24") for i in range(230, 240)]
    if not pool.subnet_of(ipaddress.ip_network("10.250.0.0/16")) or any(pool.overlaps(n) for n in taken):
        raise StackError("E2E_AGENT_POOL: trong 10.250.0.0/16, ngoài staging, e2e 10.250.23x, g3dev, P3-T07, agent-it")
    lo, hi = (int(x) for x in os.environ.get("E2E_AGENT_RUN_UIDS", "39500-39599").split("-"))
    if not 1000 <= lo < hi or WORKER_UID in range(lo, hi + 1):
        raise StackError("E2E_AGENT_RUN_UIDS: lo-hi, không chứa 65532")
    return {"pool": str(pool), "lo": lo, "hi": hi, "root": pathlib.Path(f"/tmp/{st.prefix}-agentroot"),
            "region": f"{st.prefix}-r", "image": f"{st.prefix}-agent:e2e"}


def override(st: Stack) -> pathlib.Path:
    return st.work / "render" / "e2e124" / "compose.orchestrator.yaml"


def compose_with_override(st: Stack, *args: str, **kw):
    return st.docker("compose", "-p", st.prefix, "--project-directory", str(ROOT), "--env-file", str(st.work / "stack.env"),
                     *st.compose_files(), "-f", str(override(st)), *args, **kw)


def check_free(st: Stack, cidr: str) -> None:
    mine = ipaddress.ip_network(cidr)
    ids = st.docker("network", "ls", "-q").stdout.split()
    for line in st.docker("network", "inspect", "-f", "{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}", *ids).stdout.splitlines():
        name, *subs = line.split()
        for s in subs:
            try:
                n = ipaddress.ip_network(s)
            except ValueError:
                continue
            if n.version == 4 and n.overlaps(mine) and not name.startswith((f"{st.prefix}-", f"mg-t-{st.prefix}-")):
                raise StackError(f"network {name} {s} chồng E2E_AGENT_POOL {cidr}")


# ---------------------------------------------------------------------------------------------------- orchestrator
def start_orchestrator(st: Stack, p: dict) -> None:
    """The Host Agent built from the tree + the worker recreated with MG_AGENT_*/MG_PROVISION_* (as g3dev.up)."""
    check_free(st, p["pool"])
    root = p["root"]
    token = "".join(secrets.choice(ALNUM) for _ in range(40))
    st.secret_values.add(token)
    st.docker("run", "--rm", "--network", "none", "-v", "/tmp:/hosttmp", st.images["alpine"], "sh", "-ec",
              f"rm -rf /hosttmp/{root.name}; mkdir -p /hosttmp/{root.name}")
    st.docker("run", "--rm", "-i", "--network", "none", "-v", f"{root}:{root}", st.images["alpine"], "sh", "-ec",
              f"cd {root}; install -d -o 0 -g 0 -m 0755 tenants cfg; install -d -o 0 -g 0 -m 0700 backups backups/tenants; "
              f"install -d -o 0 -g {WORKER_GID} -m 0750 run; umask 077; cat > cfg/agent_token; "
              f"chown 0:{WORKER_GID} cfg/agent_token; chmod 0440 cfg/agent_token; "
              f"printf '%s\\n' '{st.images['headscale']}' > cfg/allowlist; chmod 0644 cfg/allowlist", input=token)
    t0 = time.time()
    st.docker("build", "-q", "-f", str(ROOT / "infrastructure" / "docker" / "agent" / "Dockerfile"), "--build-arg",
              "VERSION=e2e124", "--build-arg", "COMMIT=dev", "--label", "meshguard.role=e2e", "-t", p["image"], str(ROOT),
              timeout=1800)
    helper_image = st.docker("image", "inspect", "-f", "{{.Id}}", p["image"]).stdout.strip()
    log(f"E2E-124: build agent {helper_image[:19]}… trong {time.time() - t0:.0f} s")
    st.docker("rm", "-f", st.name("agent"), check=False)
    env = {"MG_ENV": "ci", "MG_LOG_LEVEL": "info", "MG_BASE_DOMAIN": st.domain, "MG_AGENT_DRIVER": "compose",
           "MG_AGENT_SOCKET": f"{root}/run/agent.sock", "MG_AGENT_SOCKET_GID": str(WORKER_GID),
           "MG_AGENT_PEER_UIDS": str(WORKER_UID), "MG_AGENT_TOKEN_FILE": f"{root}/cfg/agent_token",
           "MG_AGENT_IMAGE_ALLOWLIST_FILE": f"{root}/cfg/allowlist", "MG_AGENT_TENANTS_DIR": f"{root}/tenants",
           "MG_AGENT_BACKUPS_DIR": f"{root}/backups/tenants", "MG_AGENT_RUN_UID_RANGE": f"{p['lo']}-{p['hi']}",
           "MG_AGENT_TENANT_NET_POOL": p["pool"], "MG_AGENT_PUBLIC_ENTRY_IPV4": st.edge_ip,
           "MG_AGENT_EDGE_CONTAINER": st.name("edge"), "MG_AGENT_EDGE_NETWORK": st.name("edge"),
           "MG_AGENT_EDGE_SUPERVISOR_INTERVAL": "5s", "MG_AGENT_HELPER_IMAGE": helper_image,
           "MG_AGENT_COMPOSE_BIN": "/usr/local/bin/docker-compose",
           "DOCKER_HOST": "unix:///var/run/docker.sock", "DOCKER_CONFIG": "/tmp/docker"}
    st.docker("run", "-d", "--name", st.name("agent"), "--label", "meshguard.role=e2e", "--network", "none", "--read-only",
              "--tmpfs", "/tmp:size=16m,mode=1777", "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "FOWNER",
              "--cap-add", "DAC_OVERRIDE", "--security-opt", "no-new-privileges", "--user", "0:0", "--pids-limit", "256",
              "--memory", "512m", "-v", "/var/run/docker.sock:/var/run/docker.sock", "-v", f"{root}:{root}",
              *[x for k, v in env.items() for x in ("-e", f"{k}={v}")], p["image"])
    if not checks.wait(lambda: st.docker("exec", st.name("agent"), "/usr/local/bin/meshguard-agent", "healthcheck",
                                         check=False).returncode == 0, 60):
        logs = st.docker("logs", "--tail", "40", st.name("agent"), check=False)
        raise StackError("agent không healthy: " + st.redact(logs.stdout + logs.stderr)[-1500:])
    psql(st, "INSERT INTO hosts (id, name, region, run_uid_range, tenant_net_pool, public_entry) VALUES "
             f"(gen_random_uuid(), '{st.prefix}-e2e124', '{p['region']}', int4range({p['lo']}, {p['hi']}, '[]'), "
             f"'{p['pool']}'::cidr, jsonb_build_object('ipv4', '{st.edge_ip}', 'mode', 'direct')) ON CONFLICT DO NOTHING")
    digest, version = render_app.headscale_runtime()
    ov = override(st)
    ov.parent.mkdir(parents=True, exist_ok=True)
    ov.write_text("\n".join([
        "# E2E-124 (tests/e2e/harness/provisioned.py): the worker of the stack with the Host Agent and the orchestrator",
        "services:", "  worker:", "    environment:",
        "      MG_AGENT_SOCKET: /run/meshguard/agent.sock", "      MG_AGENT_TOKEN_FILE: /run/secrets/agent_token",
        f"      MG_PROVISION_HEADSCALE_DIGEST: \"{digest}\"", f"      MG_PROVISION_HEADSCALE_VERSION: \"{version}\"",
        f"      MG_PROVISION_NAMESERVERS: \"{st.env['MG_TENANT_NAMESERVERS']}\"",
        "      MG_PROVISION_DNS_CHECK: skip", f"      MG_PROVISION_EDGE_ADDR: \"{st.edge_ip}:443\"",
        f"      MG_PROBER_URL: \"http://{st.prober_admin_ip}:8080\"",
        "    secrets:", "      - {source: e2e124_agent_token, target: agent_token}",
        "    volumes:", f"      - {{type: bind, source: {root}/run, target: /run/meshguard, read_only: true}}",
        "secrets:", f"  e2e124_agent_token: {{file: {root}/cfg/agent_token}}", ""]), encoding="utf-8")
    compose_with_override(st, "up", "-d", "--wait", "--wait-timeout", "240", "worker", timeout=300)
    wl = st.docker("logs", "--since", "2m", container(st, "worker"), check=False)
    if "tenant orchestrator configured" not in wl.stdout + wl.stderr:
        raise StackError("worker tạo lại nhưng không thấy 'tenant orchestrator configured'")


def stop_orchestrator(st: Stack, p: dict, slug: str) -> list[str]:
    """Everything E2E-124 created outside the database; returns what could not be removed."""
    left: list[str] = []
    if slug:
        try:
            KeycloakAdmin(st)._call("DELETE", f"/admin/realms/{slug}")
        except Exception as e:  # noqa: BLE001 — cleanup goes on
            left.append(f"realm {slug}: {type(e).__name__}")
    names = st.docker("ps", "-a", "--format", "{{.Names}}", check=False).stdout.split()
    mine = [n for n in names if n.startswith((f"mg-hs-{st.prefix}-", f"mg-helper-{st.prefix}-"))] + \
           ([st.name("agent")] if st.name("agent") in names else [])
    if mine:
        st.docker("rm", "-f", *mine, check=False)
    nets = [n for n in st.docker("network", "ls", "--format", "{{.Name}}", check=False).stdout.split()
            if n.startswith(f"mg-t-{st.prefix}-")]
    for n in nets:
        st.docker("network", "disconnect", "-f", n, st.name("edge"), check=False)
    if nets:
        st.docker("network", "rm", *nets, check=False)
    st.docker("run", "--rm", "--network", "none", "-v", "/tmp:/hosttmp", st.images["alpine"], "sh", "-c",
              f"rm -rf /hosttmp/{p['root'].name}", check=False)
    st.docker("image", "rm", "-f", p["image"], check=False)
    if (st.work / "stack.env").exists():                 # the worker as before: no Host Agent, no orchestrator
        st.compose("up", "-d", "--wait", "--wait-timeout", "240", "--force-recreate", "worker", check=False, timeout=300)
    override(st).unlink(missing_ok=True)
    names = st.docker("ps", "-a", "--format", "{{.Names}}", check=False).stdout.split()
    left += [n for n in names if n.startswith((f"mg-hs-{st.prefix}-", f"mg-helper-{st.prefix}-", st.name("agent")))]
    left += [n for n in st.docker("network", "ls", "--format", "{{.Name}}", check=False).stdout.split()
             if n.startswith(f"mg-t-{st.prefix}-")]
    return left


# ---------------------------------------------------------------------------------------------------- e-mail + Keycloak
def action_link(st: Stack, to: str, seen: set[str], timeout: float = 180) -> tuple[str, dict]:
    """The required-actions link of the first new e-mail to `to` that holds one (the stand-in Worker keeps the raw
    message under <work>/fakeworker/bodies — DEVSERVER_BODIES); the platform's own invitation e-mail has none."""
    def find():
        f = st.work / "fakeworker" / "sent.jsonl"
        rows = [json.loads(x) for x in f.read_text(encoding="utf-8").splitlines() if x.strip()] if f.exists() else []
        for row in rows:
            if row.get("id") in seen or str(row.get("to", "")).lower() != to.lower():
                continue
            raw = st.helper(f"cat /w/fakeworker/bodies/{row['id']}.eml", f"{st.work}:/w").stdout
            seen.add(row["id"])
            msg = email.message_from_string(raw, policy=email.policy.default)
            texts = [part.get_content() for part in msg.walk() if part.get_content_maintype() == "text"]
            for text in texts:
                m = LINK_RE.search(html.unescape(text))
                if m:
                    return m.group(0), row
        return None
    got = checks.wait(find, timeout, 2)
    if not got:
        raise StackError(f"không có thư thiết lập tài khoản (Keycloak) tới {to} sau {timeout:.0f} s")
    link, row = got
    st.secret_values.add(link)
    st.secret_values.add(urllib.parse.parse_qs(urllib.parse.urlsplit(link).query).get("key", [""])[0])
    return link, row


def keycloak_pages(st: Stack, b: Browser, url: str, user: dict, otp: TOTP, portal_host: str,
                   next_link=None, langs: list[str] | None = None) -> tuple[str, list[str]]:
    """Drive Keycloak from url — an action-token link or an authorization URL — through every page an invited person
    meets: the 'proceed' page of the action token, e-mail verification (next_link() = the link of the verification
    e-mail Keycloak sent), profile, new password, TOTP enrolment, password + OTP; returns the
    redirect to the Portal ("" when the flow ended on Keycloak's own 'account updated' page) and the steps. langs
    collects the language (html lang) of every page shown (G4b-E14)."""
    steps: list[str] = []
    r = b.get(url)
    for _ in range(16):
        if r.status in (302, 303):
            loc = urllib.parse.urljoin(url, r.header("Location"))
            if urllib.parse.urlsplit(loc).hostname == portal_host:
                return loc, steps
            r, url = b.get(loc), loc
            continue
        page = r.body.decode("utf-8", "replace")
        if r.status != 200:
            raise StackError(f"Keycloak HTTP {r.status} after {steps}")
        if langs is not None:
            m = LANG_RE.search(page)
            langs.append(m.group(1) if m else "")
        if "alert-error" in page or "kc-error-message" in page:
            raise StackError(f"Keycloak error page after {steps}")
        fs = forms(page)

        def post(f: dict, step: str, extra: dict):
            steps.append(step)
            return b.request("POST", html.unescape(f["action"]), urllib.parse.urlencode({**f["inputs"], **extra}).encode(),
                             {"Content-Type": "application/x-www-form-urlencoded"})
        f = next((x for x in fs if "password-new" in x["inputs"]), None)
        if f:
            r = post(f, "update_password", {"password-new": user["password"], "password-confirm": user["password"]})
            continue
        f = next((x for x in fs if "totpSecret" in x["inputs"]), None)
        if f:
            otp.key = f["inputs"]["totpSecret"].encode()
            st.secret_values.add(f["inputs"]["totpSecret"])
            r = post(f, "configure_totp", {"totp": otp.code(), "userLabel": "e2e"})
            continue
        f = next((x for x in fs if "firstName" in x["inputs"] or "lastName" in x["inputs"]), None)
        if f:
            r = post(f, "profile", {"firstName": f["inputs"].get("firstName") or "E2E",
                                    "lastName": f["inputs"].get("lastName") or "Invited"})
            continue
        f = next((x for x in fs if "password" in x["inputs"]), None)
        if f:
            r = post(f, "password", {"username": user["username"], "password": user["password"]}
                     if "username" in f["inputs"] else {"password": user["password"]})
            continue
        f = next((x for x in fs if "otp" in x["inputs"]), None)
        if f:
            r = post(f, "otp", {"otp": otp.code()})
            continue
        if "execution=VERIFY_EMAIL" in page and next_link is not None:
            steps.append("verify_email")
            url = next_link()
            r = b.get(url)
            continue
        m = PROCEED_RE.search(page)
        if m:
            steps.append("proceed")
            url = html.unescape(m.group(1))
            r = b.get(url)
            continue
        if not fs:
            steps.append("done")
            return "", steps
        raise StackError(f"unexpected Keycloak page after {steps} ({len(fs)} forms)")
    raise StackError(f"too many Keycloak steps: {steps}")


def tenant_login(st: Stack, slug: str, user: dict, otp: TOTP, ui_locales: str = "",
                 langs: list[str] | None = None) -> tuple[Browser, dict, list[str]]:
    b, host = Browser(st), f"app.{st.domain}"
    q = f"scope=tenant&tenant={slug}" + (f"&ui_locales={ui_locales}" if ui_locales else "")
    start = b.get(f"https://{host}/api/v1/auth/login?{q}")
    if start.status != 302:
        raise StackError(f"GET /auth/login {slug}: HTTP {start.status}")
    cb, steps = keycloak_pages(st, b, start.header("Location"), user, otp, host, langs=langs)
    if not cb:
        raise StackError(f"Keycloak did not return to the Portal: {steps}")
    r = b.get(cb)
    if r.status != 302:
        raise StackError(f"callback {slug}: HTTP {r.status} {r.json().get('code')}")
    s = b.get(f"https://{host}/api/v1/auth/session")
    sess = s.json()
    st.secret_values.add(sess.get("csrf_token", ""))
    return b, sess, steps


def wait_idp_invite(st: Stack, inv_id: str, timeout: float = 180) -> str:
    def done():
        v = psql_one(st, "SELECT status || '/' || COALESCE(error ->> 'code', '') FROM provisioning_jobs "
                     f"WHERE kind = 'member.idp_invite' AND dedupe_key = 'invitation:{inv_id}:idp_invite'")
        return v if v.split("/")[0] in ("succeeded", "failed", "cancelled", "failed_resumable") else None
    return checks.wait(done, timeout, 2) or psql_one(
        st, f"SELECT status FROM provisioning_jobs WHERE dedupe_key = 'invitation:{inv_id}:idp_invite'") or "no job"


def onboard(st: Stack, slug: str, tid: str, inv_id: str, addr: str, seen: set[str], ui_locales: str) -> dict:
    """member.idp_invite of the invitation ⇒ Keycloak's e-mail ⇒ the person sets the account up ⇒ signs in from the
    Portal in language ui_locales (G4b-E14: the language of the setup pages — the realm's default, no ui_locales on an
    e-mailed link — and of the sign-in pages are recorded)."""
    out = {"job": wait_idp_invite(st, inv_id)}
    user = {"username": addr, "password": secrets.token_urlsafe(18) + "Aa1!"}
    st.secret_values.add(user["password"])
    otp = TOTP()
    link, row = action_link(st, addr, seen)
    out["mail_from"] = row.get("header_from", "")
    setup_langs: list[str] = []
    login_langs: list[str] = []
    _, out["setup"] = keycloak_pages(st, Browser(st), link, user, otp, f"app.{st.domain}",
                                     next_link=lambda: action_link(st, addr, seen)[0], langs=setup_langs)
    b, sess, out["login"] = tenant_login(st, slug, user, otp, ui_locales, login_langs)
    out["setup_lang"], out["login_lang"] = sorted(set(setup_langs)), sorted(set(login_langs))
    out["roles"] = sorted(m.get("role", "") for m in sess.get("memberships", []) if m.get("tenant_id") == tid)
    out["browser"], out["session"] = b, sess
    return out


# ---------------------------------------------------------------------------------------------------- E2E-124
def check_provisioned_invite(r, st: Stack) -> None:
    sa = getattr(st, "platform_sa", None)
    if not sa:
        raise StackError("no Super Admin of E2E-24 (st.platform_sa)")
    p = params(st)
    slug = ""
    try:
        start_orchestrator(st, p)
        b, sess = platform_session(st, sa)
        api = f"https://admin.{st.domain}/api/v1"
        slug = f"{st.prefix}-{secrets.token_hex(2)}"
        owner = f"owner-{secrets.token_hex(3)}@{slug}.example.test"
        body = json.dumps({"slug": slug, "name": "E2E-124", "plan_key": "standard", "owner_email": owner,
                           "deployment_region": p["region"], "identity_provider": {"driver": "keycloak"}}).encode()
        created = b.request("POST", f"{api}/platform/tenants", body,
                            admin_unsafe(st, sess, **{"Idempotency-Key": "e2e124-" + secrets.token_hex(8)}))
        job = created.json()
        tid, jid = job.get("tenant_id", ""), job.get("id", "")
        if created.status != 202 or not jid:
            raise StackError(f"POST /platform/tenants: HTTP {created.status} {job.get('code')}")
        t0 = time.time()

        def finished():
            j = b.get(f"{api}/platform/jobs/{jid}").json()
            return j if j.get("status") in ("succeeded", "failed", "failed_resumable", "rolled_back", "cancelled") else None
        end = checks.wait(finished, 900, 5) or {}
        log(f"E2E-124: tenant.provision {end.get('status')} sau {time.time() - t0:.0f} s")
        if end.get("status") != "succeeded":
            steps = [(s.get("name"), s.get("status")) for s in end.get("steps", []) if s.get("status") != "succeeded"]
            raise StackError(f"tenant.provision {end.get('status')} {end.get('error')} {steps}")
        realm = KeycloakAdmin(st)._call("GET", f"/admin/realms/{slug}")
        smtp = realm.get("smtpServer") or {}
        driver_made = (realm.get("attributes") or {}).get("meshguard.idp_id") == psql_one(
            st, f"SELECT id FROM identity_providers WHERE tenant_id = '{tid}'")
        owner_inv = psql_one(st, f"SELECT id FROM tenant_invitations WHERE tenant_id = '{tid}' AND email = '{owner}'")
        seen: set[str] = set()
        o = onboard(st, slug, tid, owner_inv, owner, seen, "en")
        ob, osess = o.pop("browser"), o.pop("session")
        e: dict = {}
        if o["roles"] == ["tenant_owner"]:
            user_addr = f"user-{secrets.token_hex(3)}@{slug}.example.test"
            res = invite(st, ob, osess, tid, user_addr, "end_user")
            if res.status == 201:
                e = onboard(st, slug, tid, res.json().get("id", ""), user_addr, seen, "vi")
                e.pop("browser")
                e.pop("session")
            else:
                e = {"invite": f"HTTP {res.status} {res.json().get('code')}"}
        i18n = (realm.get("internationalizationEnabled"), sorted(realm.get("supportedLocales") or []),
                realm.get("defaultLocale"))
        ok = (smtp.get("host") == "mailrelay" and smtp.get("port") == "587" and smtp.get("starttls") == "true"
              and smtp.get("auth", "false") == "false" and driver_made
              and i18n == (True, ["en", "vi"], "vi") and o.get("setup_lang") == ["vi"] and o.get("login_lang") == ["en"]
              and e.get("login_lang") == ["vi"]
              and o["job"] == "succeeded/" and "update_password" in o["setup"] and "configure_totp" in o["setup"]
              and o["roles"] == ["tenant_owner"]
              and e.get("job") == "succeeded/" and "update_password" in e.get("setup", []) and e.get("roles") == ["end_user"])
        r.add("E2E-124", "G4b-E1: tenant vừa provision qua orchestrator (realm do idp.ensure tạo) ⇒ realm có smtpServer = relay "
              "của worker (mailrelay:587 STARTTLS); lời mời Owner bước 16 chạy member.idp_invite ⇒ thư Keycloak qua mailrelay "
              "tới Worker giả ⇒ Owner đặt mật khẩu + TOTP từ link, đăng nhập app. = tenant_owner; Owner mời End User qua API "
              "⇒ cùng đường ⇒ End User đăng nhập = end_user; G4b-E14: realm bật i18n (vi, en; mặc định vi) ⇒ trang thiết lập "
              "từ link thư tiếng Việt, trang đăng nhập theo ui_locales của Portal (Owner en, End User vi)", ok,
              f"provision {end.get('status')} ({time.time() - t0:.0f} s); realm smtp {smtp.get('host')}:{smtp.get('port')} "
              f"starttls={smtp.get('starttls')} driver_realm={driver_made} i18n={i18n}; Owner: job {o['job']}, from "
              f"{o['mail_from']}, setup {o['setup']} lang {o.get('setup_lang')}, login {o['login']} lang "
              f"{o.get('login_lang')}, roles {o['roles']}; End User: job {e.get('job')}, setup {e.get('setup')}, login lang "
              f"{e.get('login_lang')}, roles {e.get('roles')} {e.get('invite', '')}", limit=1100)
    finally:
        left = stop_orchestrator(st, p, slug)
        if left:
            log(f"E2E-124: dọn còn sót {left}")



def run_all(r, st: Stack, guarded) -> None:
    guarded(r, "E2E-124", check_provisioned_invite, st)
