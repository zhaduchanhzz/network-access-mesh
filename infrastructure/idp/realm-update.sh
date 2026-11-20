#!/bin/bash
# G2 vòng 2 (docs/planning/evidence/G2-security-review.md, "Sửa sau vòng 2") — đưa các realm ĐANG CHẠY về template mới và
# gia cố realm master. `--import-realm` bỏ qua realm đã tồn tại (IGNORE_EXISTING), nên realm import từ template cũ
# không nhận thay đổi của template; script này áp đúng các khóa G2 vòng 2 đổi:
#   realm platform/tenant-*: passwordPolicy (+ passwordBlacklist — A-3), attributes.meshguard.template, smtpServer
#     (P3-T05b-mail: Mailpit ⇄ mailrelay:587 STARTTLS theo MG_IDP_MAIL_SINK của bản render — không bao giờ mật khẩu),
#     i18n (G4b-E14: internationalizationEnabled, supportedLocales vi/en, defaultLocale — trang đăng nhập theo ui_locales
#     của Portal; bản dịch vi có sẵn trong theme của Keycloak 26.8.2);
#     mg-portal: post.logout.redirect.uris (A-1), protocol mapper amr (A-6);
#     flow mg-browser-forms: authenticatorConfig amr của bước mật khẩu (pwd) và OTP (otp) (A-6);
#     required action UPDATE_PASSWORD, CONFIGURE_TOTP, delete_credential, webauthn-register(-passwordless),
#     CONFIGURE_RECOVERY_AUTHN_CODES: config max_auth_age = 0 (A-4)
#   realm master (A-8): brute force bật (khóa TẠM như realm khác), passwordPolicy như realm khác, login/admin event bật.
#     Giữ nguyên: sslRequired=external (kcadm gọi http://localhost:8080 trong container), admin-cli + password grant (kcadm
#     dùng nó), admin khởi tạo (thay bằng admin có OTP: việc còn mở của P3-T15 — rủi ro còn lại ghi ở evidence).
#   P3-T15 (console quản trị chỉ ở origin admin, job idp.audit_sync):
#     realm master: attributes.frontendUrl = https://admin.<domain> — console, trang đăng nhập và token của realm master
#       phát URL của origin admin (edge chỉ phục vụ console ở đó, sau forward_auth); issuer của token master đổi theo
#       (token cũ bị Admin API từ chối 401 một lần, driver tự lấy token mới);
#     danh tính provisioning (client mg-provisioner, MG_IDP_PROVISIONER_CLIENT): thêm đúng role view-events của
#       master-realm và của realm platform (đọc login/admin event cho idp.audit_sync) — không gỡ role nào; chưa có
#       client (idp-bootstrap chưa chạy) ⇒ bỏ qua.
# Giá trị muốn có đọc từ realm ĐÃ RENDER bằng tools/render_idp.py của commit mới (/opt/meshguard/core/idp/realms/<realm>.json,
# đã qua check_realm lúc render); domain, idp id… không nằm trong script. Sau khi áp: in diff trước → sau (không có
# secret nào trong các khóa này) rồi chạy check_realm (tools/render_idp.py) trên bản export của chính Keycloak.
#
#   sudo bash infrastructure/idp/realm-update.sh [--check] [<realm> …]      (mặc định: mọi file trong thư mục realm đã render)
#     --check   chỉ in diff, không ghi; exit 3 nếu còn thay đổi chờ áp (dùng làm kiểm sau triển khai)
#
# Điều kiện: image idp mới (có /opt/keycloak/mg/password-blacklists/mg-passwords-v1.txt) đang chạy — với image cũ Keycloak
# từ chối passwordBlacklist(mg-passwords-v1.txt) và script dừng trước mọi ghi (bước kiểm đầu tiên). Chạy từ thư mục gốc
# của repo (cần tools/render_idp.py) trên host, như user-id.sh: kcadm chạy TRONG container idp, mật khẩu admin khởi tạo đọc
# từ secret đã mount (/run/secrets/keycloak.conf) vào biến môi trường của riêng tiến trình kcadm — không in ra, không nằm
# trong argv, không qua host. Payload (JSON không secret) đi qua stdin của docker exec. Chạy lại an toàn (idempotent).
# Biến: MG_IDP_PROJECT (mặc định mg-idp), MG_IDP_REALMS (mặc định /opt/meshguard/core/idp/realms), DOCKER (mặc định docker).
# Hoàn tác: mục "Cập nhật sau G2 vòng 2" của docs/operations/deploy-backend.md (giá trị trước nằm trong diff đã in).
set -euo pipefail
cd "$(dirname "$0")/../.."
exec python3 - "$@" <<'PY'
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys

sys.path.insert(0, "tools")
import render_idp  # noqa: E402 — check_realm, BLOCKLIST_FILE, REAUTH_ACTIONS

PROJECT = os.environ.get("MG_IDP_PROJECT", "mg-idp")
PROVISIONER = os.environ.get("MG_IDP_PROVISIONER_CLIENT", "mg-provisioner")
VIEW_EVENTS = "view-events"
REALMS_DIR = pathlib.Path(os.environ.get("MG_IDP_REALMS", "/opt/meshguard/core/idp/realms"))
DOCKER = shlex.split(os.environ.get("DOCKER", "docker"))
FORMS = "mg-browser-forms"
# realm master (A-8): khóa tạm như các realm khác (render_idp.check_realm), event để rà soát (P3-T15)
MASTER = {"bruteForceProtected": True, "permanentLockout": False, "failureFactor": 5, "waitIncrementSeconds": 60,
          "maxFailureWaitSeconds": 900, "quickLoginCheckMilliSeconds": 1000, "minimumQuickLoginWaitSeconds": 60,
          "maxDeltaTimeSeconds": 43200, "eventsEnabled": True, "eventsExpiration": 2592000,
          "adminEventsEnabled": True, "adminEventsDetailsEnabled": True}


def die(msg: str, code: int = 1) -> None:
    print(f"realm-update: {msg}", file=sys.stderr)
    sys.exit(code)


args = sys.argv[1:]
check_only = "--check" in args
realms = [a for a in args if a != "--check"]
if any(not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", r) for r in realms) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", PROJECT) \
        or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", PROVISIONER):
    die("tham số không hợp lệ (realm: [a-z0-9-]; MG_IDP_PROJECT, MG_IDP_PROVISIONER_CLIENT: [a-z0-9_-])", 2)
if not realms:
    realms = sorted(p.stem for p in REALMS_DIR.glob("*.json"))
want = {}
for r in realms:
    f = REALMS_DIR / f"{r}.json"
    if not f.is_file():
        die(f"không có realm đã render {f} — render lại bằng tools/render_idp.py của commit mới", 2)
    want[r] = json.loads(f.read_text(encoding="utf-8"))
    if want[r].get("realm") != r:
        die(f"{f}: realm {want[r].get('realm')!r} khác tên file", 2)

ids = subprocess.run([*DOCKER, "ps", "-q", "-f", f"label=com.docker.compose.project={PROJECT}", "-f",
                      "label=com.docker.compose.service=idp"], capture_output=True, text=True, check=True).stdout.split()
if len(ids) != 1:
    die(f"cần đúng một container idp đang chạy của project {PROJECT} (thấy {len(ids)})")
CID = ids[0]

LOGIN = r'''set -euo pipefail
cfg=$(mktemp /tmp/kcadm.XXXXXX)
trap 'rm -f "$cfg"' EXIT
conf=/run/secrets/keycloak.conf
admin=$(sed -n 's/^bootstrap-admin-username=//p' "$conf")
KC_CLI_PASSWORD=$(sed -n 's/^bootstrap-admin-password=//p' "$conf") \
  /opt/keycloak/bin/kcadm.sh config credentials --config "$cfg" --server http://localhost:8080 --realm master \
  --user "$admin" >/dev/null </dev/null
kc() { /opt/keycloak/bin/kcadm.sh "$@" --config "$cfg"; }
'''


def kc_session(body: str) -> str:
    """Run kcadm commands inside the idp container (script on stdin: no argument carries anything)."""
    p = subprocess.run([*DOCKER, "exec", "-i", CID, "bash", "-s"], input=LOGIN + body, capture_output=True, text=True,
                       timeout=600)
    if p.returncode != 0:
        die(f"kcadm trong container idp thất bại (exit {p.returncode}): {p.stderr.strip()[-800:]}")
    return p.stdout


def get_many(reqs: dict[str, str], verb: str = "get") -> dict:
    """reqs: key → kcadm arguments of a GET (or of `verb`, e.g. get-roles); returns key → parsed JSON."""
    # kcadm prints JSON without a final newline: each marker starts on a line of its own
    body = "".join(f"echo; echo '@@{k}'\nkc {verb} {a} </dev/null\n" for k, a in reqs.items())
    out, cur, res = kc_session(body), None, {}
    for line in out.splitlines(keepends=True):
        if line.startswith("@@") and line.strip()[2:] in reqs:
            cur = line.strip()[2:]
            res[cur] = ""
        elif cur:
            res[cur] += line
    return {k: json.loads(v) if v.strip() else None for k, v in res.items()}


def q(s: str) -> str:
    return shlex.quote(s)


def payload(cmd: str, obj) -> str:
    return f"kc {cmd} -f - <<'MGJSON'\n{json.dumps(obj, ensure_ascii=False)}\nMGJSON\n"


def smtp_norm(smtp) -> str:
    """smtpServer comparable between the rendered realm and Keycloak's answer: string values, no empty value, no
    (masked) password — the templates never carry one (check_realm)."""
    return json.dumps({k: str(v) for k, v in (smtp or {}).items() if k != "password" and v not in ("", None)}, sort_keys=True)


def i18n_norm(rep) -> str:
    """i18n of a realm comparable between the rendered realm and Keycloak's answer (G4b-E14; locales as a set)."""
    return json.dumps({"internationalizationEnabled": bool(rep.get("internationalizationEnabled")),
                       "supportedLocales": sorted(rep.get("supportedLocales") or []),
                       "defaultLocale": rep.get("defaultLocale") or None}, sort_keys=True)


def snapshot(r: str) -> dict:
    """The live values this script manages (and nothing else) of realm r."""
    first = get_many({"realm": f"realms/{q(r)}", "portal": f"clients -r {q(r)} -q clientId=mg-portal",
                      "execs": f"authentication/flows/{FORMS}/executions -r {q(r)}"})
    if not first.get("realm"):
        die(f"realm {r} không tồn tại ở Keycloak")
    portal = (first["portal"] or [{}])[0]
    reqs = {f"ra:{a}": f"authentication/required-actions/{q(a)}/config -r {q(r)}" for a in render_idp.REAUTH_ACTIONS}
    if portal.get("id"):
        reqs["mappers"] = f"clients/{q(portal['id'])}/protocol-mappers/models -r {q(r)}"
    for e in first["execs"] or []:
        if e.get("authenticationConfig"):
            reqs[f"cfg:{e['providerId']}"] = f"authentication/config/{q(e['authenticationConfig'])} -r {q(r)}"
    more = get_many(reqs)
    s = {"passwordPolicy": first["realm"].get("passwordPolicy"), "smtpServer": smtp_norm(first["realm"].get("smtpServer")),
         "i18n": i18n_norm(first["realm"]),
         "attributes.meshguard.template": (first["realm"].get("attributes") or {}).get("meshguard.template"),
         "mg-portal.post.logout.redirect.uris": (portal.get("attributes") or {}).get("post.logout.redirect.uris"),
         "mg-portal.protocolMappers": sorted((m["name"], m["protocolMapper"], json.dumps(m.get("config", {}), sort_keys=True))
                                             for m in more.get("mappers") or [])}
    for e in first["execs"] or []:
        if e.get("providerId") in render_idp.AMR_REFS:
            cfg = more.get(f"cfg:{e['providerId']}") or {}
            s[f"{FORMS}.{e['providerId']}.authenticatorConfig"] = (cfg.get("alias"), json.dumps(cfg.get("config", {}), sort_keys=True))
    for a in render_idp.REAUTH_ACTIONS:
        s[f"requiredAction.{a}.config"] = json.dumps((more.get(f"ra:{a}") or {}).get("config", {}), sort_keys=True)
    s["_portal"] = portal
    s["_ids"] = {"portal": portal.get("id"), "execs": {e["providerId"]: (e["id"], e.get("authenticationConfig"))
                                                      for e in first["execs"] or [] if e.get("providerId") in render_idp.AMR_REFS},
                 "mappers": {m["name"]: m["id"] for m in more.get("mappers") or []}}
    return s


def desired(r: str) -> dict:
    rep = want[r]
    portal = next(c for c in rep["clients"] if c["clientId"] == render_idp.PORTAL)
    cfgs = {c["alias"]: c for c in rep.get("authenticatorConfig", [])}
    flow = next(f for f in rep["authenticationFlows"] if f["alias"] == FORMS)
    d = {"passwordPolicy": rep["passwordPolicy"], "smtpServer": smtp_norm(rep.get("smtpServer")), "i18n": i18n_norm(rep),
         "attributes.meshguard.template": rep["attributes"]["meshguard.template"],
         "mg-portal.post.logout.redirect.uris": portal["attributes"]["post.logout.redirect.uris"],
         "mg-portal.protocolMappers": sorted((m["name"], m["protocolMapper"], json.dumps(m.get("config", {}), sort_keys=True))
                                             for m in portal.get("protocolMappers", []))}
    for e in flow["authenticationExecutions"]:
        if e.get("authenticator") in render_idp.AMR_REFS:
            c = cfgs[e["authenticatorConfig"]]
            d[f"{FORMS}.{e['authenticator']}.authenticatorConfig"] = (c["alias"], json.dumps(c["config"], sort_keys=True))
    ra = {a["alias"]: a for a in rep["requiredActions"]}
    for a in render_idp.REAUTH_ACTIONS:
        d[f"requiredAction.{a}.config"] = json.dumps(ra[a].get("config", {}), sort_keys=True)
    return d


def plan(r: str, live: dict, d: dict) -> tuple[list[str], str]:
    rep, ids, changes, body = want[r], live["_ids"], [], ""
    portal = next(c for c in rep["clients"] if c["clientId"] == render_idp.PORTAL)
    if not ids["portal"]:
        die(f"{r}: không có client mg-portal — realm không phải của MeshGuard?")
    upd = {}
    if live["passwordPolicy"] != d["passwordPolicy"]:
        upd["passwordPolicy"] = d["passwordPolicy"]
    if live["attributes.meshguard.template"] != d["attributes.meshguard.template"]:
        cur = get_many({"r": f"realms/{q(r)}"})["r"].get("attributes") or {}
        upd["attributes"] = {**cur, "meshguard.template": d["attributes.meshguard.template"]}
    if live["smtpServer"] != d["smtpServer"]:   # P3-T05b-mail: Mailpit ⇄ mailrelay ⇄ none, as rendered (never a password)
        upd["smtpServer"] = json.loads(d["smtpServer"])
    if live["i18n"] != d["i18n"]:   # G4b-E14: the login pages in the Portal's language (ui_locales)
        upd.update({k: v for k, v in json.loads(d["i18n"]).items() if v is not None})
    if upd:
        body += payload(f"update realms/{q(r)}", upd)
        changes += [k for k in ("passwordPolicy", "smtpServer", "i18n", "attributes.meshguard.template") if live[k] != d[k]]
    if live["mg-portal.post.logout.redirect.uris"] != d["mg-portal.post.logout.redirect.uris"]:
        # the FULL current representation with the attribute set (never a partial PUT: Keycloak would derive webOrigins
        # from the redirect URIs — see putClient of internal/idp/keycloak); mappers have their own endpoint
        full = dict(live["_portal"])
        for k in ("protocolMappers", "access", "authorizationSettings"):
            full.pop(k, None)
        full["attributes"] = {**(full.get("attributes") or {}),
                              "post.logout.redirect.uris": d["mg-portal.post.logout.redirect.uris"]}
        full["webOrigins"] = full.get("webOrigins") or []
        body += payload(f"update clients/{q(ids['portal'])} -r {q(r)}", full)
        changes.append("mg-portal.post.logout.redirect.uris")
    if live["mg-portal.protocolMappers"] != d["mg-portal.protocolMappers"]:
        for m in portal.get("protocolMappers", []):
            if m["name"] in ids["mappers"]:
                body += payload(f"update clients/{q(ids['portal'])}/protocol-mappers/models/{q(ids['mappers'][m['name']])} -r {q(r)}",
                                {**m, "id": ids["mappers"][m["name"]]})
            else:
                body += payload(f"create clients/{q(ids['portal'])}/protocol-mappers/models -r {q(r)}", m)
        changes.append("mg-portal.protocolMappers")
    cfgs = {c["alias"]: c for c in rep.get("authenticatorConfig", [])}
    flow = next(f for f in rep["authenticationFlows"] if f["alias"] == FORMS)
    for e in flow["authenticationExecutions"]:
        prov = e.get("authenticator")
        if prov not in render_idp.AMR_REFS:
            continue
        k = f"{FORMS}.{prov}.authenticatorConfig"
        if live.get(k) == d[k]:
            continue
        exec_id, cfg_id = ids["execs"].get(prov, (None, None))
        if not exec_id:
            die(f"{r}: flow {FORMS} không có bước {prov} — cấu trúc flow lệch template, sửa tay trước (P2-T05a)")
        c = cfgs[e["authenticatorConfig"]]
        if cfg_id:
            body += payload(f"update authentication/config/{q(cfg_id)} -r {q(r)}", {**c, "id": cfg_id})
        else:
            body += payload(f"create authentication/executions/{q(exec_id)}/config -r {q(r)}", c)
        changes.append(k)
    for a in render_idp.REAUTH_ACTIONS:
        k = f"requiredAction.{a}.config"
        if live[k] != d[k]:
            body += payload(f"update authentication/required-actions/{q(a)}/config -r {q(r)}", {"config": json.loads(d[k])})
            changes.append(k)
    return changes, body


def admin_url() -> str:
    """https://admin.<domain> (P3-T15): the frontend URL of the master realm — the domain read from the Portal redirect
    URI of a rendered realm (https://app|admin.<domain>/api/v1/auth/callback/<idp id>)."""
    portal = next(c for c in want[realms[0]]["clients"] if c["clientId"] == render_idp.PORTAL)
    host = portal["redirectUris"][0].split("/")[2]
    return "https://admin." + host.split(".", 1)[1]


def master_plan() -> tuple[dict, list[str], str]:
    m = get_many({"m": "realms/master"})["m"]
    attrs = m.get("attributes") or {}
    live = {k: m.get(k) for k in MASTER}
    live["passwordPolicy"] = m.get("passwordPolicy")
    live["attributes.frontendUrl"] = attrs.get("frontendUrl") or None
    d = {**MASTER, "passwordPolicy": want[realms[0]]["passwordPolicy"], "attributes.frontendUrl": admin_url()}
    changed = sorted(k for k, v in d.items() if live.get(k) != v)
    upd = {k: v for k, v in d.items() if live.get(k) != v and k != "attributes.frontendUrl"}
    if live["attributes.frontendUrl"] != d["attributes.frontendUrl"]:
        upd["attributes"] = {**attrs, "frontendUrl": d["attributes.frontendUrl"]}
    body = payload("update realms/master", upd) if upd else ""
    return {"before": live, "after": d}, changed, body


def provisioner_plan() -> tuple[dict | None, list[str], str]:
    """P3-T15: the provisioning identity reads the login and admin events of master (console sign-ins) and of the
    platform realm(s) for idp.audit_sync — exactly view-events of their management clients, added, never removed
    (Bootstrap keeps them). None when the client does not exist (idp-bootstrap not run yet)."""
    if not get_many({"c": f"clients -r master -q clientId={q(PROVISIONER)}"})["c"]:
        return None, [], ""
    user = f"service-account-{PROVISIONER}"
    clients = ["master-realm"] + [f"{r}-realm" for r in realms if (render_idp.REALMS.get(r) or {}).get("scope") == "platform"]
    live = get_many({c: f"-r master --uusername {q(user)} --cclientid {q(c)}" for c in clients}, verb="get-roles")
    have = {c: sorted(x["name"] for x in (live.get(c) or [])) for c in clients}
    missing = [c for c in clients if VIEW_EVENTS not in have[c]]
    body = "".join(f"kc add-roles -r master --uusername {q(user)} --cclientid {q(c)} --rolename {VIEW_EVENTS} </dev/null\n"
                   for c in missing)
    return have, missing, body


def live_rep(r: str) -> dict:
    """Keycloak's own export of realm r, normalised for check_realm: only the template's clients (built-in clients of
    Keycloak are expected), masked secrets dropped, users = the service account of mg-idp-driver with its roles."""
    out = kc_session(f"kc create {q('partial-export?exportClients=true&exportGroupsAndRoles=true')} -r {q(r)} -o </dev/null\n")
    full = json.loads(out)
    # only the keys the template manages: the export also holds Keycloak's own built-ins (role descriptions such as
    # "${role_impersonation}", localized names) that check_realm's text rules are not about
    rep = {k: full[k] for k in want[r] if k in full}
    rep["clients"] = [c for c in full.get("clients", []) if c.get("clientId") in render_idp.CLIENTS]
    for c in rep["clients"]:
        c.pop("secret", None)
    drv = next(c for c in rep["clients"] if c["clientId"] == render_idp.DRIVER)
    sa = get_many({"sa": f"clients/{q(drv['id'])}/service-account-user -r {q(r)}"})["sa"]
    rm = next(c for c in get_many({"c": f"clients -r {q(r)} -q clientId=realm-management"})["c"])
    roles = get_many({"roles": f"users/{q(sa['id'])}/role-mappings/clients/{q(rm['id'])} -r {q(r)}"})["roles"] or []
    rep["users"] = [{"username": sa["username"], "enabled": sa.get("enabled"), "serviceAccountClientId": render_idp.DRIVER,
                     "clientRoles": {"realm-management": sorted(x["name"] for x in roles)}}]
    rep["clientScopeMappings"] = {k: v for k, v in (rep.get("clientScopeMappings") or {}).items() if k == "realm-management"}
    rep["scopeMappings"] = [x for x in rep.get("scopeMappings", []) if x.get("client") in render_idp.CLIENTS]
    return rep


def show(label: str, before, after) -> None:
    print(f"    {label}: {before!r} → {after!r}")


pending = 0
for r in realms:
    live, d = snapshot(r), desired(r)
    changes, body = plan(r, live, d)
    print(f"realm {r}: {len(changes)} thay đổi{'' if changes else ' (đã khớp template)'}")
    for k in changes:
        show(k, live.get(k), d[k])
    pending += len(changes)
    if changes and not check_only:
        kc_session(body)
        after = snapshot(r)
        left = [k for k in d if after.get(k) != d[k]]
        if left:
            die(f"{r}: sau khi áp vẫn lệch {left}")
mp, mk, mbody = master_plan()
print(f"realm master: {len(mk)} thay đổi{'' if mk else ' (đã gia cố)'}")
for k in mk:
    show(k, mp["before"].get(k), mp["after"][k])
pending += len(mk)
if mk and not check_only:
    kc_session(mbody)
    again, left, _ = master_plan()
    if left:
        die(f"master: sau khi áp vẫn lệch {left}")
ph, pk, pbody = provisioner_plan()
if ph is None:
    print(f"danh tính provisioning {PROVISIONER}: chưa có (idp-bootstrap chưa chạy) — bỏ qua view-events")
else:
    print(f"danh tính provisioning {PROVISIONER}: {len(pk)} thay đổi{'' if pk else ' (đã đọc được event)'}")
    for c in pk:
        show(f"{c} role", ph[c], sorted([*ph[c], VIEW_EVENTS]))
    pending += len(pk)
    if pk and not check_only:
        kc_session(pbody)
        _, left, _ = provisioner_plan()
        if left:
            die(f"provisioning: sau khi áp vẫn thiếu view-events của {left}")
if check_only:
    print(f"--check: {pending} thay đổi chờ áp")
    sys.exit(3 if pending else 0)
problems = []
for r in realms:
    spec = render_idp.REALMS.get(r)
    if spec is None:
        print(f"realm {r}: không có trong render_idp.REALMS — bỏ qua check_realm")
        continue
    rep = live_rep(r)
    portal = next(c for c in rep["clients"] if c["clientId"] == render_idp.PORTAL)
    host = portal["redirectUris"][0].split("/")[2]
    p = render_idp.check_realm(rep, r, host.split(".", 1)[1], want[r]["attributes"]["meshguard.idp_id"])
    problems += p
    print(f"realm {r}: check_realm trên bản export của Keycloak — {'đạt' if not p else 'VI PHẠM: ' + '; '.join(p)}")
if problems:
    die(f"{len(problems)} vi phạm check_realm sau cập nhật")
print("OK")
PY
