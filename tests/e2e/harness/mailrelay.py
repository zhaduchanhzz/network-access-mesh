"""Outbound e-mail relay on the dev/CI stack (P3-T05b-mail) — FUNCTIONAL only (§22.1), never Cloudflare.

The relay of the stack is the real one: service `mail-bridge` (SMTP host `mailrelay`; worker image built from the tree,
`meshguard mailrelay`)
rendered by tools/render_app.py, files by infrastructure/host/mail-secrets.sh (internal CA, HMAC key), Keycloak's realms
rendered by tools/render_idp.py with MG_IDP_MAIL_SINK=mailrelay. Only the Worker is a stand-in: `fakeworker` runs the
real infrastructure/mail/cf-worker/src/index.js under node (test/devserver.mjs) with a fake EMAIL binding that records
what Email Service would send (headers, sizes, digests — never a body) and every request (status, code, the signed
headers and the body digest), so this module checks the HMAC itself with its own copy of the key.

  E2E-82  the SMTP listener answers on the `mail` network only (not on mg-egress), offers STARTTLS and refuses MAIL before
          it; a notification (policy.applied of tenant-a, `meshguard admin policy-apply` in the worker) and a Keycloak
          e-mail (execute-actions-email of a tenant-b user) both reach the Worker through mailrelay with STARTTLS, from
          the relay's one sender, each request with a valid HMAC; the outbox rows turn `sent` with the row's Message-ID;
          the coordinator's `meshguard admin mail-test --to <address>` in the worker sends one message the same way
  E2E-83  a wrong HMAC key is rejected: the bridge's key file rewritten in place ⇒ the Worker answers 401 auth_signature,
          the bridge answers 4xx, Keycloak reports the failure, nothing is sent; the right key back (no restart) ⇒ sent.
          Straight to the Worker: stale timestamp ⇒ 401 auth_timestamp, another key ⇒ 401 auth_signature, GET ⇒ 404, an
          accepted request replayed ⇒ 200 duplicate and not sent twice
Standard library only.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import socket
import time
import urllib.error
import urllib.request

import render_mail
from backend import KeycloakAdmin, psql
from phase3 import policy_apply
from stack import ROOT, Stack, log

WORKER_PORT, SMTP_PORT = 8787, 587


def ip_on(st: Stack, service: str, network: str) -> str:
    cid = st.compose("ps", "-q", service).stdout.strip()
    return st.docker("inspect", "-f", f'{{{{(index .NetworkSettings.Networks "{st.name(network)}").IPAddress}}}}',
                     cid).stdout.strip()


def records(st: Stack, name: str) -> list[dict]:
    f = st.work / "fakeworker" / f"{name}.jsonl"
    if not f.exists():
        return []
    return [json.loads(ln) for ln in f.read_text(encoding="utf-8").splitlines() if ln.strip()]


def wait_for(pred, timeout: float, every: float = 1.0):
    end = time.time() + timeout
    while True:
        v = pred()
        if v or time.time() >= end:
            return v
        time.sleep(every)


def mail_key(st: Stack) -> str:
    key = getattr(st, "mail_key", "") or st.helper("cat /w/secrets/mail/relay_hmac_key", f"{st.work}:/w").stdout.strip()
    st.mail_key = key
    st.secret_values.add(key)
    return key


def sign(key: str, ts: str, body: bytes) -> str:
    return hmac.new(key.encode(), f"{ts}\n{hashlib.sha256(body).hexdigest()}".encode(), hashlib.sha256).hexdigest()


def hmac_ok(key: str, req: dict) -> bool:
    want = hmac.new(key.encode(), f"{req['ts']}\n{req['body_sha256']}".encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, req.get("sig", ""))


def worker_call(st: Stack, body: bytes, *, key: str, ts: int | None = None, method: str = "POST") -> tuple[int, dict]:
    """A request straight to the fake Worker (its address on the stack's egress network)."""
    t = str(int(time.time()) if ts is None else ts)
    req = urllib.request.Request(f"http://{ip_on(st, 'fakeworker', 'egress')}:{WORKER_PORT}/v1/send",
                                 data=body if method == "POST" else None, method=method,
                                 headers={"Content-Type": "application/json", "X-MG-Timestamp": t,
                                          "X-MG-Signature": sign(key, t, body)})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def metrics(st: Stack) -> dict[str, float]:
    """meshguard_mailrelay_* of the relay (its /metrics on the obs network)."""
    with urllib.request.urlopen(f"http://{ip_on(st, 'mail-bridge', 'obs')}:9090/metrics", timeout=10) as r:
        text = r.read().decode()
    out = {}
    for ln in text.splitlines():
        if ln.startswith("meshguard_mailrelay_") and " " in ln:
            k, v = ln.rsplit(" ", 1)
            out[k] = float(v)
    return out


def smtp_probe(ip: str) -> list[str]:
    """Greeting, EHLO and MAIL before STARTTLS on ip:587 — the answers' first lines; [] when nothing listens."""
    try:
        s = socket.create_connection((ip, SMTP_PORT), timeout=5)
    except OSError as e:
        return [f"connect: {type(e).__name__}"]
    out = []
    with s, s.makefile("rwb") as f:
        def answer() -> str:
            lines = []
            while True:
                ln = f.readline().decode(errors="replace").rstrip("\r\n")
                lines.append(ln)
                if len(ln) < 4 or ln[3] != "-":
                    return " / ".join(lines)
        out.append(answer())
        for cmd in ("EHLO e2e.test", "MAIL FROM:<" + "no-reply@x.invalid" + ">", "QUIT"):
            f.write((cmd + "\r\n").encode())
            f.flush()
            out.append(answer())
    return out


def kc_user(kc: KeycloakAdmin, realm: str, tag: str) -> tuple[str, str]:
    name = f"{tag}-{secrets.token_hex(4)}"
    email = f"{name}@example.invalid"
    r = kc._call("POST", f"/admin/realms/{realm}/users", body={"username": name, "email": email, "emailVerified": True,
                                                               "enabled": True, "firstName": "E2E", "lastName": tag})
    return r["location"].rsplit("/", 1)[1], email


def actions_email(kc: KeycloakAdmin, realm: str, uid: str) -> int:
    """PUT …/execute-actions-email (UPDATE_PASSWORD): Keycloak sends it synchronously — 204 sent, 500 failed."""
    try:
        kc._call("PUT", f"/admin/realms/{realm}/users/{uid}/execute-actions-email", body=["UPDATE_PASSWORD"])
        return 204
    except urllib.error.HTTPError as e:
        return e.code


def sent_to(st: Stack, email: str) -> list[dict]:
    return [x for x in records(st, "sent") if x.get("to") == email]


# ---------------------------------------------------------------------------------------------------- E2E-82
def check_relay(r, st: Stack) -> None:
    rows, conds = [], []

    def cond(name: str, good: bool, row: str) -> None:
        conds.append((name, good))
        rows.append(f"[{'ok' if good else 'FAIL'} {name}] {row}")

    key = mail_key(st)
    sender = render_mail.sender(st.env)[1]
    before = metrics(st)
    on_mail, on_egress = smtp_probe(ip_on(st, "mail-bridge", "mail")), smtp_probe(ip_on(st, "mail-bridge", "egress"))
    cond("listener", len(on_mail) == 4 and on_mail[0].startswith("220 mailrelay ESMTP") and "STARTTLS" in on_mail[1]
         and on_mail[2].startswith("530 ") and on_egress[0].startswith("connect:"),
         f"mail network: {on_mail[:3]}; egress network: {on_egress[:1]}")

    # (1) a notification: policy.applied of tenant-a (the baseline again — state unchanged)
    base = (ROOT / "infrastructure" / "headscale" / "templates" / "bootstrap-policy.hujson").read_text(encoding="utf-8")
    code, out, err = policy_apply(st, base, "--trigger", "bootstrap")
    app = out.get("application_id", "")
    cond("policy_apply", code == 0 and out.get("state") == "applied" and bool(app), f"exit {code} {out.get('state')} {err[-200:]}")

    def outbox() -> list[list[str]]:
        return psql(st, "SELECT id, recipient_email, status, attempts FROM notification_outbox WHERE kind = 'policy.applied' "
                        f"AND payload->>'application_id' = '{app}' AND recipient_email IS NOT NULL ORDER BY id")

    def settled() -> bool:
        got = outbox()
        return bool(got) and all(x[2] != "pending" for x in got)
    wait_for(settled, 120, 2)
    notes = outbox()   # as they are, settled or not (the detail shows the statuses)
    domain = sender.split("@", 1)[1]
    delivered = [x for x in notes if x[2] == "sent" and any(
        s.get("message_id") == f"<{x[0]}@{domain}>" and s.get("to") == x[1].lower() and s.get("from") == sender
        and sender in (s.get("header_from") or "") for s in records(st, "sent"))]
    cond("notification", bool(notes) and len(delivered) == len(notes),
         f"{len(notes)} e-mail row(s) of the application, statuses {sorted({x[2] for x in notes})}, attempts "
         f"{sorted({x[3] for x in notes})}, {len(delivered)} at the Worker with the row's Message-ID and the sender")

    # (2) a Keycloak e-mail: execute-actions-email of a fresh tenant-b user
    kc = KeycloakAdmin(st)
    uid, email = kc_user(kc, "tenant-b", "e2e82")
    try:
        status = actions_email(kc, "tenant-b", uid)
        got = wait_for(lambda: sent_to(st, email), 30)
        cond("keycloak", status == 204 and len(got) == 1 and got[0].get("from") == sender
             and sender in (got[0].get("header_from") or "") and bool(got[0].get("subject")) and bool(got[0].get("message_id")),
             f"execute-actions-email HTTP {status}; at the Worker: {len(got or [])} message(s), header From "
             f"{(got or [{}])[0].get('header_from')}, subject present {bool((got or [{}])[0].get('subject'))}")
    finally:
        kc._call("DELETE", f"/admin/realms/tenant-b/users/{uid}")

    # (3) the coordinator's test command: `meshguard admin mail-test --to <address>` inside the running worker
    rcpt = f"e2e82-test-{secrets.token_hex(4)}@example.invalid"
    p = st.docker("exec", st.compose("ps", "-q", "worker").stdout.strip(), "/usr/local/bin/meshguard", "admin", "mail-test",
                  "--to", rcpt, check=False, timeout=120)
    res = json.loads(next((ln for ln in p.stdout.splitlines() if ln.startswith("{")), "{}"))
    got = wait_for(lambda: sent_to(st, rcpt), 15) or []
    cond("mail_test", p.returncode == 0 and res.get("result") == "sent" and len(got) == 1
         and got[0].get("message_id") == res.get("message_id") and rcpt not in p.stdout,
         f"admin mail-test: exit {p.returncode} {res.get('result')} to {res.get('to')}; at the Worker {len(got)} "
         f"message(s) with its Message-ID {bool(got) and got[0].get('message_id') == res.get('message_id')}")

    reqs = [x for x in records(st, "requests") if x.get("status") == 200]
    good = [x for x in reqs if hmac_ok(key, x)]
    cond("hmac", len(reqs) >= 3 and len(good) == len(reqs), f"{len(good)}/{len(reqs)} accepted requests carry a valid HMAC")
    after = metrics(st)
    tls_ok, delivered_n, tls_required = (after.get(k, 0) - before.get(k, 0) for k in (
        'meshguard_mailrelay_starttls_total{result="ok"}', 'meshguard_mailrelay_messages_total{result="delivered"}',
        'meshguard_mailrelay_rejected_total{reason="tls_required"}'))
    cond("metrics", tls_ok >= 3 and delivered_n >= 3 and tls_required >= 1,
         f"STARTTLS ok +{tls_ok:.0f}, delivered +{delivered_n:.0f}, MAIL before STARTTLS refused +{tls_required:.0f}")
    failed = [n for n, ok in conds if not ok]
    for row in rows:
        log(f"  E2E-82 {st.redact(row)}")
    r.add("E2E-82", "P3-T05b-mail: relay thư ra — SMTP chỉ trên network mail (STARTTLS bắt buộc); thông báo policy.applied và "
          "thư Keycloak (execute-actions-email) tới Worker (mã thật, binding giả) qua mailrelay với HMAC hợp lệ, đúng địa chỉ "
          "gửi; hàng outbox `sent` mang Message-ID của hàng", not failed,
          (f"FAILED: {', '.join(failed)} — " if failed else "") + "; ".join(rows), limit=3000)


# ---------------------------------------------------------------------------------------------------- E2E-83
def check_wrong_key(r, st: Stack) -> None:
    rows, conds = [], []

    def cond(name: str, good: bool, row: str) -> None:
        conds.append((name, good))
        rows.append(f"[{'ok' if good else 'FAIL'} {name}] {row}")

    key = mail_key(st)
    sender = render_mail.sender(st.env)[1]
    domain = sender.split("@", 1)[1]
    # straight to the Worker
    rcpt = f"e2e83-replay-{secrets.token_hex(4)}@example.invalid"
    raw = (f"From: MeshGuard <{sender}>\r\nTo: {rcpt}\r\nSubject: E2E-83 replay\r\n"
           f"Message-ID: <e2e83-{secrets.token_hex(8)}@{domain}>\r\n\r\nreplay test\r\n")
    body = json.dumps({"from": sender, "to": [rcpt], "raw_b64": base64.b64encode(raw.encode()).decode()}).encode()
    other = "".join(secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(48))
    st.secret_values.add(other)
    stale = worker_call(st, body, key=key, ts=int(time.time()) - 400)
    wrong = worker_call(st, body, key=other)
    get = worker_call(st, b"", key=key, method="GET")
    now = int(time.time())
    first = worker_call(st, body, key=key, ts=now)
    replay = worker_call(st, body, key=key, ts=now)
    cond("worker", stale == (401, {"ok": False, "code": "auth_timestamp"}) and wrong == (401, {"ok": False, "code": "auth_signature"})
         and get[0] == 404 and first[0] == 200 and first[1].get("code") == "sent" and replay[0] == 200
         and replay[1].get("code") == "duplicate" and len(sent_to(st, rcpt)) == 1,
         f"stale {stale[0]} {stale[1].get('code')}, other key {wrong[0]} {wrong[1].get('code')}, GET {get[0]}, accepted "
         f"{first[0]} {first[1].get('code')}, replayed {replay[0]} {replay[1].get('code')}, sent {len(sent_to(st, rcpt))} time(s)")

    # the bridge with a wrong key (file rewritten in place — no restart), then the right one again
    kc = KeycloakAdmin(st)
    uid, email = kc_user(kc, "tenant-b", "e2e83")
    before = metrics(st)
    n_req = len(records(st, "requests"))
    try:
        st.set_mail_key(other)
        bad = actions_email(kc, "tenant-b", uid)
        new = records(st, "requests")[n_req:]
        tkey = 'meshguard_mailrelay_messages_total{result="temporary"}'
        temporary = metrics(st).get(tkey, 0) - before.get(tkey, 0)
        answers = [(x.get("status"), x.get("code")) for x in new]
        cond("rejected", bad >= 400 and (401, "auth_signature") in answers and not sent_to(st, email) and temporary >= 1,
             f"Keycloak HTTP {bad}; Worker answers {answers}; sent {len(sent_to(st, email))}; bridge temporary +{temporary:.0f}")
    finally:
        st.set_mail_key(key)
    try:
        good = actions_email(kc, "tenant-b", uid)
        got = wait_for(lambda: sent_to(st, email), 30)
        cond("restored", good == 204 and len(got or []) == 1, f"right key back (no restart): HTTP {good}, sent {len(got or [])}")
    finally:
        kc._call("DELETE", f"/admin/realms/tenant-b/users/{uid}")
    failed = [n for n, ok in conds if not ok]
    for row in rows:
        log(f"  E2E-83 {st.redact(row)}")
    r.add("E2E-83", "P3-T05b-mail: khóa HMAC sai bị Worker từ chối (401 auth_signature ⇒ cầu SMTP trả 4xx, không thư nào "
          "gửi), khóa đúng ghi lại tại chỗ ⇒ gửi được không restart; gọi thẳng Worker: timestamp cũ, khóa khác ⇒ 401, GET ⇒ "
          "404, request đã nhận bị phát lại ⇒ duplicate, không gửi lần hai", not failed,
          (f"FAILED: {', '.join(failed)} — " if failed else "") + "; ".join(rows), limit=3000)


def run_all(r, st: Stack, guarded) -> None:
    if not (st.work / "fakeworker").exists():
        for tid in ("E2E-82", "E2E-83"):
            r.add(tid, "P3-T05b-mail: relay thư ra", False, "the stack has no fake Worker (MG_MAILRELAY_URL of ci.env)")
        return
    guarded(r, "E2E-82", check_relay, st)
    guarded(r, "E2E-83", check_wrong_key, st)
