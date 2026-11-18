#!/usr/bin/env python3
"""Unit test of tools/render_mail.py (P3-T05b-mail): the Worker's wrangler.toml and the shared rules of the relay.

    python tools/test_render_mail.py        # exit code 0 = pass. Standard library only.

Checks: the sender (default no-reply@<MG_BASE_DOMAIN>, configurable, only in the environment's domain, ASCII, no header
injection through the display name); the Worker URL (https …/v1/send, http only on the ci stack, no credentials, query
or other path); wrangler.toml — valid TOML, the send_email binding EMAIL restricted to the sender, the same sender in
RELAY_ALLOWED_FROM, no secret, no placeholder, invocation logs off; the tracked template names no domain; the GID of
mg-sec-mail; the real staging env file renders.
"""
from __future__ import annotations

import pathlib
import re
import sys
import tomllib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import mgenv  # noqa: E402
import render_mail as rm  # noqa: E402

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8")
failures = 0
ENV = {"MG_ENV": "staging", "MG_BASE_DOMAIN": "example.com"}


def check(ok: bool, name: str, detail: str = "") -> None:
    global failures
    print(f"{'PASS' if ok else 'FAIL'} {name}{'' if ok else ': ' + detail}")
    failures += 0 if ok else 1


def raises(fn, name: str) -> None:
    try:
        fn()
    except (rm.ParamError, mgenv.EnvError) as e:
        check(True, f"{name} ({str(e).splitlines()[0][:70]})")
        return
    check(False, name, "no error raised")


# sender
check(rm.sender(ENV) == ("MeshGuard", "no-reply@example.com"), "default sender MeshGuard <no-reply@<domain>>", str(rm.sender(ENV)))
check(rm.from_header(ENV) == "MeshGuard <no-reply@example.com>", "From header of the worker (MG_SMTP_FROM)")
custom = {**ENV, "MG_SMTP_FROM": "MeshGuard (staging) <Alerts@Mail.Example.com>"}
check(rm.sender(custom) == ("MeshGuard (staging)", "alerts@mail.example.com"), "configurable sender, subdomain allowed, lower case")
for bad, name in (("no-reply@other.example", "a sender outside the domain is refused"),
                  ("no-reply@example.com.evil.net", "a look-alike domain is refused"),
                  ("Name <no-reply@example.com", "an unbalanced \"Name <address\" is refused"),
                  ("A <b@example.com>, C <d@example.com>", "two senders are refused"),
                  ("a..b@example.com", "a malformed local part is refused"), ("thư@example.com", "a non-ASCII address is refused")):
    raises(lambda b=bad: rm.sender({**ENV, "MG_SMTP_FROM": b}), name)
for bad in ('Evil" <x@y.z>', "Name\r\nBcc: x@y.z", "A<B>"):
    raises(lambda b=bad: rm.sender({**ENV, "MG_SMTP_FROM": f"{b} <no-reply@example.com>"}), f"display name {bad[:12]!r} is refused (header injection)")
raises(lambda: rm.sender({"MG_ENV": "staging"}), "no MG_BASE_DOMAIN is refused")

# Worker URL
check(rm.relay_url(ENV) == "", "no MG_MAILRELAY_URL ⇒ no relay")
url = "https://meshguard-mailrelay-staging.acct.workers.dev/v1/send"
check(rm.relay_url({**ENV, "MG_MAILRELAY_URL": url}) == url, "https Worker URL accepted")
check(rm.relay_url({"MG_ENV": "ci", "MG_MAILRELAY_URL": "http://fakeworker:8787/v1/send"}) == "http://fakeworker:8787/v1/send",
      "http only on the ci stack (the fake Worker)")
for bad in ("http://relay.example.com/v1/send", "https://u:p@relay.example.com/v1/send", "https://relay.example.com/v1/send?x=1",
            "https://relay.example.com/send", "https://Relay.Example.com/v1/send", "ftp://relay.example.com/v1/send"):
    raises(lambda b=bad: rm.relay_url({**ENV, "MG_MAILRELAY_URL": b}), f"URL {bad[:40]} is refused")

# wrangler.toml
files = rm.render(ENV)
check(sorted(files) == ["wrangler.toml"] and files == rm.render(ENV), "render writes wrangler.toml, deterministic")
w = files["wrangler.toml"]
conf = tomllib.loads(w)
check(conf["name"] == "meshguard-mailrelay-staging" and conf["main"] == "src/index.js" and conf["workers_dev"] is True,
      "Worker name per environment, entry src/index.js", str(conf.get("name")))
check(conf["send_email"] == [{"name": "EMAIL", "allowed_sender_addresses": ["no-reply@example.com"]}],
      "send_email binding EMAIL restricted to the one sender", str(conf.get("send_email")))
check(conf["vars"] == {"RELAY_ALLOWED_FROM": "no-reply@example.com"}, "RELAY_ALLOWED_FROM = the same sender (and nothing else in vars)")
check(conf["observability"]["enabled"] is True and conf["observability"]["logs"]["invocation_logs"] is False,
      "observability on, invocation logs (URL, request metadata) off")
check("$" not in w and "RELAY_HMAC_KEY" not in re.sub(r"(?m)^#.*$", "", w) and "secret" not in conf,
      "no placeholder left, no secret in wrangler.toml (the key is a Worker secret)")
check(tomllib.loads(rm.render({**ENV, "MG_MAILRELAY_WORKER_NAME": "mg-mail"})["wrangler.toml"])["name"] == "mg-mail",
      "MG_MAILRELAY_WORKER_NAME overrides the name")
raises(lambda: rm.render({**ENV, "MG_MAILRELAY_WORKER_NAME": "Bad_Name"}), "invalid Worker name is refused")
raises(lambda: rm.render({**ENV, "MG_ENV": "ci"}), "no Worker for the ci stack (it uses the local devserver)")
tmpl = rm.WRANGLER_TMPL.read_text(encoding="utf-8")
check(not re.search(r"@[a-z0-9-]+\.[a-z]", tmpl) and "workers.dev" not in tmpl, "the tracked template names no domain or address")
check(rm.mail_gid() == 20009, "versions.lock [ids] mg-sec-mail = 20009")
check(set(rm.FILES) == {"relay_hmac_key", "tls_key", "tls_cert", "ca.crt"} and rm.SECRETS == "/opt/meshguard/secrets/mail",
      "host files of the relay under /opt/meshguard/secrets/mail")

# the real staging env file renders (its MG_MAILRELAY_URL may still be empty — set after `wrangler deploy`)
staging = mgenv.environment(rm.ROOT / "infrastructure" / "environments" / "staging" / "staging.env")
try:
    s = tomllib.loads(rm.render(staging)["wrangler.toml"])
    check(s["send_email"][0]["allowed_sender_addresses"] == [f"no-reply@{staging['MG_BASE_DOMAIN']}"] or
          bool(staging.get("MG_SMTP_FROM")), "staging.env renders the Worker with a sender of its domain")
    rm.relay_url(staging)
    check(True, "staging.env: MG_MAILRELAY_URL empty or valid")
except rm.ParamError as e:
    check(False, "staging.env renders the Worker", str(e))
sys.exit(1 if failures else 0)
