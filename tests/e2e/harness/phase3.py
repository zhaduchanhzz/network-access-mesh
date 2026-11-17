"""Phase 3 building blocks on the dev/CI stack — FUNCTIONAL only (§22.1).

  E2E-32  P3-T14a enrollment test helper (tests/e2e/helpers, tag mgtestfixture) through the Headscale adapter and the
          edge's admin listener: user ensured + one-time pre-auth key with an explicit expiration ≤ 15 min, written to a
          0600 file; an official client joins tenant-a with it and is listed by ListNodes with that key; the same key
          is refused to a second client; the key file is deleted; cleanup leaves no node, user or valid key
  E2E-33  P3-T03a prober, STUN (through its RPC, as the worker calls it): mapped address = the prober's own address on
          the edge network (no NAT on the bridge); a closed port ⇒ typed error; a target outside the allow-list ⇒
          target_not_allowed
  E2E-34  P3-T03a prober, HTTPS through the real Caddyfile: edge check of each tenant (/key 200 + its own publicKey,
          every forbidden path ⇒ 404 not_found); SNI tenant-a + Host tenant-b ⇒ 421 misdirected; foreign SNI ⇒
          tls_handshake; unknown tenant ⇒ uniform 404; relay check (/derp/probe + STUN); without the run's CA ⇒
          tls_verify (verification is on by default)
  E2E-35  P3-T03a prober container: non-root, read-only, cap_drop ALL, no-new-privileges, no published port, only the
          edge and admin networks, healthy; a caller outside the allow-list ⇒ caller_not_allowed; a token in a probed
          path is redacted in the prober's log
Standard library only. The pre-auth key never passes through this process: the Go helper writes it to a 0600 file
that only the client containers mount.
"""
from __future__ import annotations

import json
import re
import secrets
import string

import checks
from stack import ENV_DIR, SECRET_RE, TENANTS, Stack

ENROLL_SLUG = "tenant-a"
ENROLL_USER = "mg-e2e-enroll"
ENROLL_HOST, REUSE_HOST = "e2e32-client", "e2e32-reuse"


def logline(out: str, marker: str) -> str:
    """The t.Logf line of a phase, without its file:line prefix."""
    line = next((ln.strip() for ln in out.splitlines() if marker in ln), "")
    return re.sub(r"^\S+\.go:\d+: ", "", line)


def leaked(text: str) -> bool:
    """A Headscale credential or a Bearer value not redacted."""
    return any(m.group(0) != "[REDACTED]" for m in SECRET_RE.finditer(text))


# ---------------------------------------------------------------------------------------------------- E2E-32
def run_enroll(st: Stack, phase: str, env: dict[str, str], dirs: dict[str, str]):
    """One phase of TestEnrollE2E, compiled by build_enroll(), in a container on the admin network (root without any
    capability: it reads the 0400 root-owned secrets and writes the 0600 key file the client containers read)."""
    args = [x for k, v in {**env, "MG_E2E_ENROLL_PHASE": phase}.items() for x in ("-e", f"{k}={v}")]
    return st.docker("run", "--rm", "--name", st.name("enroll"), "--network", st.name("admin"), "--user", "0:0",
                     "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                     "-v", f"{st.work / 'bin' / 'mg-e2e-enroll'}:/usr/local/bin/mg-e2e-enroll:ro",
                     "-v", f"{dirs['secrets']}:/run/mg-enroll:ro", "-v", f"{dirs['keys']}:/keys",
                     "-v", f"{dirs['state']}:/state", *args, st.images["distroless"], "/usr/local/bin/mg-e2e-enroll",
                     "-test.run", "^TestEnrollE2E$", "-test.v", "-test.count=1", check=False, timeout=180)


def check_enroll(r, st: Stack) -> None:
    meta = json.loads((ENV_DIR / "tenants" / f"{ENROLL_SLUG}.json").read_text(encoding="utf-8"))
    api_key = json.loads(st.headscale(ENROLL_SLUG, "apikeys", "create", "-e", "1h", "-o", "json").stdout)
    st.secret_values.add(api_key)
    try:
        sec, keys, state = st.fresh_dir("secrets/enroll"), st.fresh_dir("secrets/enroll-keys"), st.fresh_dir("state/enroll")
        st.write_private(sec / "apikey", api_key)
        st.write_private(sec / "edge_token", (st.work / "secrets" / "harness" / "admin_token").read_text(encoding="ascii"))
        st.helper("chown -R 0:0 /w/secrets/enroll /w/secrets/enroll-keys /w/state/enroll; chmod 0500 /w/secrets/enroll; "
                  "chmod 0400 /w/secrets/enroll/*; chmod 0700 /w/secrets/enroll-keys; chmod 0755 /w/state/enroll",
                  f"{st.work}:/w")
        env = {"MG_E2E_ENROLL_ADMIN_URL": f"http://{st.admin_ip}:8081", "MG_E2E_ENROLL_TENANT_ID": meta["tenant_id"],
               "MG_E2E_ENROLL_INSTANCE_ID": meta["instance_id"], "MG_E2E_ENROLL_SLUG": ENROLL_SLUG,
               "MG_E2E_ENROLL_USER": ENROLL_USER, "MG_E2E_ENROLL_HOST": ENROLL_HOST,
               "MG_E2E_ENROLL_REUSE_HOST": REUSE_HOST, "MG_E2E_ENROLL_DIR": "/keys",
               "MG_E2E_ENROLL_STATE": "/state/enroll.json", "MG_E2E_ENROLL_SECRETS": "/run/mg-enroll"}
        dirs = {"secrets": str(sec), "keys": str(keys), "state": str(state)}
        rows, ok, outputs = [], True, []

        p1 = run_enroll(st, "issue", env, dirs)
        outputs.append(p1.stdout + p1.stderr)
        issued = "--- PASS: TestEnrollE2E" in p1.stdout
        ok &= p1.returncode == 0 and issued
        rows.append(logline(p1.stdout, 'issued:') or f"issue exit {p1.returncode}: {st.redact(p1.stdout)[-200:]}")
        doc = json.loads((state / "enroll.json").read_text(encoding="utf-8")) if issued else {}
        files = doc.get("key_files") or []
        if not issued or len(files) != 1:
            r.add("E2E-32", "P3-T14a: helper enrollment qua adapter", False, "; ".join(rows))
            return
        key_file = str(keys / files[0].rsplit("/", 1)[-1])

        rc1, state1, out1 = checks.probe_enroll(st, key_file, ENROLL_SLUG, ENROLL_HOST)
        rc2, state2, out2 = checks.probe_enroll(st, key_file, ENROLL_SLUG, REUSE_HOST)
        outputs += [out1, out2]
        joined, refused = rc1 == 0 and state1 == "Running", rc2 != 0 and state2 != "Running"
        ok &= joined and refused
        rows.append(f"{ENROLL_HOST} rc={rc1} {state1}")
        reason = "authkey already used" if "already used" in out2 else out2.split(chr(10), 1)[-1][:80]
        rows.append(f"{REUSE_HOST} rc={rc2} {state2} ({reason})")

        p2 = run_enroll(st, "verify", env, dirs)
        outputs.append(p2.stdout + p2.stderr)
        verified = p2.returncode == 0 and "--- PASS: TestEnrollE2E" in p2.stdout
        ok &= verified
        rows.append(logline(p2.stdout, 'verified:') or f"verify exit {p2.returncode}: {st.redact(p2.stdout)[-200:]}")
        left = st.helper("ls -A /w/secrets/enroll-keys | wc -l", f"{st.work}:/w").stdout.strip()
        ok &= left == "0"
        clean = not any(leaked(o) for o in outputs)
        ok &= clean
        rows.append(f"key files left {left}; " + ("no credential in output" if clean else "CREDENTIAL IN OUTPUT"))
        r.add("E2E-32", "P3-T14a: helper (tag mgtestfixture) qua adapter + listener admin của edge — user + pre-auth key "
              "dùng 1 lần, hạn tường minh ≤ 15 phút, file 0600; client chính thức join tenant-a và có trong ListNodes "
              "với đúng key; dùng lại key bị từ chối; file key bị xóa; dọn sạch node/user", ok, "; ".join(rows))
    finally:
        st.headscale(ENROLL_SLUG, "apikeys", "expire", "--prefix", api_key.split("-")[2], check=False)
        st.helper("rm -rf /w/secrets/enroll /w/secrets/enroll-keys /w/state/enroll", f"{st.work}:/w")


# ---------------------------------------------------------------------------------------------------- prober
def prober_call(st: Stack, kind: str, req: dict, network: str = "admin") -> tuple[int, dict]:
    """`meshguard-probe call` (the Go RPC client the worker uses) in a throwaway container of the probe image."""
    p = st.docker("run", "--rm", "-i", "--name", st.name("probe-call"), "--network", st.name(network), "--read-only",
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--user", "65532:65532",
                  st.images["probe"], "call", "--url", f"http://{st.name('prober')}:8080", kind,
                  input=json.dumps(req), check=False, timeout=120)
    try:
        return p.returncode, json.loads(p.stdout)
    except ValueError:
        return p.returncode, {"raw": st.redact(p.stdout + p.stderr)[-300:]}


def code(doc: dict) -> str:
    return ((doc.get("error") or {}).get("code")) or ""


def check_prober_stun(r, st: Stack) -> None:
    ip = st.docker("inspect", "-f", "{{(index .NetworkSettings.Networks \"" + st.name("edge") + "\").IPAddress}}",
                   st.name("prober")).stdout.strip()
    rows, ok = [], True
    rc, doc = prober_call(st, "stun", {"target": f"{st.edge_ip}:3478"})
    mapped = doc.get("mapped", "")
    good = rc == 0 and doc.get("ok") is True and mapped.rsplit(":", 1)[0] == ip and mapped == doc.get("local")
    ok &= good
    rows.append(f"{st.edge_ip}:3478 ⇒ mapped {mapped} (prober on the edge network: {ip}, local {doc.get('local')}), "
                f"{doc.get('attempts')} attempt(s), rtt {doc.get('rtt_ms')} ms")
    rc, doc = prober_call(st, "stun", {"target": f"{st.edge_ip}:3479", "timeout_ms": 3000})
    good = rc == 1 and doc.get("ok") is False and code(doc) in ("refused", "timeout")
    ok &= good
    rows.append(f"{st.edge_ip}:3479 (closed) ⇒ exit {rc}, {code(doc)} after {doc.get('attempts')} attempt(s)")
    rc, doc = prober_call(st, "stun", {"target": "192.0.2.1:3478"})
    ok &= rc == 3 and code(doc) == "target_not_allowed"
    rows.append(f"192.0.2.1:3478 ⇒ exit {rc}, {code(doc)}")
    r.add("E2E-33", "P3-T03a prober (RPC qua client Go): STUN tới stund tại IP điểm vào ⇒ mapped address = địa chỉ nguồn "
          "của prober; cổng sai ⇒ lỗi có kiểu; đích ngoài allow-list ⇒ target_not_allowed", ok, "; ".join(rows))


def check_prober_https(r, st: Stack) -> None:
    addr = f"{st.edge_ip}:443"
    rows, ok, keys = [], True, {}
    for slug in TENANTS:
        rc, doc = prober_call(st, "edge", {"address": addr, "host": f"{slug}.{st.mesh}"})
        forb = doc.get("forbidden") or []
        classes = {f.get("class") for f in forb}
        keys[slug] = ((doc.get("key") or {}).get("json") or {}).get("publicKey", "")
        good = (rc == 0 and doc.get("ok") is True and doc.get("blocked") == len(forb) and len(forb) >= 20
                and classes == {"not_found"} and keys[slug].startswith("mkey:"))
        ok &= good
        rows.append(f"edge {slug}: /key {(doc.get('key') or {}).get('status')}, {doc.get('blocked')}/{len(forb)} "
                    f"forbidden ⇒ 404, {doc.get('total_ms')} ms")
    ok &= keys["tenant-a"] != keys["tenant-b"]
    rows.append("publicKey A ≠ B" if keys["tenant-a"] != keys["tenant-b"] else "publicKey A = B")
    a, b = f"tenant-a.{st.mesh}", f"tenant-b.{st.mesh}"
    for name, req, want_rc, pred in (
        ("SNI A + Host B", {"address": addr, "sni": a, "host": b, "path": "/key?v=113", "expect": {"status": [421]}}, 0,
         lambda d: d.get("class") == "misdirected"),
        ("foreign SNI", {"address": addr, "sni": "foreign.example", "path": "/"}, 1,
         lambda d: code(d) == "tls_handshake"),
        ("unknown tenant", {"address": addr, "sni": f"nope-tenant.{st.mesh}", "path": "/key?v=113",
                            "expect": {"status": [404]}}, 0, lambda d: d.get("class") == "not_found"),
    ):
        rc, doc = prober_call(st, "https", req)
        good = rc == want_rc and pred(doc)
        ok &= good
        rows.append(f"{name}: exit {rc}, status {doc.get('status')} {doc.get('class') or code(doc)}")
    rc, doc = prober_call(st, "relay", {"address": addr, "host": b, "stun": f"{st.edge_ip}:3478"})
    good = rc == 0 and doc.get("ok") is True
    ok &= good
    rows.append(f"relay tenant-b: /derp/probe {(doc.get('derp') or {}).get('status')}, STUN "
                f"{'ok' if (doc.get('stun') or {}).get('ok') else code(doc.get('stun') or {})}")
    # verification on by default: the same probe without the run's CA (system roots of the image) is refused
    p = st.docker("run", "--rm", "-i", "--name", st.name("probe-run"), "--network", st.name("edge"), "--read-only",
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", st.images["probe"], "run", "https",
                  input=json.dumps({"address": addr, "sni": a, "path": "/key?v=113"}), check=False, timeout=60)
    try:
        doc = json.loads(p.stdout)
    except ValueError:
        doc = {}
    good = p.returncode == 1 and code(doc) == "tls_verify"
    ok &= good
    rows.append(f"without the run's CA: exit {p.returncode}, {code(doc)}")
    r.add("E2E-34", "P3-T03a prober: HTTPS GET tới IP edge với SNI/Host chỉ định (Caddyfile thật) — /key đúng key của "
          "từng tenant, mọi path cấm ⇒ 404 (not_found); SNI≠Host ⇒ 421; SNI lạ ⇒ tls_handshake; relay (/derp/probe + "
          "STUN); xác minh TLS bật mặc định", ok, "; ".join(rows))


def check_prober_container(r, st: Stack) -> None:
    fmt = ("{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.CapDrop}}|{{.HostConfig.SecurityOpt}}|"
           "{{len .HostConfig.PortBindings}}|{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}|"
           "{{.State.Health.Status}}")
    user, ro, caps, sec, ports, nets, health = st.docker("inspect", "-f", fmt, st.name("prober")).stdout.strip().split("|")
    want_nets = sorted([st.name("edge"), st.name("admin")])
    hard = (user == "65532:65532" and ro == "true" and caps == "[ALL]" and "no-new-privileges:true" in sec
            and ports == "0" and sorted(nets.split()) == want_nets and health == "healthy")
    rows = [f"user {user}, read_only {ro}, cap_drop {caps}, {sec}, {ports} published port(s), networks {nets.strip()}, "
            f"{health}"]
    rc, doc = prober_call(st, "stun", {"target": f"{st.edge_ip}:3478"}, network="edge")
    guard = rc == 3 and code(doc) == "caller_not_allowed"
    rows.append(f"caller on the edge network ⇒ exit {rc}, {code(doc)}")
    # a marker (not a secret of the run): a forbidden path, so the edge answers 404 itself and nothing reaches Headscale
    token = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
    prober_call(st, "https", {"address": f"{st.edge_ip}:443", "sni": f"tenant-a.{st.mesh}",
                              "path": f"/api/v1/node?token={token}&v=1", "expect": {"status": [404]}})
    logs = st.docker("logs", st.name("prober"), check=False)
    text = logs.stdout + logs.stderr
    redacted = token not in text and "token=[REDACTED]" in text and not leaked(text)
    probes = len(re.findall(r'"msg":"probe"', text))
    rows.append(f"log: {probes} probe lines, token in a probed path {'redacted' if redacted else 'NOT REDACTED'}")
    r.add("E2E-35", "P3-T03a prober: container non-root, rootfs chỉ-đọc, cap_drop ALL, no-new-privileges, không publish "
          "cổng, chỉ network edge + admin; caller ngoài allow-list ⇒ caller_not_allowed; log không chứa token",
          hard and guard and redacted, "; ".join(rows))


def run_all(r, st: Stack, guarded) -> None:
    guarded(r, "E2E-32", check_enroll, st)
    guarded(r, "E2E-33", check_prober_stun, st)
    guarded(r, "E2E-34", check_prober_https, st)
    guarded(r, "E2E-35", check_prober_container, st)
