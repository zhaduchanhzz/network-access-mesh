"""Functional checks of the dev/CI stack (P2-T01a). Every result is labelled "functional" — containers on one Docker
host, never "network E2E verified" (§9.5, §22.1, HS-24).

Traffic is real TCP through WireGuard: `tailscale nc` (LocalAPI dial through the client's userspace netstack) to a
listener on the peer; never `tailscale ping` as proof of a policy (HS-25, CL-09) — ping is only used to show the path.
"""
from __future__ import annotations

import http.client
import json
import socket
import ssl
import sys
import time
import urllib.request

from stack import CLIENTS, RELAY_ONLY, ROOT, TENANTS, Stack, StackError, log

sys.path.insert(0, str(ROOT / "tests" / "security" / "edge"))
import conformance  # noqa: E402 — FORBIDDEN_PUBLIC / TRAVERSAL / allowed_public of the edge conformance suite (P1-T10a)

SOCK = "--socket=/tmp/tailscaled.sock"
ALLOWED_PORT, DENIED_PORT = 8000, 8001        # test-allow-intra.hujson: only tcp:8000 (+ icmp) inside a tenant
REQUIRED_FORBIDDEN = ["/api/v1/node", "/api/v1/apikey", "/api/v1/policy", "/swagger", "/swagger/v1/openapiv2.json",
                      "/verify", "/metrics"]


class Results:
    def __init__(self, st: Stack) -> None:
        self.st = st
        self.rows: list[dict] = []

    def add(self, tid: str, name: str, ok: bool, detail: str = "") -> bool:
        detail = self.st.redact(str(detail)).replace("\n", " ")[:400]
        self.rows.append({"id": tid, "name": name, "result": "PASS" if ok else "FAIL", "label": "functional",
                          "detail": detail})
        log(f"{'PASS' if ok else 'FAIL'} [{tid}] {name}" + (f" — {detail}" if detail else ""))
        return ok

    @property
    def failed(self) -> int:
        return sum(r["result"] != "PASS" for r in self.rows)


# ---------------------------------------------------------------------------------------------------- client helpers
def ts(st: Stack, c: str, *args: str, timeout: float = 60, check: bool = False):
    return st.exec(f"ts-{c}", "tailscale", SOCK, *args, check=check, timeout=timeout)


def status(st: Stack, c: str) -> dict:
    return json.loads(ts(st, c, "status", "--json", check=True).stdout)


def peers(s: dict) -> list[dict]:
    return list((s.get("Peer") or {}).values())


def ip4(node: dict) -> str:
    return next(a for a in node.get("TailscaleIPs") or [] if "." in a)


def wait(pred, timeout: float, every: float = 1.0):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        last = pred()
        if last:
            return last
        time.sleep(every)
    return last


def wait_running(st: Stack, clients, timeout: float = 120) -> dict[str, dict]:
    out = {}
    for c in clients:
        def ok(c=c):
            try:
                s = status(st, c)
            except (StackError, ValueError):
                return None
            return s if s.get("BackendState") == "Running" and s.get("Self", {}).get("TailscaleIPs") else None
        s = wait(ok, timeout)
        if not s:
            logs = st.docker("logs", "--tail", "30", st.name(f"ts-{c}"), check=False)
            raise StackError(f"client {c} không Running sau {timeout}s:\n" + st.redact(logs.stdout + logs.stderr)[-1500:])
        out[c] = s
    return out


def wait_peer_count(st: Stack, c: str, n: int, timeout: float = 60) -> dict | None:
    return wait(lambda: (lambda s: s if len(peers(s)) == n else None)(status(st, c)), timeout)


def start_listeners(st: Stack, c: str) -> None:
    """Persistent TCP listeners on the allowed and the denied port; each answers with who it is, then closes."""
    for port in (ALLOWED_PORT, DENIED_PORT):
        st.docker("exec", "-d", st.name(f"ts-{c}"), "nc", "-lk", "-p", str(port), "-e", "echo",
                  f"mg-e2e {CLIENTS[c]} {c} tcp/{port}")


def tcp(st: Stack, src: str, dst_ip: str, port: int, wait_s: int = 8) -> str:
    """Real TCP from src to dst_ip:port over the tailnet; returns what the listener answered ('' = no connection).
    stdin of `tailscale nc` is a FIFO kept open by a background writer, so nc ends when the peer closes (not on EOF)."""
    script = (f'f=$(mktemp -u); mkfifo "$f"; (sleep {wait_s + 2} >"$f" 2>/dev/null &); '
              f'timeout {wait_s} tailscale {SOCK} nc {dst_ip} {port} <"$f" 2>/dev/null; rm -f "$f"')
    return st.exec(f"ts-{src}", "sh", "-c", script, check=False, timeout=wait_s + 30).stdout.strip()


def local_tcp(st: Stack, c: str, port: int) -> str:
    return st.exec(f"ts-{c}", "sh", "-c", f"echo | nc -w 3 127.0.0.1 {port}", check=False, timeout=30).stdout.strip()


# ---------------------------------------------------------------------------------------------------- checks
def check_db(r: Results, st: Stack, res: dict) -> None:
    ok = (res.get("schema_version") == res.get("latest_migration") and res.get("schema_version", 0) > 0
          and res.get("river_migrations", 0) > 0 and res.get("system_roles", 0) > 0
          and not res.get("partition_grant_violations") and res.get("pools") == ["api", "worker"])
    r.add("E2E-01", "PostgreSQL: migration bằng đường của repo (store.Bootstrap → MigrateAll) — schema mới nhất, "
          "River, seed RBAC, role đăng nhập dùng được", ok,
          f"schema {res.get('schema_version')}/{res.get('latest_migration')}, river {res.get('river_migrations')} "
          f"version, {res.get('system_roles')} role hệ thống, pool {res.get('pools')}, "
          f"{len(res.get('roles_with_password', []))} role có mật khẩu, vi phạm partition "
          f"{len(res.get('partition_grant_violations') or [])}")


def check_idp(r: Results, st: Stack) -> None:
    ip = st.docker("inspect", "-f", f'{{{{(index .NetworkSettings.Networks "{st.name("idp")}").IPAddress}}}}',
                   st.compose("ps", "-q", "idp").stdout.strip()).stdout.strip()
    issuers, kids, problems = {}, {}, []
    for realm in ("platform", "tenant-a", "tenant-b"):
        try:
            with urllib.request.urlopen(f"http://{ip}:8080/realms/{realm}/.well-known/openid-configuration", timeout=15) as f:
                doc = json.load(f)
            issuers[realm] = doc["issuer"]
            with urllib.request.urlopen(f"http://{ip}:8080/realms/{realm}/protocol/openid-connect/certs", timeout=15) as f:
                kids[realm] = {k["kid"] for k in json.load(f)["keys"] if k.get("use") == "sig"}
        except (OSError, ValueError, KeyError) as e:
            problems.append(f"{realm}: {type(e).__name__}: {e}")
    want = {realm: f"https://auth.{st.domain}/realms/{realm}" for realm in ("platform", "tenant-a", "tenant-b")}
    all_kids = [k for v in kids.values() for k in v]
    r.add("E2E-02", "IdP Keycloak: 3 realm import sẵn, 3 issuer khác nhau, khóa ký riêng từng realm",
          not problems and issuers == want and len(all_kids) == len(set(all_kids)) >= 3,
          "; ".join(problems) or f"issuer {sorted(issuers.values())}; {len(set(all_kids))} kid khác nhau")


def check_baseline(r: Results, st: Stack, stat: dict[str, dict]) -> None:
    counts = {c: len(peers(s)) for c, s in stat.items()}
    r.add("E2E-03", "Baseline deny-all (bootstrap-policy, áp trước khi edge gắn vào network tenant): client Running, "
          "0 peer", all(n == 0 for n in counts.values()), f"số peer {counts}")


def check_nodes(r: Results, st: Stack, stat: dict[str, dict]) -> None:
    detail, ok = [], True
    for slug in TENANTS:
        nodes = json.loads(st.headscale(slug, "nodes", "list", "-o", "json").stdout or "[]") or []
        names = sorted(n.get("given_name") or n.get("name") for n in nodes)
        keys = {n.get("node_key") for n in nodes}
        want = sorted(c for c, t in CLIENTS.items() if t == slug)
        mine = {stat[c]["Self"]["PublicKey"] for c in want}
        ok &= names == want and keys == mine
        detail.append(f"{slug}: {names}")
    r.add("E2E-04", "Enrollment bằng pre-auth key (CLI Headscale trong container): mỗi Headscale chỉ có đúng 2 node "
          "của tenant mình", ok, "; ".join(detail))


def check_isolation(r: Results, st: Stack) -> dict[str, dict]:
    stat = {c: wait_peer_count(st, c, 1, 60) or status(st, c) for c in CLIENTS}
    keys = {c: s["Self"]["PublicKey"] for c, s in stat.items()}
    ok, detail = True, []
    for c, s in stat.items():
        mine = CLIENTS[c]
        sibling = {keys[o] for o, t in CLIENTS.items() if t == mine and o != c}
        other = {keys[o] for o, t in CLIENTS.items() if t != mine}
        pk = {p["PublicKey"] for p in peers(s)}
        good = bool(pk) and pk == sibling and not (pk & other)
        ok &= good
        detail.append(f"{c}: {len(pk)} peer {'= anh em cùng tenant' if good else 'SAI'}")
    ips = {c: ip4(s["Self"]) for c, s in stat.items()}
    overlap = sorted({ips["a1"], ips["a2"]} & {ips["b1"], ips["b2"]})
    r.add("E2E-05", "IT-05 (functional, status --json): dưới test-allow-intra mỗi client thấy đúng peer cùng tenant, "
          "không thấy node nào của tenant kia (danh sách peer khác rỗng)", ok,
          "; ".join(detail) + f"; IP tailnet {ips}" + (f" — hai tailnet dùng chung địa chỉ {overlap}" if overlap else ""))
    return stat


def check_derp_map(r: Results, st: Stack) -> None:
    ok, detail = True, []
    for c, slug in CLIENTS.items():
        dm = json.loads(ts(st, c, "debug", "derp-map", check=True).stdout)
        regions = dm.get("Regions") or {}
        want_id = "901" if slug == "tenant-a" else "902"
        reg = regions.get(want_id) or {}
        nodes = reg.get("Nodes") or []
        good = (list(regions) == [want_id] and reg.get("RegionCode") == f"mg-{slug}" and len(nodes) == 1
                and nodes[0].get("HostName") == f"{slug}.{st.mesh}" and nodes[0].get("IPv4") == st.edge_ip)
        ok &= good
        detail.append(f"{c}: {sorted(regions)} {reg.get('RegionCode')}")
    r.add("E2E-06", "DERP map: mỗi client chỉ có region DERP nhúng của tenant mình (urls: [], host tenant, IP điểm vào)",
          ok, "; ".join(detail))


def check_stun(r: Results, st: Stack) -> None:
    ok, detail = True, []
    for c, slug in CLIENTS.items():
        p = ts(st, c, "netcheck", "--format=json", timeout=60)
        try:
            nc = json.loads(p.stdout)
        except ValueError:
            ok = False
            detail.append(f"{c}: netcheck lỗi {p.stderr.strip()[:120]}")
            continue
        want = 901 if slug == "tenant-a" else 902
        good = nc.get("UDP") is True and nc.get("PreferredDERP") == want and bool(nc.get("GlobalV4"))
        ok &= good
        detail.append(f"{c}: UDP={nc.get('UDP')} GlobalV4={nc.get('GlobalV4')} DERP={nc.get('PreferredDERP')}")
    r.add("E2E-07", "STUN dùng chung tại IP điểm vào (stund trong netns của edge, như staging): netcheck UDP true, "
          "DERP ưa thích = region của tenant", ok, "; ".join(detail))


def check_tcp(r: Results, st: Stack, ips: dict[str, str]) -> None:
    for c in CLIENTS:
        start_listeners(st, c)
    time.sleep(1)
    allowed, denied = [], []
    for src, dst in (("a1", "a2"), ("a2", "a1"), ("b1", "b2"), ("b2", "b1")):
        want = f"mg-e2e {CLIENTS[dst]} {dst} tcp/{ALLOWED_PORT}"
        got = tcp(st, src, ips[dst], ALLOWED_PORT)
        allowed.append((f"{src}→{dst}:{ALLOWED_PORT}", got == want, got or "không có phản hồi"))
    for src, dst in (("a1", "a2"), ("b1", "b2")):
        control = local_tcp(st, dst, DENIED_PORT)
        got = tcp(st, src, ips[dst], DENIED_PORT)
        denied.append((f"{src}→{dst}:{DENIED_PORT}", got == "" and control.endswith(f"tcp/{DENIED_PORT}"),
                       f"qua tailnet: {got or 'không kết nối được'}; đối chứng cục bộ trên {dst}: {control or 'listener không chạy'}"))
    r.add("E2E-08", "TCP thật qua tailnet tới cổng được phép (tcp:8000), cả hai chiều, hai tenant — bên trả lời là "
          "đúng node cùng tenant", all(x[1] for x in allowed), "; ".join(f"{n}: {g}" for n, _, g in allowed))
    r.add("E2E-09", "TCP thật tới cổng không được phép (tcp:8001) bị chặn bởi policy (listener có chạy — đối chứng "
          "cục bộ)", all(x[1] for x in denied), "; ".join(f"{n}: {g}" for n, _, g in denied))


def check_paths(r: Results, st: Stack, ips: dict[str, str]) -> None:
    # tenant-a: TS_DEBUG_ALWAYS_USE_DERP ⇒ every packet via the tenant's own DERP (edge → hs-tenant-a /derp)
    detail, ok = [], True
    for src, dst in (("a1", "a2"), ("a2", "a1")):
        out = ts(st, src, "ping", "--until-direct=false", "-c", "3", "--timeout", "5s", ips[dst], timeout=60).stdout
        peer = next(p for p in peers(status(st, src)) if ip4(p) == ips[dst])
        good = "via DERP(mg-tenant-a)" in out and peer.get("Relay") == "mg-tenant-a" and not peer.get("CurAddr")
        ok &= good
        line = next((ln for ln in out.splitlines() if "pong" in ln), out.strip()[:120])
        detail.append(f"{src}→{dst}: {line}; Relay={peer.get('Relay')} CurAddr={peer.get('CurAddr') or '-'}")
    r.add("E2E-10", "Relay ép buộc (TS_DEBUG_ALWAYS_USE_DERP): đường của tenant-a đi qua DERP của chính tenant-a qua "
          "edge, TCP thật vẫn thông (E2E-08)", ok, "; ".join(detail))
    detail, ok = [], True
    for src, dst in (("b1", "b2"), ("b2", "b1")):
        out = ts(st, src, "ping", "-c", "10", "--timeout", "5s", ips[dst], timeout=90).stdout
        peer = next(p for p in peers(status(st, src)) if ip4(p) == ips[dst])
        good = bool(peer.get("CurAddr")) and "via DERP" not in (out.strip().splitlines() or [""])[-1]
        ok &= good
        detail.append(f"{src}→{dst}: CurAddr={peer.get('CurAddr') or '-'} Relay={peer.get('Relay')}")
    r.add("E2E-11", "Đường trực tiếp giữa hai client tenant-b (cùng bridge Docker — chỉ functional, không phải P2P qua "
          "NAT)", ok, "; ".join(detail))


def _https(st: Stack, ctx: ssl.SSLContext, sni: str, method: str, path: str, headers: dict | None = None,
           host: str | None = None):
    try:
        raw = socket.create_connection((st.edge_ip, 443), timeout=8)
        tls = ctx.wrap_socket(raw, server_hostname=sni)
    except (OSError, ssl.SSLError) as e:
        return None, f"{type(e).__name__}: {e}"
    conn = http.client.HTTPConnection(st.edge_ip, 443, timeout=8)
    conn.sock = tls
    try:
        conn.request(method, path, headers={"Host": host or sni, **(headers or {})})
        res = conn.getresponse()
        return res.status, res.read(4096).decode("utf-8", "replace")
    except (OSError, http.client.HTTPException) as e:
        return None, f"{type(e).__name__}: {e}"
    finally:
        conn.close()


def check_edge_public(r: Results, st: Stack, api_keys: dict[str, str]) -> None:
    ctx = ssl.create_default_context(cafile=str(st.work / "ca" / "ca.crt"))   # ONLY the run's CA
    bad, controls, n = [], {}, 0
    for slug in TENANTS:
        host = f"{slug}.{st.mesh}"
        auth = {"Authorization": f"Bearer {api_keys[slug]}"}       # a real, valid key: Headscale would answer 200
        code, body = _https(st, ctx, host, "GET", "/key?v=113")
        controls[slug] = (code, body)
        paths = sorted(set(REQUIRED_FORBIDDEN) | set(conformance.FORBIDDEN_PUBLIC))
        for path in paths:
            for method in (("GET", "POST") if path == "/verify" else ("GET",)):
                code, _ = _https(st, ctx, host, method, path, headers=auth if path.startswith("/api/") else None)
                n += 1
                if code != 404:
                    bad.append(f"{host} {method} {path} ⇒ {code}")
        for path in conformance.TRAVERSAL:
            if conformance.allowed_public(conformance.normalized(path)):
                continue
            code, _ = _https(st, ctx, host, "GET", path, headers=auth)
            n += 1
            if code is not None and code < 400:
                bad.append(f"{host} traversal {path} ⇒ {code}")
    keys = {}
    for slug, (code, body) in controls.items():
        try:
            keys[slug] = json.loads(body).get("publicKey") if code == 200 else None
        except ValueError:
            keys[slug] = None
    ok_ctrl = all(keys.values()) and keys["tenant-a"] != keys["tenant-b"]
    r.add("E2E-12", "Edge (Caddyfile thật, TLS từ CA nội bộ): allow-list chặn /api/v1 (kèm API key thật), /swagger, "
          "/verify, /metrics… ⇒ 404 trên cả hai hostname tenant; /key tới đúng instance của từng tenant",
          not bad and ok_ctrl, f"{n} request bị chặn đúng" if not bad else "; ".join(bad[:8]))
    code, _ = _https(st, ctx, f"tenant-a.{st.mesh}", "GET", "/key?v=113", host=f"tenant-b.{st.mesh}")
    r.add("E2E-12b", "SNI tenant-a + Host tenant-b ⇒ 421 (strict_sni_host, không domain fronting giữa tenant)",
          code == 421, f"status {code}")


def check_edge_admin(r: Results, st: Stack, api_keys: dict[str, str]) -> None:
    """From a container on the admin network (role of api/worker): the instance API key is valid only on its own
    instance; requests are written to files by this process (no secret in any command line)."""
    token = (st.work / "secrets" / "harness" / "admin_token").read_text(encoding="ascii")
    st.secret_values.add(token)
    cases = {"a-on-a": ("tenant-a", api_keys["tenant-a"], token, "200"),
             "a-on-b": ("tenant-b", api_keys["tenant-a"], token, "401"),
             "b-on-b": ("tenant-b", api_keys["tenant-b"], token, "200"),
             "no-token": ("tenant-a", api_keys["tenant-a"], None, "403")}
    req_dir = st.fresh_dir("secrets/caller")
    for name, (inst, key, tok, _) in cases.items():
        lines = ["GET /api/v1/node HTTP/1.1", "Host: edge-admin", f"X-MG-Instance: {inst}", f"Authorization: Bearer {key}",
                 "Connection: close"] + ([f"X-MG-Token: {tok}"] if tok else [])
        st.write_private(req_dir / f"{name}.http", "\r\n".join(lines) + "\r\n\r\n")
    st.helper(f"chown -R 65534:65534 /w/secrets/caller; chmod 0500 /w/secrets/caller; chmod 0400 /w/secrets/caller/*",
              f"{st.work}:/w")
    # busybox nc half-closes on stdin EOF and Caddy then cancels the proxied request (499): keep stdin open briefly
    script = "; ".join(f'printf "{n} "; (cat /req/{n}.http; sleep 2) | nc -w 10 {st.admin_ip} 8081 | head -1'
                       for n in cases)
    out = st.docker("run", "--rm", "--name", st.name("caller"), "--network", st.name("admin"), "--user", "65534:65534",
                    "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                    "-v", f"{req_dir}:/req:ro", st.images["alpine"], "sh", "-c", script, check=False).stdout
    got = {ln.split()[0]: (ln.split() + ["", ""])[2] for ln in out.splitlines() if ln.strip()}
    ok = all(got.get(n) == want for n, (*_, want) in cases.items())
    r.add("E2E-13", "Listener admin nội bộ của edge (từ network admin): API key của instance chỉ dùng được trên chính "
          "instance đó; thiếu token ⇒ 403", ok, ", ".join(f"{n} ⇒ {got.get(n) or '?'} (cần {w})"
                                                       for n, (*_, w) in cases.items()))


def probe_enroll(st: Stack, key_file: str, slug: str, host: str) -> tuple[int, str, str]:
    """Throwaway official client (userspace, state in memory) tries `tailscale up` with a key file on `slug`."""
    script = ('tailscaled --tun=userspace-networking --state=mem: --socket=/tmp/ts.sock --statedir=/tmp/st '
              '>/tmp/tsd.log 2>&1 & i=0; while [ ! -S /tmp/ts.sock ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done; '
              'timeout 45 tailscale --socket=/tmp/ts.sock up --login-server="$LOGIN" --auth-key=file:/run/mg-e2e/authkey '
              '--hostname="$HN" --accept-dns=false --timeout=30s >/tmp/up.log 2>&1; rc=$?; '
              'st=$(tailscale --socket=/tmp/ts.sock status --json 2>/dev/null | grep -m1 BackendState | tr -dc A-Za-z:); '
              'echo "rc=$rc $st"; head -c 300 /tmp/up.log | tr "\\n" " "')
    p = st.docker("run", "--rm", "--name", st.name(f"probe-{host}"), "--network", st.name("edge"),
                  "--add-host", f"tenant-a.{st.mesh}:{st.edge_ip}", "--add-host", f"tenant-b.{st.mesh}:{st.edge_ip}",
                  "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                  "-v", f"{st.work / 'ca'}:/etc/mg-ci-ca:ro", "-v", f"{key_file}:/run/mg-e2e/authkey:ro",
                  "-e", "SSL_CERT_FILE=/etc/mg-ci-ca/ca.crt", "-e", "SSL_CERT_DIR=/etc/mg-ci-ca",
                  "-e", "TS_NO_LOGS_NO_SUPPORT=true", "-e", f"LOGIN=https://{slug}.{st.mesh}", "-e", f"HN={host}",
                  "--entrypoint", "sh", st.images["tailscale"], "-c", script, check=False, timeout=120)
    first = p.stdout.strip().splitlines()[0] if p.stdout.strip() else ""
    rc = int(first.split()[0][3:]) if first.startswith("rc=") else -1
    state = first.split("BackendState:")[-1] if "BackendState:" in first else "?"
    return rc, state, st.redact(p.stdout.strip())


def check_cross_tenant_key(r: Results, st: Stack) -> None:
    keys = {}
    probe = st.fresh_dir("probe")
    for slug in TENANTS:
        uid = st.users[slug]
        k = json.loads(st.headscale(slug, "preauthkeys", "create", "-u", uid, "-e", "15m", "-o", "json").stdout)["key"]
        st.secret_values.add(k)
        st.write_private(probe / f"{slug}.key", k)
        keys[slug] = str(probe / f"{slug}.key")
    st.helper("chown 0:0 /w/probe/*.key; chmod 0400 /w/probe/*.key", f"{st.work}:/w")
    rows, ok = [], True
    for key_of, on, expect in (("tenant-a", "tenant-b", "reject"), ("tenant-b", "tenant-a", "reject"),
                               ("tenant-a", "tenant-a", "accept"), ("tenant-b", "tenant-b", "accept")):
        host = f"it13-{key_of[-1]}-on-{on[-1]}"
        rc, state, out = probe_enroll(st, keys[key_of], on, host)
        good = (rc != 0 and state != "Running") if expect == "reject" else (rc == 0 and state == "Running")
        ok &= good
        msg = out.split("\n", 1)[-1][:160] if expect == "reject" else ""
        if expect == "accept":                     # the control node leaves the tenant again (verified)
            def control_nodes(on=on, host=host):
                nodes = json.loads(st.headscale(on, "nodes", "list", "-o", "json").stdout or "[]") or []
                return [n for n in nodes if (n.get("given_name") or n.get("name")) == host]
            for n in control_nodes():
                st.headscale(on, "nodes", "delete", "--identifier", str(n["id"]), "--force")
            gone = bool(wait(lambda: not control_nodes(), 15))
            ok &= gone
            msg = "node đối chứng đã xóa" if gone else "node đối chứng CHƯA xóa được"
        rows.append(f"key {key_of} → {on}: rc={rc} state={state}{' — ' + msg if msg else ''}")
    r.add("E2E-14", "AC-14/IT-13 (functional): pre-auth key của tenant này bị tenant kia từ chối (hai chiều); đối chứng: "
          "cùng key đăng ký được ở đúng tenant (key không bị tiêu khi bị từ chối)", ok, "; ".join(rows))


def check_deny(r: Results, st: Stack, ips: dict[str, str]) -> None:
    for slug in TENANTS:
        st.headscale(slug, "policy", "set", "-f", "/etc/headscale/bootstrap-policy.hujson")
    counts = {c: len(peers(wait_peer_count(st, c, 0, 60) or status(st, c))) for c in CLIENTS}
    got = {f"{s}→{d}": tcp(st, s, ips[d], ALLOWED_PORT) for s, d in (("a1", "a2"), ("b1", "b2"))}
    r.add("E2E-15", "Policy chuyển về deny-all: peer biến mất và TCP tới cổng vừa được phép (8000) bị chặn",
          all(n == 0 for n in counts.values()) and not any(got.values()),
          f"số peer {counts}; " + ", ".join(f"{k}: {v or 'không kết nối được'}" for k, v in got.items()))
