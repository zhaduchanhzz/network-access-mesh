"""Kênh điều khiển giữa spec Playwright và harness (P4-T14, G4b) — FUNCTIONAL only (§22.1).

Trình duyệt chạy trong container Playwright; phần "thế giới bên ngoài" của các luồng G4b (THIẾT BỊ chạy client Tailscale
chính thức, đồng hồ của phiên cho step-up, thành viên dùng-một-lần, dọn node) chỉ harness làm được. Spec ghi một yêu cầu
JSON vào <work>/state/pw/ctl/<id>.req.json (gắn vào container ở /pw/ctl, thư mục 0700 — không phải thư mục kết quả), harness
xử lý trong lúc Playwright chạy (`Control.poll`, gọi từ vòng chờ của playwrightui.run_once) rồi ghi <id>.res.json (0600,
ghi tạm + rename). Thao tác (op), đều chỉ trên tenant-a của stack dev/CI:

  webauth_client {tag, hostname}  client chính thức `tailscale up --login-server https://tenant-a.<mesh> --hostname <hn>`
                                  KHÔNG key ⇒ link /register/<auth_id> client in ra ⇒ {client, link} (trình duyệt tự mở link
                                  qua edge — 302 về trang claim của Portal)
  key_client {tag, key, hostname} client chính thức dùng pre-auth key (tệp 0400 trong container) ⇒ {client}
  client_state {client}           BackendState của client do kênh này tạo
  nodes {prefixes}                node của tenant-a có name/given_name bắt đầu bằng một prefix (id, name, given_name, user)
  cleanup {clients, prefixes}     gỡ client + node còn sót (CLI Headscale) — mỗi ca tự dọn để không ảnh hưởng ca sau
                                  (bài học E2E-118)
  age_session {identity_id, origin}  đẩy auth_time của phiên MỚI NHẤT còn sống của danh tính (origin app|admin) về 20 phút
                                  trước (như policylife.py) ⇒ thao tác nhạy cảm kế tiếp nhận 401 reauth_required (step-up)
  new_member {}                   một End User dùng-một-lần của tenant-a (mời qua API bởi một Owner riêng của harness +
                                  đăng nhập lần đầu) ⇒ {id, name, email} — đối tượng của ca đổi role / offboard
  grants_cleanup {}               thu hồi mọi Support Access Grant còn mở của tenant-a (dọn sau ca C4 dù ca lỗi giữa chừng)

Giá trị nhạy cảm (pre-auth key, Auth ID, mật khẩu của user mới) vào tập redaction của lượt (PW-S dò lại artifact).
Thư viện chuẩn.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import time

import enrollment
import webauth
from backend import Browser, portal_login, psql
from dualcontrol import owner_session, psql_one, tenant_id
from members import invited_member
from stack import TENANTS, Stack, StackError, log

SLUG = "tenant-a"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
TAG_RE = re.compile(r"^[a-z0-9-]{1,24}$")
HOST_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
PREFIX_RE = re.compile(r"^pw[a-z0-9-]{1,40}$")     # chỉ node/nhãn do spec đặt (pw…) mới được dọn


def ctl_dir(st: Stack) -> pathlib.Path:
    return st.work / "state" / "pw" / "ctl"


class Control:
    def __init__(self, st: Stack):
        self.st = st
        self.dir = ctl_dir(st)
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        for f in self.dir.glob("*"):
            f.unlink(missing_ok=True)
        self.clients: set[str] = set()
        self.a_id = tenant_id(st, SLUG)
        self._owner: tuple[Browser, dict, float] | None = None
        self._owner_user: dict | None = None
        self.handled = 0

    # ------------------------------------------------------------------------------------------------ vòng xử lý
    def poll(self) -> None:
        for req in sorted(self.dir.glob("*.req.json")):
            rid = req.name[: -len(".req.json")]
            try:
                data = json.loads(req.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue            # đang ghi dở (spec ghi tạm rồi rename — hiếm)
            req.unlink(missing_ok=True)
            op = str(data.get("op", ""))
            t0 = time.time()
            try:
                fn = getattr(self, f"op_{op}", None)
                if fn is None or not re.fullmatch(r"[a-z_]{1,32}", op):
                    raise StackError(f"op không biết: {op!r}")
                out = fn(data)
            except (StackError, OSError, ValueError, KeyError, TypeError) as e:
                out = {"error": f"{type(e).__name__}: {self.st.redact(str(e))[-600:]}"}
            self.handled += 1
            log(f"pwctl {op}: {'LỖI ' + out['error'] if 'error' in out else 'xong'} ({time.time() - t0:.1f} s)")
            tmp = self.dir / f"{rid}.res.tmp"
            tmp.write_text(json.dumps(out), encoding="utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.dir / f"{rid}.res.json")

    def close(self) -> None:
        for c in sorted(self.clients):
            self.st.docker("rm", "-f", c, check=False)
        self.clients.clear()
        try:
            self.op_cleanup({"clients": [], "prefixes": ["pw"]})
        except StackError:
            pass

    # ------------------------------------------------------------------------------------------------ thiết bị
    def _client(self, tag: str, hostname: str, key_file: str | None = None) -> str:
        """Client chính thức chạy lâu (userspace, state trong bộ nhớ), tên <prefix>-pwc-<tag> (teardown gỡ mọi pw*)."""
        if not TAG_RE.match(tag) or not HOST_RE.match(hostname):
            raise StackError("tag/hostname sai dạng")
        st = self.st
        name = st.name(f"pwc-{tag}")
        st.docker("rm", "-f", name, check=False)
        auth = '--auth-key=file:/run/mg-e2e/authkey ' if key_file else ''
        script = ('tailscaled --tun=userspace-networking --state=mem: --socket=/tmp/ts.sock --statedir=/tmp/st '
                  '>/tmp/tsd.log 2>&1 & i=0; while [ ! -S /tmp/ts.sock ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done; '
                  f'(timeout 600 tailscale --socket=/tmp/ts.sock up --login-server="$LOGIN" {auth}--hostname="$HN" '
                  '--accept-dns=false --timeout=580s >/tmp/up.log 2>&1 &); exec sleep 1200')
        args = ["run", "-d", "--name", name, "--network", st.name("edge"), "--label", "meshguard.role=e2e",
                *[x for s in TENANTS for x in ("--add-host", f"{s}.{st.mesh}:{st.edge_ip}")],
                "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                "-v", f"{st.work / 'ca'}:/etc/mg-ci-ca:ro", "-e", "SSL_CERT_FILE=/etc/mg-ci-ca/ca.crt",
                "-e", "SSL_CERT_DIR=/etc/mg-ci-ca", "-e", "TS_NO_LOGS_NO_SUPPORT=true",
                "-e", f"LOGIN=https://{SLUG}.{st.mesh}", "-e", f"HN={hostname}"]
        if key_file:
            args += ["-v", f"{key_file}:/run/mg-e2e/authkey:ro"]
        st.docker(*args, "--entrypoint", "sh", st.images["tailscale"], "-c", script)
        self.clients.add(name)
        return name

    def op_webauth_client(self, d: dict) -> dict:
        name = self._client(str(d["tag"]), str(d["hostname"]))
        host, auth = webauth._link(self.st, name, 90)       # Auth ID vào tập redaction
        if not auth:
            log_tail = self.st.docker("exec", name, "tail", "-c", "400", "/tmp/up.log", check=False).stdout
            raise StackError(f"client không in link đăng nhập: {self.st.redact(log_tail)!r}")
        return {"client": name, "link": f"https://{host}/register/{auth}"}

    def op_key_client(self, d: dict) -> dict:
        key, tag = str(d["key"]), str(d["tag"])
        if not re.fullmatch(r"hskey-auth-[A-Za-z0-9_-]{8,200}", key):
            raise StackError("pre-auth key sai dạng")
        self.st.secret_values.add(key)
        f = enrollment._key_file(self.st, f"pw-{tag}", key)
        return {"client": self._client(tag, str(d["hostname"]), key_file=f)}

    def op_client_state(self, d: dict) -> dict:
        name = str(d["client"])
        if name not in self.clients:
            raise StackError("client không do kênh này tạo")
        return {"state": webauth._backend_state(self.st, name)}

    def _nodes(self, prefixes: list[str]) -> list[dict]:
        if not prefixes or not all(PREFIX_RE.match(p) or p == "pw" for p in prefixes):
            raise StackError("prefix phải bắt đầu bằng pw")
        out = []
        for n in webauth._nodes(self.st, SLUG):
            names = (str(n.get("name") or ""), str(n.get("given_name") or ""))
            if any(x.startswith(p) for x in names for p in prefixes):
                out.append({"id": str(n.get("id")), "name": names[0], "given_name": names[1],
                            "user": (n.get("user") or {}).get("name", ""), "online": bool(n.get("online"))})
        return out

    def op_nodes(self, d: dict) -> dict:
        return {"nodes": self._nodes([str(p) for p in d.get("prefixes", [])])}

    def op_cleanup(self, d: dict) -> dict:
        removed = []
        for c in d.get("clients", []):
            if c in self.clients:
                self.st.docker("rm", "-f", c, check=False)
                self.clients.discard(c)
                removed.append(c)
        nodes = self._nodes([str(p) for p in d.get("prefixes", [])]) if d.get("prefixes") else []
        for n in nodes:
            self.st.headscale(SLUG, "nodes", "delete", "--identifier", n["id"], "--force", check=False)
        left = self._nodes([str(p) for p in d.get("prefixes", [])]) if d.get("prefixes") else []
        return {"clients": removed, "deleted_nodes": [n["given_name"] or n["name"] for n in nodes], "left": len(left)}

    # ------------------------------------------------------------------------------------------------ phiên / thành viên
    def op_age_session(self, d: dict) -> dict:
        ident, origin = str(d["identity_id"]), str(d.get("origin", "app"))
        if not UUID_RE.match(ident) or origin not in ("app", "admin"):
            raise StackError("identity_id/origin sai")
        n = psql_one(self.st, "WITH s AS (SELECT id_hash FROM sessions WHERE identity_id = '" + ident + "' AND origin = '"
                     + origin + "' AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1), u AS (UPDATE sessions SET "
                     "auth_time = now() - interval '20 minutes' WHERE id_hash IN (SELECT id_hash FROM s) RETURNING 1) "
                     "SELECT count(*) FROM u")
        if n != "1":
            raise StackError(f"không thấy phiên còn sống của danh tính ({n})")
        return {"aged": 1}

    def _ops_owner(self) -> tuple[Browser, dict]:
        """Owner RIÊNG của harness (không phải user nào của Playwright — bộ đếm TOTP không chung), đăng nhập lại khi phiên
        đã quá 20 phút (idle 30 phút của tenant)."""
        if self._owner and time.time() - self._owner[2] < 1200:
            return self._owner[0], self._owner[1]
        if self._owner_user is None:
            b, sess, u = owner_session(self.st, SLUG)
            self._owner_user = u
        else:
            b = Browser(self.st)
            sess, _ = portal_login(self.st, b, f"app.{self.st.domain}", f"scope=tenant&tenant={SLUG}", self._owner_user,
                                   self._owner_user["otp"])
        self.st.secret_values.add(sess.get("csrf_token", ""))
        self._owner = (b, sess, time.time())
        return b, sess

    def op_new_member(self, _d: dict) -> dict:
        ob, osess = self._ops_owner()
        u, _, s, _ = invited_member(self.st, ob, osess, self.a_id, "end_user")
        rows = psql(self.st, "SELECT m.id, coalesce(i.display_name, ''), coalesce(i.email, '') FROM tenant_memberships m "
                             "JOIN identities i ON i.id = m.identity_id WHERE i.subject = '" + u["sub"] + "' AND m.tenant_id = '"
                             + self.a_id + "'")
        if not rows or not UUID_RE.match(rows[0][0]):
            raise StackError("không thấy membership của thành viên mới")
        return {"id": rows[0][0], "name": rows[0][1], "email": rows[0][2]}

    def op_grants_cleanup(self, _d: dict) -> dict:
        n = psql_one(self.st, "WITH u AS (UPDATE support_access_grants SET status = 'revoked', revoked_at = now(), updated_at = "
                     "now(), version = version + 1 WHERE tenant_id = '" + self.a_id + "' AND status IN ('pending', 'approved') "
                     "RETURNING 1) SELECT count(*) FROM u")
        return {"revoked": int(n or 0)}

