#!/usr/bin/env python3
"""P2-T05 — đăng nhập thử từng realm của IdP như trình duyệt của Portal (§8.3), trên stack dev/CI (tests/idp/run_dev.sh).

Với MỖI realm đã render (platform, tenant-a, tenant-b):
  * discovery: issuer = https://auth.<domain>/realms/<realm>, có hỗ trợ tham số iss (RFC 9207) và PKCE S256; grant
    của feature đã tắt (device, CIBA, token exchange) bị token endpoint từ chối;
  * service account mg-idp-driver (client credentials) tạo user thử có mật khẩu — user mới mang sẵn CONFIGURE_TOTP;
  * đăng nhập 1 (lần đầu): Authorization Code + PKCE S256 qua form HTML: mật khẩu → BẮT BUỘC cấu hình TOTP (mã tính bằng
    hmac/hashlib) → code → đổi code bằng client mg-portal → ID token: chữ ký RS256 theo JWKS của realm, iss, aud, azp,
    nonce, exp, auth_time; không có refresh token;
  * đăng nhập 2 (trình duyệt mới): mật khẩu → OTP sai bị từ chối → OTP đúng → ID token mới;
  * SSO (cùng trình duyệt, không prompt): code ngay, auth_time giữ nguyên; prompt=login (step-up): phải nhập lại mật
    khẩu + OTP, auth_time mới — đúng cơ chế step-up của §8.3 bước 7;
  * bị từ chối: password grant (mg-portal, admin-cli, mg-idp-driver), client_credentials trên mg-portal, implicit,
    thiếu PKCE, PKCE plain, redirect URI khác (callback của realm khác, đuôi thêm);
  * impersonation không dùng được: feature tắt (serverinfo), POST …/impersonation trả lỗi kể cả với admin master;
  * service account chỉ quản lý user của realm mình: realm khác, clients, tạo realm ⇒ bị từ chối;
  * brute force: 4 lần sai chưa khóa, lần sai thứ 5 khóa tạm — mật khẩu đúng cũng không vào được;
  * /metrics và /health KHÔNG có trên hostname công khai (chỉ ở cổng quản trị nội bộ 9000).
Sau cùng: ba issuer khác nhau và ba khóa ký khác nhau.

Thông tin admin khởi tạo (bootstrap admin của realm master) CHỈ dùng trong test để đọc secret của client và kiểm
impersonation; không in ra. Mật khẩu/TOTP của user thử sinh ngẫu nhiên mỗi lượt, không in ra; user thử bị xóa khi xong.

    python3 tests/idp/login_test.py --base-url https://auth.<domain> --realms-dir <render>/idp/realms \\
        --admin-conf <keycloak.conf> [--connect 127.0.0.1:18443] [--cafile ca.crt] [--report out.json] \\
        [--event-ip-present IP]... [--event-ip-absent IP]...

--connect: nối TCP tới địa chỉ này nhưng vẫn dùng hostname cho SNI/kiểm chứng chỉ (như curl --connect-to) — không đụng
DNS. --event-ip-*: kiểm proxy tin cậy — IP phải có / không được có trong event CLIENT_LOGIN_ERROR của realm platform.
Chỉ thư viện chuẩn của Python. Mã thoát 0 = đạt.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import html.parser
import http.client
import json
import pathlib
import secrets
import socket
import ssl
import sys
import time
import urllib.parse

PORTAL, DRIVER = "mg-portal", "mg-idp-driver"
DRIVER_ROLES = {"manage-users", "view-users", "query-users"}
UA = "meshguard-p2t05-login-test"
failures: list[str] = []


def check(ok: bool, name: str, detail: str = "") -> bool:
    print(f"{'PASS' if ok else 'FAIL'} {name}{'' if ok or not detail else ': ' + detail}", flush=True)
    if not ok:
        failures.append(name)
    return ok


# ---------------------------------------------------------------- TOTP (RFC 4226 / RFC 6238), JWT RS256
def hotp(key: bytes, counter: int, digits: int = 6) -> str:
    mac = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return f"{(int.from_bytes(mac[off:off + 4], 'big') & 0x7FFFFFFF) % 10 ** digits:0{digits}d}"


class Totp:
    """One TOTP credential. Keycloak refuses a code twice (otpPolicyCodeReusable=false) and accepts ±1 period
    (otpPolicyLookAheadWindow=1): use the current or the next counter, strictly increasing; otherwise wait."""

    def __init__(self, key: bytes, period: int = 30):
        self.key, self.period, self.last = key, period, -1

    def code(self) -> str:
        while True:
            now = int(time.time() // self.period)
            for c in (now, now + 1):
                if c > self.last:
                    self.last = c
                    return hotp(self.key, c)
            time.sleep(self.period - time.time() % self.period + 0.5)

    def wrong(self) -> str:
        now = int(time.time() // self.period)
        valid = {hotp(self.key, c) for c in range(now - 2, now + 3)}
        return next(c for c in ("000000", "111111", "123456", "999999") if c not in valid)


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def verify_rs256(jwt: str, jwks: dict) -> tuple[dict, dict]:
    """RSASSA-PKCS1-v1_5 + SHA-256 (RFC 7518 §3.3) with the realm's JWKS — pure integer arithmetic."""
    h64, p64, s64 = jwt.split(".")
    header = json.loads(b64d(h64))
    if header.get("alg") != "RS256":
        raise ValueError(f"alg {header.get('alg')}")
    key = next((k for k in jwks["keys"] if k.get("kid") == header.get("kid") and k.get("kty") == "RSA"), None)
    if not key:
        raise ValueError("kid không có trong JWKS của realm")
    n, e = int.from_bytes(b64d(key["n"]), "big"), int.from_bytes(b64d(key["e"]), "big")
    k = (n.bit_length() + 7) // 8
    em = pow(int.from_bytes(b64d(s64), "big"), e, n).to_bytes(k, "big")
    digest = hashlib.sha256(f"{h64}.{p64}".encode()).digest()
    want = b"\x00\x01" + b"\xff" * (k - 3 - len(SHA256_DIGEST_INFO) - len(digest)) + b"\x00" + SHA256_DIGEST_INFO + digest
    if not hmac.compare_digest(em, want):
        raise ValueError("chữ ký sai")
    return header, json.loads(b64d(p64))


def unverified_claims(jwt: str) -> dict:
    return json.loads(b64d(jwt.split(".")[1]))


# ---------------------------------------------------------------- HTTP: one host, pinned address, cookie jar
class Resp:
    def __init__(self, status: int, headers, body: bytes):
        self.status, self.headers, self.body = status, headers, body

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.body) if self.body.strip() else None


class Jar:
    """Minimal cookie jar for the single IdP host (Keycloak sets AUTH_SESSION_ID, KC_RESTART, KEYCLOAK_IDENTITY…)."""

    def __init__(self):
        self.c: dict[str, str] = {}

    def update(self, set_cookies: list[str]) -> None:
        for sc in set_cookies:
            parts = [p.strip() for p in sc.split(";")]
            if "=" not in parts[0]:
                continue
            name, value = parts[0].split("=", 1)
            attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1)[1] if "=" in p else "") for p in parts[1:]}
            gone = attrs.get("max-age") == "0" or value == ""
            if "expires" in attrs and not gone:
                try:
                    gone = time.mktime(time.strptime(attrs["expires"][5:25], "%d %b %Y %H:%M:%S")) - time.timezone < time.time()
                except ValueError:
                    pass
            if gone:
                self.c.pop(name, None)
            else:
                self.c[name] = value

    def header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.c.items())


class Http:
    def __init__(self, base_url: str, connect: tuple[str, int] | None, cafile: str | None):
        u = urllib.parse.urlsplit(base_url)
        if u.scheme != "https" or not u.hostname:
            raise SystemExit("--base-url phải là https://<host>")
        self.base, self.host, self.port, self.connect = base_url.rstrip("/"), u.hostname, u.port or 443, connect
        self.ctx = ssl.create_default_context(cafile=cafile)

    def request(self, method: str, url: str, *, body: bytes | None = None, headers: dict | None = None,
                jar: Jar | None = None) -> Resp:
        u = urllib.parse.urlsplit(urllib.parse.urljoin(self.base + "/", url))
        if u.scheme != "https" or u.hostname != self.host:
            raise AssertionError(f"không gọi host khác: {u.geturl()}")
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=30)
        if self.connect:
            target = self.connect
            conn._create_connection = lambda addr, timeout=None, source_address=None: socket.create_connection(
                target, timeout, source_address)
        h = {"User-Agent": UA, "Accept": "*/*"}
        h.update(headers or {})
        if jar is not None and jar.c:
            h["Cookie"] = jar.header()
        try:
            conn.request(method, u.path + (f"?{u.query}" if u.query else ""), body=body, headers=h)
            r = conn.getresponse()
            data = r.read()
        finally:
            conn.close()
        if jar is not None:
            jar.update(r.headers.get_all("Set-Cookie") or [])
        return Resp(r.status, r.headers, data)

    def get(self, url: str, **kw) -> Resp:
        return self.request("GET", url, **kw)

    def form(self, url: str, data: dict, *, basic: tuple[str, str] | None = None, bearer: str | None = None,
             jar: Jar | None = None, headers: dict | None = None) -> Resp:
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        if basic:   # RFC 6749 §2.3.1: form-urlencode id and secret, then Basic
            cred = f"{urllib.parse.quote(basic[0], safe='')}:{urllib.parse.quote(basic[1], safe='')}"
            h["Authorization"] = "Basic " + base64.b64encode(cred.encode()).decode()
        if bearer:
            h["Authorization"] = "Bearer " + bearer
        h.update(headers or {})
        return self.request("POST", url, body=urllib.parse.urlencode(data).encode(), headers=h, jar=jar)

    def api(self, method: str, path: str, token: str, payload=None) -> Resp:
        h = {"Authorization": "Bearer " + token, "Accept": "application/json"}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode()
            h["Content-Type"] = "application/json"
        return self.request(method, path, body=body, headers=h)


class Page(html.parser.HTMLParser):
    """Forms (action, inputs) and visible error texts of a Keycloak login page — theme-agnostic."""

    def __init__(self, text: str):
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self.errors: list[str] = []
        self.title = ""
        self._form = None
        self._grab: list[str] | None = None
        self._grab_tag = None
        self._depth = 0
        self._in_title = False
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "form":
            self._form = {"id": a.get("id", ""), "action": a.get("action", ""), "inputs": {}}
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None and a.get("name"):
            kind = a.get("type", "text").lower()
            if kind in ("checkbox", "radio") and "checked" not in a:
                return
            if kind not in ("submit", "button", "image", "reset"):
                self._form["inputs"][a["name"]] = a.get("value", "")
        elif tag == "title":
            self._in_title = True
        cls, ident = a.get("class", ""), a.get("id", "")
        if self._grab is None and (ident.startswith("input-error") or "kc-feedback-text" in cls
                                   or "alert-error" in cls or "pf-m-danger" in cls or ident == "kc-error-message"):
            self._grab, self._grab_tag, self._depth = [], tag, 0
        elif self._grab is not None and tag == self._grab_tag:
            self._depth += 1

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None
        elif tag == "title":
            self._in_title = False
        if self._grab is not None and tag == self._grab_tag:
            if self._depth == 0:
                t = " ".join("".join(self._grab).split())
                if t:
                    self.errors.append(t)
                self._grab = None
            else:
                self._depth -= 1

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._grab is not None:
            self._grab.append(data)

    def form_with(self, *names: str) -> dict | None:
        return next((f for f in self.forms if all(n in f["inputs"] for n in names)), None)

    def describe(self) -> str:
        return f"title={self.title.strip()!r} forms={[(f['id'], sorted(f['inputs'])) for f in self.forms]} errors={self.errors}"


# ---------------------------------------------------------------- the Portal's side of the flow (§8.3)
class Realm:
    def __init__(self, name: str, rep: dict, base: str):
        self.name, self.issuer = name, f"{base}/realms/{name}"
        portal = next(c for c in rep["clients"] if c["clientId"] == PORTAL)
        self.redirect = portal["redirectUris"][0]
        self.auth_url = self.token_url = self.jwks = None
        self.portal_secret = self.driver_secret = None
        self.summary: dict = {"realm": name, "issuer": self.issuer, "redirect_uri": self.redirect}


class Login:
    """One browser-style login attempt: Authorization Code + PKCE S256, returns the redirect parameters."""

    def __init__(self, http: Http, realm: Realm, jar: Jar | None = None, **extra):
        self.http, self.realm, self.jar = http, realm, jar or Jar()
        self.state, self.nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        self.verifier = secrets.token_urlsafe(48)
        challenge = b64e(hashlib.sha256(self.verifier.encode()).digest())
        q = {"client_id": PORTAL, "response_type": "code", "scope": "openid", "redirect_uri": realm.redirect,
             "state": self.state, "nonce": self.nonce, "code_challenge": challenge, "code_challenge_method": "S256"}
        q.update(extra)    # giá trị None = bỏ hẳn tham số
        self.url = realm.auth_url + "?" + urllib.parse.urlencode({k: v for k, v in q.items() if v is not None})
        self.steps: list[str] = []
        self.result: dict | None = None
        self.last_page: Page | None = None

    def run(self, user: str, password: str, totp: Totp | None, *, wrong_otp_first: bool = False) -> "Login":
        r = self.http.get(self.url, jar=self.jar)
        wrong_sent = False
        for _ in range(16):
            if r.status in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "")
                if loc.startswith(self.realm.redirect + "?") or loc.startswith(self.realm.redirect + "#"):
                    sep = "?" if "?" in loc else "#"
                    self.result = dict(urllib.parse.parse_qsl(loc.split(sep, 1)[1]))
                    return self
                if loc.startswith(self.realm.redirect):
                    raise AssertionError("redirect lạ")
                r = self.http.get(loc, jar=self.jar)
                continue
            page = Page(r.text)
            self.last_page = page
            if r.status != 200:
                raise AssertionError(f"HTTP {r.status}: {page.describe()}")
            f = page.form_with("password")
            if f is not None and "totp" not in f["inputs"]:
                data = dict(f["inputs"])
                if "username" in data:
                    data["username"] = user
                data["password"] = password
                self.steps.append("password")
                r = self.http.form(f["action"], data, jar=self.jar)
                continue
            f = page.form_with("totp", "totpSecret")
            if f is not None:
                if totp is None:
                    raise AssertionError("trang cấu hình TOTP nhưng test không chờ")
                totp.key = f["inputs"]["totpSecret"].encode()   # secret thô; base32 của nó là chuỗi hiện cho user
                data = dict(f["inputs"])
                data.update({"totp": totp.code(), "userLabel": "p2t05-test"})
                self.steps.append("configure_totp")
                r = self.http.form(f["action"], data, jar=self.jar)
                continue
            f = page.form_with("otp")
            if f is not None:
                if totp is None or not totp.key:
                    raise AssertionError("trang OTP nhưng user chưa có TOTP")
                data = dict(f["inputs"])
                if wrong_otp_first and not wrong_sent:
                    data["otp"], wrong_sent = totp.wrong(), True
                    self.steps.append("otp_wrong")
                else:
                    data["otp"] = totp.code()
                    self.steps.append("otp")
                r = self.http.form(f["action"], data, jar=self.jar)
                continue
            raise AssertionError(f"trang không mong đợi: {page.describe()}")
        raise AssertionError("quá nhiều bước")


def exchange(http: Http, realm: Realm, login: Login, verifier: str | None = None) -> Resp:
    return http.form(realm.token_url, {"grant_type": "authorization_code", "code": login.result["code"],
                                       "redirect_uri": realm.redirect, "code_verifier": verifier or login.verifier},
                     basic=(PORTAL, realm.portal_secret))


def check_id_token(realm: Realm, login: Login, tr: Resp, tag: str) -> dict | None:
    body = tr.json() or {}
    if not check(tr.status == 200 and "id_token" in body, f"{realm.name} {tag}: đổi code lấy token",
                 f"HTTP {tr.status} {body.get('error')}"):
        return None
    check("refresh_token" not in body, f"{realm.name} {tag}: không có refresh token (use.refresh.tokens=false)")
    try:
        header, c = verify_rs256(body["id_token"], realm.jwks)
    except (ValueError, KeyError, StopIteration) as e:
        check(False, f"{realm.name} {tag}: chữ ký ID token theo JWKS của realm", str(e))
        return None
    check(True, f"{realm.name} {tag}: chữ ký RS256 của ID token hợp lệ (kid {header.get('kid')})")
    now = time.time()
    aud = c.get("aud") if isinstance(c.get("aud"), list) else [c.get("aud")]
    check(c.get("iss") == realm.issuer, f"{realm.name} {tag}: iss = {realm.issuer}", str(c.get("iss")))
    check(PORTAL in aud and c.get("azp") == PORTAL, f"{realm.name} {tag}: aud/azp = {PORTAL}", f"{aud} {c.get('azp')}")
    check(c.get("nonce") == login.nonce, f"{realm.name} {tag}: nonce khớp")
    check(isinstance(c.get("exp"), int) and c["exp"] > now and isinstance(c.get("sub"), str),
          f"{realm.name} {tag}: exp còn hạn, có sub")
    at = c.get("auth_time")
    check(isinstance(at, int) and now - 600 < at <= now + 5, f"{realm.name} {tag}: có auth_time hợp lệ", str(at))
    c["_kid"] = header.get("kid")
    return c


def check_auth_response(realm: Realm, login: Login, tag: str) -> bool:
    res = login.result or {}
    ok = check("code" in res and res.get("state") == login.state, f"{realm.name} {tag}: redirect về đúng callback với code + state",
               f"{sorted(res)}")
    check(res.get("iss") == realm.issuer, f"{realm.name} {tag}: tham số iss = issuer (RFC 9207)", str(res.get("iss")))
    return ok


def expect_error_redirect(http: Http, realm: Realm, name: str, want: str, **params) -> None:
    lg = Login(http, realm, **params)
    r = http.get(lg.url, jar=lg.jar)
    loc = r.headers.get("Location", "")
    q = dict(urllib.parse.parse_qsl(loc.split("?", 1)[1] if "?" in loc else loc.split("#", 1)[-1]))
    check(r.status in (302, 303) and loc.startswith(realm.redirect) and q.get("error") == want
          and "code" not in q and "access_token" not in q and "id_token" not in q,
          f"{realm.name}: {name} bị từ chối ({want})", f"HTTP {r.status} error={q.get('error')} {q.get('error_description')}")


def expect_bad_redirect(http: Http, realm: Realm, name: str, redirect_uri: str) -> None:
    lg = Login(http, realm, redirect_uri=redirect_uri)
    r = http.get(lg.url, jar=lg.jar)
    check(r.status == 400 and not r.headers.get("Location"), f"{realm.name}: {name} bị từ chối (trang lỗi 400, không redirect)",
          f"HTTP {r.status} Location={r.headers.get('Location')}")


# ---------------------------------------------------------------- per-realm scenario
def admin_token(http: Http, conf: dict) -> str:
    r = http.form("/realms/master/protocol/openid-connect/token",
                  {"grant_type": "password", "client_id": "admin-cli", "username": conf["bootstrap-admin-username"],
                   "password": conf["bootstrap-admin-password"]})
    if r.status != 200:
        raise SystemExit(f"không lấy được token admin khởi tạo: HTTP {r.status}")
    return r.json()["access_token"]


def client_secret(http: Http, admin: str, realm: str, client_id: str) -> str:
    cl = http.api("GET", f"/admin/realms/{realm}/clients?clientId={client_id}", admin).json()
    r = http.api("GET", f"/admin/realms/{realm}/clients/{cl[0]['id']}/client-secret", admin).json() or {}
    if not r.get("value"):
        r = http.api("POST", f"/admin/realms/{realm}/clients/{cl[0]['id']}/client-secret", admin).json()
    return r["value"]


def driver_token(http: Http, realm: Realm) -> str:
    r = http.form(realm.token_url, {"grant_type": "client_credentials"}, basic=(DRIVER, realm.driver_secret))
    if r.status != 200:
        raise AssertionError(f"client credentials của {DRIVER}: HTTP {r.status} {r.text[:200]}")
    return r.json()["access_token"]


def new_password() -> str:
    return secrets.token_urlsafe(24)   # 32 ký tự: đạt length(12), maxLength(128), notUsername, notEmail


def create_user(http: Http, realm: Realm, tag: str) -> tuple[str, str, str]:
    username = f"mgtest-{tag}-{secrets.token_hex(4)}"
    password = new_password()
    tok = driver_token(http, realm)
    r = http.api("POST", f"/admin/realms/{realm.name}/users", tok, {
        "username": username, "email": f"{username}@example.invalid", "emailVerified": True, "enabled": True,
        "firstName": "P2T05", "lastName": "Test", "credentials": [{"type": "password", "value": password, "temporary": False}]})
    if r.status != 201:
        raise AssertionError(f"{DRIVER} tạo user: HTTP {r.status} {r.text[:200]}")
    return r.headers["Location"].rsplit("/", 1)[1], username, password


def scenario(http: Http, realm: Realm, admin: str, other: str, created: list) -> None:
    n = realm.name
    # discovery + JWKS
    d = http.get(f"/realms/{n}/.well-known/openid-configuration").json()
    check(d.get("issuer") == realm.issuer, f"{n}: discovery issuer = {realm.issuer}", str(d.get("issuer")))
    check(d.get("authorization_response_iss_parameter_supported") is True and "S256" in d.get("code_challenge_methods_supported", []),
          f"{n}: discovery có iss trong authorization response (RFC 9207) và PKCE S256")
    off = {"urn:ietf:params:oauth:grant-type:device_code", "urn:openid:params:grant-type:ciba",
           "urn:ietf:params:oauth:grant-type:token-exchange"}
    check("device_authorization_endpoint" not in d and not off & set(d.get("grant_types_supported", [])),
          f"{n}: discovery không có device endpoint, không quảng bá grant device/CIBA/token-exchange")
    realm.auth_url, realm.token_url = d["authorization_endpoint"], d["token_endpoint"]
    for g in sorted(off):   # feature tắt ở mức server ⇒ token endpoint không nhận các grant này
        r = http.form(realm.token_url, {"grant_type": g, "client_id": PORTAL, "device_code": "x", "auth_req_id": "x",
                                        "subject_token": "x"})
        check(r.status == 400 and (r.json() or {}).get("error") == "unsupported_grant_type",
              f"{n}: grant {g.rsplit(':', 1)[1]} bị từ chối (unsupported_grant_type)", f"HTTP {r.status}")
    # Keycloak 26.8.2 vẫn ghi backchannel_authentication_endpoint trong discovery dù CIBA tắt — endpoint thật là 404
    if d.get("backchannel_authentication_endpoint"):
        r = http.form(d["backchannel_authentication_endpoint"], {"client_id": PORTAL})
        check(r.status == 404, f"{n}: endpoint CIBA (vẫn có tên trong discovery) trả 404", f"HTTP {r.status}")
    check(realm.auth_url.startswith(realm.issuer + "/") and realm.token_url.startswith(realm.issuer + "/"),
          f"{n}: endpoint nằm dưới issuer (hostname cố định https://auth.<domain>)")
    realm.jwks = http.get(d["jwks_uri"]).json()
    realm.portal_secret = client_secret(http, admin, n, PORTAL)      # test-only: Portal sẽ lấy từ SecretStore
    realm.driver_secret = client_secret(http, admin, n, DRIVER)

    # service account của driver: đúng 3 role realm-management, không role realm; token cho Admin API của CHÍNH realm này
    drv = http.api("GET", f"/admin/realms/{n}/clients?clientId={DRIVER}", admin).json()[0]
    sa = http.api("GET", f"/admin/realms/{n}/clients/{drv['id']}/service-account-user", admin).json()
    rm = http.api("GET", f"/admin/realms/{n}/users/{sa['id']}/role-mappings", admin).json() or {}
    roles = {r["name"] for r in rm.get("clientMappings", {}).get("realm-management", {}).get("mappings", [])}
    check(roles == DRIVER_ROLES and not rm.get("realmMappings") and set(rm.get("clientMappings", {})) == {"realm-management"},
          f"{n}: service account {DRIVER} có đúng {sorted(DRIVER_ROLES)}, không role nào khác", json.dumps(rm)[:300])
    realm.summary["driver_roles"] = sorted(roles)
    tok = driver_token(http, realm)
    tc = unverified_claims(tok)
    check(f"{realm.issuer.rsplit('/realms/', 1)[0]}/admin/realms/{n}" in (tc.get("aud") if isinstance(tc.get("aud"), list) else [tc.get("aud")]),
          f"{n}: token của {DRIVER} mang audience Admin API của realm (kc-admin-api)", str(tc.get("aud")))
    uid, user, pw = create_user(http, realm, "a")
    created.append((realm, uid))
    u = http.api("GET", f"/admin/realms/{n}/users/{uid}", tok).json()
    check(u.get("requiredActions") == ["CONFIGURE_TOTP"], f"{n}: user mới mang sẵn required action CONFIGURE_TOTP",
          str(u.get("requiredActions")))
    for path, method, name in ((f"/admin/realms/{other}/users", "GET", f"đọc user realm {other}"),
                               (f"/admin/realms/{n}/clients", "GET", "đọc clients"),
                               ("/admin/realms", "POST", "tạo realm"),
                               (f"/admin/realms/{n}/users/{uid}/impersonation", "POST", "impersonation")):
        r = http.api(method, path, tok, {"realm": "p2t05-should-not-exist", "enabled": False} if method == "POST" and path == "/admin/realms" else None)
        check(r.status in (401, 403, 404, 501), f"{n}: {DRIVER} bị từ chối {name}", f"HTTP {r.status}")
    r = http.api("POST", f"/admin/realms/{n}/users/{uid}/impersonation", admin)
    check(r.status in (403, 404, 501), f"{n}: impersonation bị từ chối cả với admin master", f"HTTP {r.status} {r.text[:120]}")
    realm.summary["impersonation_admin_status"] = r.status

    # đăng nhập 1: lần đầu ⇒ bắt buộc cấu hình TOTP
    totp = Totp(b"")
    l1 = Login(http, realm).run(user, pw, totp)
    check(l1.steps == ["password", "configure_totp"], f"{n} login1: mật khẩu rồi BẮT BUỘC cấu hình TOTP", str(l1.steps))
    c1 = check_id_token(realm, l1, exchange(http, realm, l1), "login1") if check_auth_response(realm, l1, "login1") else None
    r = exchange(http, realm, l1)
    check(r.status == 400 and (r.json() or {}).get("error") == "invalid_grant", f"{n}: code chỉ dùng được một lần",
          f"HTTP {r.status}")

    # đăng nhập 2: trình duyệt mới ⇒ mật khẩu + OTP (OTP sai bị từ chối trước)
    l2 = Login(http, realm).run(user, pw, totp, wrong_otp_first=True)
    check(l2.steps == ["password", "otp_wrong", "otp"], f"{n} login2: mật khẩu → OTP sai bị từ chối → OTP đúng", str(l2.steps))
    bad = Login(http, realm)
    c2 = None
    if check_auth_response(realm, l2, "login2"):
        r = http.form(realm.token_url, {"grant_type": "authorization_code", "code": l2.result["code"],
                                        "redirect_uri": realm.redirect, "code_verifier": bad.verifier}, basic=(PORTAL, realm.portal_secret))
        check(r.status == 400 and (r.json() or {}).get("error") == "invalid_grant", f"{n}: code_verifier sai bị từ chối (PKCE)",
              f"HTTP {r.status}")
        l2b = Login(http, realm, jar=l2.jar)   # code đầu đã hỏng do verifier sai: lấy code mới qua SSO
        l2b.run(user, pw, totp)
        check(l2b.steps == [], f"{n} SSO: cùng trình duyệt, không prompt ⇒ trả code ngay, không hỏi lại", str(l2b.steps))
        if check_auth_response(realm, l2b, "sso"):
            c2 = check_id_token(realm, l2b, exchange(http, realm, l2b), "sso")
    # step-up (§8.3 bước 7): prompt=login ⇒ phải nhập lại mật khẩu + OTP, auth_time mới
    if c2:
        time.sleep(1.1)
        l3 = Login(http, realm, jar=l2.jar, prompt="login").run(user, pw, totp)
        check(l3.steps == ["password", "otp"], f"{n} step-up: prompt=login ⇒ nhập lại mật khẩu + OTP", str(l3.steps))
        if check_auth_response(realm, l3, "step-up"):
            c3 = check_id_token(realm, l3, exchange(http, realm, l3), "step-up")
            if c3:
                check(c2["auth_time"] < c3["auth_time"], f"{n}: auth_time tăng sau step-up ({c2['auth_time']} → {c3['auth_time']})")
                realm.summary.update({"auth_time_login2_sso": c2["auth_time"], "auth_time_step_up": c3["auth_time"]})
    if c1:
        realm.summary.update({"kid": c1["_kid"], "auth_time_login1": c1["auth_time"], "acr": c1.get("acr"),
                              "amr": c1.get("amr"), "id_token_claims": sorted(k for k in c1 if not k.startswith("_"))})
        jw = next(k for k in realm.jwks["keys"] if k.get("kid") == c1["_kid"])
        realm.summary["signing_key_sha256"] = hashlib.sha256(b64d(jw["n"])).hexdigest()[:16]
    realm.summary["steps"] = {"login1": l1.steps, "login2": l2.steps}

    # bị từ chối: grant không dùng, PKCE, redirect URI
    for cid, auth, name in ((PORTAL, (PORTAL, realm.portal_secret), PORTAL), ("admin-cli", None, "admin-cli"),
                            (DRIVER, (DRIVER, realm.driver_secret), DRIVER)):
        data = {"grant_type": "password", "username": user, "password": pw, "scope": "openid"}
        if auth is None:
            data["client_id"] = cid
        r = http.form(realm.token_url, data, basic=auth)
        err = (r.json() or {}).get("error") if r.body.strip().startswith(b"{") else None
        check(r.status in (400, 401) and err in ("unauthorized_client", "invalid_client") and "access_token" not in r.text,
              f"{n}: password grant (direct access) bị từ chối với {name}", f"HTTP {r.status} {err}")
        realm.summary.setdefault("password_grant", {})[name] = f"{r.status} {err}"
    r = http.form(realm.token_url, {"grant_type": "client_credentials"}, basic=(PORTAL, realm.portal_secret))
    check(r.status in (400, 401) and (r.json() or {}).get("error") == "unauthorized_client",
          f"{n}: client_credentials bị từ chối với {PORTAL}", f"HTTP {r.status}")
    expect_error_redirect(http, realm, "implicit (response_type=id_token token)", "unauthorized_client",
                          response_type="id_token token", code_challenge=None, code_challenge_method=None)
    expect_error_redirect(http, realm, "thiếu PKCE", "invalid_request", code_challenge=None, code_challenge_method=None)
    expect_error_redirect(http, realm, "PKCE plain", "invalid_request", code_challenge="x" * 43, code_challenge_method="plain")
    other_redirect = realm.redirect.rsplit("/", 1)[0] + "/00000000-0000-7000-8000-00000000dead"
    expect_bad_redirect(http, realm, "redirect URI với idpId khác", other_redirect)
    expect_bad_redirect(http, realm, "redirect URI có đuôi thêm", realm.redirect + "/x")
    expect_bad_redirect(http, realm, "redirect URI khác origin", realm.redirect.replace("https://", "https://evil.", 1))

    # brute force: 4 lần sai chưa khóa, lần 5 khóa tạm; khi khóa, mật khẩu đúng cũng không vào
    buid, buser, bpw = create_user(http, realm, "bf")
    created.append((realm, buid))
    lg = Login(http, realm)
    r = http.get(lg.url, jar=lg.jar)
    status = None
    for i in range(1, 6):
        f = Page(r.text).form_with("username", "password")
        if f is None:
            check(False, f"{n}: brute force — form đăng nhập", Page(r.text).describe())
            break
        time.sleep(1.2)   # > quickLoginCheckMilliSeconds: đếm theo failureFactor, không theo luật "đăng nhập dồn dập"
        r = http.form(f["action"], {**f["inputs"], "username": buser, "password": "wrong-" + secrets.token_hex(8)}, jar=lg.jar)
        status = http.api("GET", f"/admin/realms/{n}/attack-detection/brute-force/users/{buid}", driver_token(http, realm)).json()
        if i == 4:
            check(status.get("disabled") is False, f"{n}: brute force — 4 lần sai chưa khóa", str(status))
    check(bool(status) and status.get("disabled") is True and status.get("numFailures") == 5,
          f"{n}: brute force — lần sai thứ 5 khóa tạm user", str(status))
    f = Page(r.text).form_with("username", "password")
    if f is not None:
        r = http.form(f["action"], {**f["inputs"], "username": buser, "password": bpw}, jar=lg.jar)
        locked_ok = r.status == 200 and Page(r.text).form_with("username", "password") is not None
        check(locked_ok, f"{n}: brute force — khi bị khóa, mật khẩu đúng cũng bị từ chối", f"HTTP {r.status}")
    realm.summary["brute_force_status"] = {k: status.get(k) for k in ("disabled", "numFailures", "lastIPFailure")} if status else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--realms-dir", required=True)
    ap.add_argument("--admin-conf", required=True)
    ap.add_argument("--connect")
    ap.add_argument("--cafile")
    ap.add_argument("--report")
    ap.add_argument("--event-ip-present", action="append", default=[])
    ap.add_argument("--event-ip-absent", action="append", default=[])
    a = ap.parse_args()
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    check(hotp(b"12345678901234567890", 59 // 30, 8) == "94287082", "TOTP tự cài khớp vector RFC 6238 (T=59, SHA-1)")
    connect = None
    if a.connect:
        h, p = a.connect.rsplit(":", 1)
        connect = (h, int(p))
    http = Http(a.base_url, connect, a.cafile)
    conf = {}
    for line in pathlib.Path(a.admin_conf).read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            conf[k.strip()] = v.strip()
    realms = []
    for f in sorted(pathlib.Path(a.realms_dir).glob("*.json")):
        rep = json.loads(f.read_text(encoding="utf-8"))
        realms.append(Realm(rep["realm"], rep, http.base))
    check([r.name for r in realms] == ["platform", "tenant-a", "tenant-b"], "ba realm: platform, tenant-a, tenant-b",
          str([r.name for r in realms]))

    for path in ("/metrics", "/health", "/health/ready"):
        r = http.get(path)
        check(r.status == 404, f"hostname công khai không phục vụ {path} (chỉ cổng quản trị nội bộ)", f"HTTP {r.status}")
    r = http.get("/admin/serverinfo")
    check(r.status == 401, "Admin API không có token ⇒ 401", f"HTTP {r.status}")
    admin = admin_token(http, conf)
    info = http.api("GET", "/admin/serverinfo", admin).json()
    feats = {f["name"]: f["enabled"] for f in info.get("features", [])}
    check(feats.get("IMPERSONATION") is False, "feature IMPERSONATION tắt ở mức server", str(feats.get("IMPERSONATION")))
    disabled = sorted(k for k in ("IMPERSONATION", "KERBEROS", "CIBA", "DEVICE_FLOW", "TOKEN_EXCHANGE_STANDARD_V2") if feats.get(k) is False)
    check(len(disabled) == 5, "feature tắt: impersonation, kerberos, ciba, device-flow, token-exchange-standard", str(disabled))
    version = info.get("systemInfo", {}).get("version")

    created: list = []
    extra: dict = {}
    try:
        for i, realm in enumerate(realms):
            print(f"--- realm {realm.name}", flush=True)
            try:
                scenario(http, realm, admin, realms[(i + 1) % len(realms)].name, created)
            except (AssertionError, KeyError, ValueError, OSError) as e:
                check(False, f"{realm.name}: kịch bản chạy hết", f"{type(e).__name__}: {e}")
            admin = admin_token(http, conf)    # token admin sống 60 s
        iss = [r.summary.get("issuer") for r in realms]
        keys = [r.summary.get("signing_key_sha256") for r in realms]
        check(len(set(iss)) == 3, "ba issuer khác nhau", str(iss))
        check(None not in keys and len(set(keys)) == 3, "ba khóa ký (RSA) khác nhau", str(keys))
        if a.event_ip_present or a.event_ip_absent:
            ev = http.api("GET", "/admin/realms/platform/events?type=CLIENT_LOGIN_ERROR&max=200", admin).json() or []
            ips = sorted({e.get("ipAddress") for e in ev})
            extra["platform_client_login_error_ips"] = ips
            for ip in a.event_ip_present:
                check(ip in ips, f"proxy tin cậy: event CLIENT_LOGIN_ERROR có IP {ip}", str(ips))
            for ip in a.event_ip_absent:
                check(ip not in ips, f"proxy KHÔNG tin cậy: X-Forwarded-For giả {ip} bị bỏ qua", str(ips))
    finally:
        for realm, uid in created:
            try:
                http.api("DELETE", f"/admin/realms/{realm.name}/users/{uid}", driver_token(http, realm))
            except (AssertionError, OSError):
                pass
    if a.report:
        pathlib.Path(a.report).write_text(json.dumps({"keycloak": version, "base_url": a.base_url,
                                                      "realms": [r.summary for r in realms], **extra,
                                                      "failures": failures}, indent=2, ensure_ascii=False),
                                          encoding="utf-8")
    print(f"\n{'ĐẠT' if not failures else 'KHÔNG ĐẠT'}: {len(failures)} lỗi" + (f" — {failures}" if failures else ""))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
