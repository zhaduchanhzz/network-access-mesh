"""The SPA behind the edge on the dev/CI stack (P4-T01a) — FUNCTIONAL only (§22.1).

The edge is the stack's render of edge template v9 (only its tls block differs — stack.ci_tls); the SPA is service `web`
of compose.app.yaml (tools/render_app.py) with the image built from the tree (infrastructure/docker/web).

  E2E-85  app./admin. serve the SPA through the edge: https://app.<domain>/ and a deep link /tenants/<id>/devices ⇒ the
          same index.html (200, text/html, no-cache), https://admin.<domain>/ and /platform/tenants likewise (from the
          allowed source); /api/v1/auth/session still answered by the api (401 problem+json) on both; exactly ONE value of
          each security header (CSP of portal_headers, HSTS, nosniff, X-Frame-Options, Referrer-Policy, COOP, CORP,
          Permissions-Policy) on SPA and api responses alike — the edge is their only source — and no Server header;
          the edge conformance suite `platform` (tests/security/edge/conformance.py: SPA for every path outside /api/*
          including /healthz, /metrics, /internal/*, 404 for dot segments, dotfiles, "\" and unknown /api/*, IdP
          refusals) from this host; the web container hardened (65532, read-only, cap_drop ALL, no-new-privileges,
          healthy, mg-edge only, no published port, no mount)
  E2E-86  web stopped ⇒ app./ and admin./ answer the edge's static 503 (Retry-After, no-store, the same security
          headers), the api keeps answering on /api/*; web started again ⇒ healthy and the SPA is back
Standard library only.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time

from backend import Browser
from stack import ENV_DIR, ROOT, Stack, StackError

CSP = "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'"
SECURITY = {"Content-Security-Policy": CSP, "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
            "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Resource-Policy": "same-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()"}


def header_issues(resp) -> list[str]:
    """Each security header exactly once with its value (one source: the edge), no Server header."""
    out = []
    for name, want in SECURITY.items():
        got = [v for k, v in resp.headers if k.lower() == name.lower()]
        if got != [want]:
            out.append(f"{name}={got}")
    if resp.header("Server"):
        out.append("Server present")
    return out


def is_index(resp) -> bool:
    return (resp.status == 200 and resp.header("Content-Type") == "text/html; charset=utf-8"
            and b'id="root"' in resp.body and b'<script type="module"' in resp.body)


def web_container(st: Stack) -> str:
    return st.name("web")


def check_spa(r, st: Stack) -> None:
    b = Browser(st)
    tenant_a = json.loads((ENV_DIR / "tenants" / "tenant-a.json").read_text(encoding="utf-8"))["tenant_id"]
    app, admin = f"https://app.{st.domain}", f"https://admin.{st.domain}"
    root = b.get(f"{app}/")
    pages = {"app /": root, f"app /tenants/{tenant_a}/devices": b.get(f"{app}/tenants/{tenant_a}/devices"),
             "admin /": b.get(f"{admin}/"), "admin /platform/tenants": b.get(f"{admin}/platform/tenants")}
    spa_ok = all(is_index(p) and p.body == root.body and p.header("Cache-Control") == "no-cache" for p in pages.values())
    api = {"app": b.get(f"{app}/api/v1/auth/session"), "admin": b.get(f"{admin}/api/v1/auth/session")}
    api_ok = all(p.status == 401 and p.header("Content-Type").startswith("application/problem+json")
                 and p.json().get("code") == "unauthenticated" for p in api.values())
    issues = {k: header_issues(p) for k, p in {**pages, **{f"{k} /api/v1/auth/session": v for k, v in api.items()}}.items()}
    hdr_ok = not any(issues.values())
    # the edge conformance suite, group `platform`, from this host (the only admin. source of the stack)
    try:
        conf = subprocess.run([sys.executable, "-I", str(ROOT / "tests" / "security" / "edge" / "conformance.py"),
                               "platform", "--edge", st.edge_ip, "--domain", st.domain, "--admin", "allowed",
                               "--cafile", str(st.work / "ca" / "ca.crt")],
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
    except subprocess.TimeoutExpired as e:
        raise StackError("conformance.py platform: timeout") from e
    conf_lines = conf.stdout.strip().splitlines()
    conf_ok = conf.returncode == 0 and bool(conf_lines) and conf_lines[-1].startswith("PASS platform sites")
    conf_fail = [ln for ln in conf_lines if ln.startswith("FAIL")][:6]
    # the container: hardened, healthy, on the edge network only
    fmt = ("{{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}} "
           "{{.State.Health.Status}} {{len .HostConfig.PortBindings}} {{len .Mounts}} "
           "{{range $k, $v := .NetworkSettings.Networks}}{{$k}},{{end}}")
    ins = st.docker("inspect", "-f", fmt, web_container(st)).stdout.strip()
    box_ok = ins == f"65532:65532 true [ALL] [no-new-privileges:true] healthy 0 0 {st.name('edge')},"
    ok = spa_ok and api_ok and hdr_ok and conf_ok and box_ok
    r.add("E2E-85", "P4-T01a: app./admin. phục vụ SPA qua edge v9 (/, deep link /tenants/<id>/devices, /platform/tenants "
          "⇒ cùng index.html 200 no-cache); /api/v1/auth/session vẫn là api (401 problem+json); mỗi header bảo mật đúng "
          "MỘT giá trị (edge là nguồn duy nhất), không Server; conformance `platform` (SPA cho mọi path ngoài /api/*, "
          "404 cho dot segment/dotfile/\\ và /api/<lạ>) từ host; container web 65532, chỉ-đọc, cap_drop ALL, "
          "no-new-privileges, healthy, chỉ network edge, không cổng, không mount", ok,
          f"SPA {spa_ok} ({', '.join(f'{k} {p.status}' for k, p in pages.items())}); api {api_ok} "
          f"({', '.join(f'{k} {p.status}' for k, p in api.items())}); header {hdr_ok} "
          f"{ {k: v for k, v in issues.items() if v} }; conformance rc={conf.returncode} "
          f"{conf_lines[-1] if conf_lines else conf.stderr[-200:]} {conf_fail}; container {ins!r}", limit=1200)


def wait_health(st: Stack, want: str, timeout: float = 90) -> str:
    end, state = time.time() + timeout, ""
    while time.time() < end:
        state = st.docker("inspect", "-f", "{{.State.Health.Status}}", web_container(st), check=False).stdout.strip()
        if state == want:
            return state
        time.sleep(1)
    return state


def check_web_down(r, st: Stack) -> None:
    b = Browser(st)
    app, admin = f"https://app.{st.domain}", f"https://admin.{st.domain}"
    st.docker("stop", "-t", "5", web_container(st))
    try:
        down = {"app /": b.get(f"{app}/"), "app /tenants/x": b.get(f"{app}/tenants/x"), "admin /": b.get(f"{admin}/")}
        api = b.get(f"{app}/api/v1/auth/session")
    finally:
        st.docker("start", web_container(st))
    health = wait_health(st, "healthy")
    back = b.get(f"{app}/")
    down_ok = all(p.status == 503 and p.body == b"Service temporarily unavailable" and p.header("Retry-After") == "30"
                  and p.header("Cache-Control") == "no-store" and not header_issues(p) for p in down.values())
    ok = down_ok and api.status == 401 and health == "healthy" and is_index(back)
    r.add("E2E-86", "P4-T01a: web dừng ⇒ app./admin. trả 503 tĩnh của edge (Retry-After 30, no-store, cùng bộ header bảo "
          "mật, không lộ 502 mặc định); api vẫn trả lời /api/*; web chạy lại ⇒ healthy, SPA trở lại", ok,
          f"khi dừng: {', '.join(f'{k} {p.status} {p.body[:40]!r} {header_issues(p)}' for k, p in down.items())}; "
          f"api {api.status}; sau khi chạy lại: {health}, / {back.status}", limit=900)


def run_all(r, st: Stack, guarded) -> None:
    guarded(r, "E2E-85", check_spa, st)
    guarded(r, "E2E-86", check_web_down, st)
