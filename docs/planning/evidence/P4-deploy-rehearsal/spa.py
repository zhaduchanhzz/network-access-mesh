#!/usr/bin/env python3
"""dep4 — kiểm site nền tảng sau edge v9/v10 từ LAN và qua "VPS": SPA, /api, console Keycloak, chuyển hướng web-auth."""
import http.client
import os
import socket
import ssl

ctx = ssl.create_default_context(cafile=os.path.expanduser("~/dep4/ca.crt"))
AID = "hskey-authreq-" + "A" * 24
CASES = [("app.dep4.test", "/"), ("app.dep4.test", "/tenants/x/devices"), ("app.dep4.test", "/api/v1/auth/session"),
         ("app.dep4.test", "/healthz"), ("app.dep4.test", "/.env"), ("admin.dep4.test", "/"),
         ("admin.dep4.test", "/admin/master/console/"), ("app.dep4.test", f"/enroll/claim?tenant=tenant-a&auth_id={AID}"),
         ("tenant-a.mesh.dep4.test", f"/register/{AID}"), ("tenant-a.mesh.dep4.test", f"/register/{AID}?via=portal")]


def get(ip, host, path):
    raw = socket.create_connection((ip, 443), timeout=5)
    c = http.client.HTTPConnection(ip, 443, timeout=5)
    c.sock = ctx.wrap_socket(raw, server_hostname=host)
    c.request("GET", path, headers={"Host": host})
    r = c.getresponse()
    return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()


for ip, via in (("10.77.4.10", "LAN"), ("192.88.99.10", "VPS")):
    for host, path in CASES:
        try:
            s, h, b = get(ip, host, path)
            print(f"{via} {host}{path[:56]:57} {s} {h.get('content-type', '')[:24]:24} csp={int('content-security-policy' in h)} "
                  f"spa={int(b'id=\"root\"' in b)} loc={h.get('location', '')[:80]}")
        except Exception as e:  # noqa: BLE001
            print(f"{via} {host}{path[:56]:57} ERR {type(e).__name__}")
