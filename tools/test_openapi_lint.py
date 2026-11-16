#!/usr/bin/env python3
"""Tests of tools/openapi_lint.py (P2-T02): the YAML subset parser, the readers of the master plan (§8.5, §8.6, §13.2,
§20), the real api/openapi.yaml (must pass) and fixture specs that must fail — at least one per rule.

    python tools/test_openapi_lint.py        # exit code 0 = pass. Standard library only.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import openapi_lint as ol  # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
failures = 0


def check(ok: bool, name: str, detail: str = "") -> None:
    global failures
    print(f"{'PASS' if ok else 'FAIL'} {name}{'' if ok else ': ' + detail}")
    failures += 0 if ok else 1


def cli(*args: str) -> int:
    """Exit code of openapi_lint.main(args); its own output is swallowed."""
    with contextlib.redirect_stdout(io.StringIO()):
        return ol.main(list(args))


# ====================================================================== YAML subset parser

YAML_OK = [
    ("scalars", "a: 1\nb: -2\nc: 3.5\nd: true\ne: ~\nf: 3.1.0\ng: v0.29.7\nh: 'it''s'\ni: \"tab\\tq\\\"\"\nj: x:y\n",
     {"a": 1, "b": -2, "c": 3.5, "d": True, "e": None, "f": "3.1.0", "g": "v0.29.7", "h": "it's", "i": 'tab\tq"',
      "j": "x:y"}),
    ("comments", "# c\na: x # trailing\nb: 'x # kept'\nc: x#y\n", {"a": "x", "b": "x # kept", "c": "x#y"}),
    ("flow collections", "a: [x, 'y', \"z\", [1, 2]]\nb: {type: string, format: uuid}\nc: []\nd: {}\n"
                         "e: [string, 'null']\nf: {$ref: '#/c/s/X'}\n",
     {"a": ["x", "y", "z", [1, 2]], "b": {"type": "string", "format": "uuid"}, "c": [], "d": {},
      "e": ["string", "null"], "f": {"$ref": "#/c/s/X"}}),
    ("sequence at the key's indentation", "k:\n- a\n- b\nn: 1\n", {"k": ["a", "b"], "n": 1}),
    ("compact mappings in a sequence", "p:\n  - name: id\n    in: path\n  - $ref: '#/x'\n",
     {"p": [{"name": "id", "in": "path"}, {"$ref": "#/x"}]}),
    ("literal block", "d: |-\n  line 1\n\n  # not a comment\n    indented\nn: 2\n",
     {"d": "line 1\n\n# not a comment\n  indented", "n": 2}),
    ("literal block, clip", "d: |\n  a\n  b\n\n", {"d": "a\nb\n"}),
    ("folded block", "d: >-\n  a\n  b\n\n  c\n", {"d": "a b\nc"}),
    ("quoted keys", "'200':\n  x: 1\n\"a b\": 2\n", {"200": {"x": 1}, "a b": 2}),
    ("nested mappings", "a:\n  b:\n    c: [1]\n  d: x\n", {"a": {"b": {"c": [1]}, "d": "x"}}),
    ("path keys with braces and colons", "/t/{id}:\n  x: 1\n/t/{id}:expire:\n  y: 2\n",
     {"/t/{id}": {"x": 1}, "/t/{id}:expire": {"y": 2}}),
]
YAML_BAD = [
    ("anchor", "a: &x 1\n"),
    ("alias", "a: *x\n"),
    ("tag", "a: !!str 1\n"),
    ("': ' inside a plain scalar", "a: b: c\n"),
    ("duplicate key", "a: 1\na: 2\n"),
    ("duplicate key in flow mapping", "a: {b: 1, b: 2}\n"),
    ("tab indentation", "a:\n\tb: 1\n"),
    ("unterminated quoted scalar", "a: 'x\n"),
    ("plain scalar starting with a backtick", "a: `x`\n"),
    ("multi-line plain scalar", "a: b\n  c\n"),
    ("complex key", "? a\n: b\n"),
    ("document marker", "---\na: 1\n"),
    ("bad indentation", "a:\n    b: 1\n  c: 2\n"),
    ("unclosed flow sequence", "a: [1, 2\n"),
    ("text after a flow collection", "a: [1] x\n"),
]
for name, text, want in YAML_OK:
    try:
        got = ol.load_yaml(text)
        check(got == want, f"yaml: {name}", f"got {got!r}")
    except ol.YamlError as e:
        check(False, f"yaml: {name}", str(e))
for name, text in YAML_BAD:
    try:
        ol.load_yaml(text)
        check(False, f"yaml rejects: {name}", "no error")
    except ol.YamlError:
        check(True, f"yaml rejects: {name}")

# ====================================================================== readers of the master plan

master = ol.Master(ol.MASTER.read_text(encoding="utf-8"))
check({"P2-T02", "P2-T13a", "P1-T12a", "P7-T05"} <= master.tasks, "§20: task IDs (with letter suffixes)")
check(len(master.perms) >= 80, "§8.5/§8.6: permissions parsed", str(len(master.perms)))
P = master.perms
check(P["tenant.device:read"].own and P["tenant.notification:read"].own and not P["tenant.device:sync"].own,
      "§8.6: ○ cells mark own-resource permissions")
check(P["platform.tenant:delete"].dual_all and P["platform.instance:release"].dual_all
      and not P["platform.instance:quarantine"].dual_any, "§8.5: 2P cells, split per ':key' alternative")
check(P["platform.idp:manage"].dual_any and not P["platform.idp:manage"].dual_all, "§8.5: conditional 2P is not all-2P")
for scope, method, segs, want in [
    ("tenant", "GET", (), {"tenant.tenant:read"}),
    ("tenant", "GET", ("devices", "{}"), {"tenant.device:read"}),
    ("tenant", "POST", ("devices", "sync"), {"tenant.device:sync"}),
    ("tenant", "POST", ("policies", "{}", "validate"), {"tenant.policy:edit"}),
    ("tenant", "GET", ("policies", "{}", "diff"), {"tenant.policy:read"}),
    ("tenant", "DELETE", ("dns", "records", "{}"), {"tenant.dns:update"}),
    ("tenant", "POST", ("invitations",), {"tenant.invitation:manage"}),
    ("platform", "POST", ("platform", "tenants", "{}", "resume"), {"platform.tenant:suspend"}),
    ("platform", "POST", ("platform", "instances", "{}", "release"), {"platform.instance:release"}),
    ("platform", "PATCH", ("platform", "hosts", "{}"), {"platform.host:manage"}),
    ("platform", "GET", ("platform", "approvals", "{}"), {"platform.approval:read"}),
]:
    got = master.permissions_for(scope, method, segs)
    check(got == want, f"§8.5/§8.6 API action: {method} /{'/'.join(segs)}", f"got {got}")
for method, path, want in [
    ("GET", "/tenants", {"P2-T11"}),
    ("GET", "/tenants/{tenantId}/devices", {"P2-T13"}),
    ("PUT", "/tenants/{tenantId}/devices/{deviceId}/tags", {"P4-T10"}),
    ("GET", "/tenants/{tenantId}/users/{membershipId}", {"P2-T11"}),
    ("PUT", "/tenants/{tenantId}/users/{membershipId}/role", {"P4-T09"}),
    ("GET", "/platform/tenants/{tenantId}", {"P2-T11"}),
    ("PATCH", "/platform/tenants/{tenantId}", {"P4-T03a"}),
    ("POST", "/platform/instances/{instanceId}/restart", {"P3-T11", "P3-T13", "P3-T13a"}),
    ("POST", "/platform/jobs/{jobId}/cancel", {"P3-T05"}),
    ("GET", "/platform/relay-regions", {"P3-T05c"}),
    ("POST", "/platform/relay-regions", {"P7-T04"}),
    ("GET", "/tenants/{tenantId}/identity-provider", {"P4-T03a"}),
    ("GET", "/internal/edge/ask", {"P7-T05"}),
]:
    got = master.trace_candidates(method, path)
    check(got == want, f"§13.2 traceability: {method} {path}", f"got {got}")

# ====================================================================== the real spec

spec = ol.load_yaml(ol.SPEC.read_text(encoding="utf-8"))
errs = ol.lint(spec, master)
check(not errs, "api/openapi.yaml passes the lint", "\n  ".join(errs))
phase2 = {"authLogin", "authCallback", "authLogout", "getAuthSession", "listAuthSessions", "revokeAuthSession",
          "listMyTenants", "getTenant", "getTenantDashboard", "listDevices", "syncDevices", "getDevice", "renameDevice",
          "deleteDevice", "expireDevice", "listTenantUsers", "getTenantUser", "listTenantAuditEvents", "listTenantJobs",
          "getTenantJob", "listPlatformTenants", "getPlatformTenant", "listPlatformInstances", "getPlatformInstance",
          "getPlatformHealth", "listPlatformAuditEvents", "listPlatformJobs", "getPlatformJob"}
ids = {op.get("operationId") for _, _, op, _ in ol.operations(spec)}
check(phase2 <= ids, "api/openapi.yaml has every Phase 2 operation", str(sorted(phase2 - ids)))

# ====================================================================== fixtures that must fail (mutations of the real spec)


def op(s: dict, method: str, path: str) -> dict:
    return s["paths"][path][method]


DEVICES, DEVICE = "/tenants/{tenantId}/devices", "/tenants/{tenantId}/devices/{deviceId}"
EXPIRE, SYNC = DEVICE + "/expire", DEVICES + "/sync"
PROBLEM_REF = {"$ref": "#/components/schemas/Problem"}


def set_(path: list, value):
    def mutate(s: dict) -> None:
        node = s
        for k in path[:-1]:
            node = node[k]
        node[path[-1]] = value
    return mutate


def pop(path: list):
    def mutate(s: dict) -> None:
        node = s
        for k in path[:-1]:
            node = node[k]
        del node[path[-1]]
    return mutate


def move_path(old: str, new: str):
    def mutate(s: dict) -> None:
        s["paths"][new] = s["paths"].pop(old)
    return mutate


def add_param(path: str, method: str, param: dict):
    def mutate(s: dict) -> None:
        op(s, method, path).setdefault("parameters", []).append(param)
    return mutate


def add_tenant_delete(s: dict) -> None:
    """A 2P operation (platform.tenant:delete) without x-dual-control."""
    new = copy.deepcopy(op(s, "get", "/platform/tenants/{tenantId}"))
    new.update({"operationId": "deletePlatformTenant", "x-permission": "platform.tenant:delete", "x-task": "P3-T05",
                "x-audit-action": "platform.tenant.delete", "security": [{"sessionCookie": [], "csrfToken": []}]})
    new["responses"]["202"] = {"description": "accepted", "headers": {"Location": {"$ref": "#/components/headers/JobLocation"}}}
    del new["responses"]["200"]
    s["paths"]["/platform/tenants/{tenantId}"]["delete"] = new


def secondary_twice(s: dict) -> None:
    op(s, "get", DEVICES)["x-permission-secondary"] = "tenant.device:sync"
    op(s, "get", DEVICE)["x-permission-secondary"] = "tenant.device:sync"


FIXTURES = [
    # x-permission (§13.1, §8.4 invariant 4, §8.5, §8.6)
    ("missing x-permission", pop(["paths", DEVICES, "get", "x-permission"]), "missing x-permission"),
    ("two permissions", set_(["paths", DEVICES, "get", "x-permission"], ["tenant.device:read", "tenant.device:sync"]),
     "exactly one permission"),
    ("permission not in the matrices", set_(["paths", DEVICES, "get", "x-permission"], "tenant.device:teleport"),
     "is not a permission of the §8.5/§8.6 matrices"),
    ("permission of another row", set_(["paths", DEVICES, "get", "x-permission"], "tenant.audit:read"),
     "is not in the API action column of tenant.audit:read"),
    ("platform permission on a tenant path", set_(["paths", "/tenants/{tenantId}", "get", "x-permission"],
                                                  "platform.tenant:read"), "on a path outside /platform"),
    ("public on a tenant operation", set_(["paths", DEVICE, "get", "x-permission"], "public"),
     "x-permission public is not allowed on this operation"),
    ("authenticated on a platform operation", set_(["paths", "/platform/health", "get", "x-permission"],
                                                   "authenticated"), "x-permission authenticated is not allowed"),
    ("missing x-own-resource on a ○ row", pop(["paths", DEVICE, "get", "x-own-resource"]),
     "x-own-resource: true required"),
    ("x-own-resource on a row without ○", set_(["paths", SYNC, "post", "x-own-resource"], True), "has no ○ cell"),
    ("x-dual-control without 2P", set_(["paths", "/tenants/{tenantId}", "get", "x-dual-control"], True),
     "has no 2P cell"),
    ("2P operation without x-dual-control", add_tenant_delete, "x-dual-control: true required"),
    ("x-permission-secondary on two operations", secondary_twice, "allowed on at most one operation"),
    # x-task (§20, §13.2)
    ("missing x-task", pop(["paths", DEVICES, "get", "x-task"]), "missing x-task"),
    ("x-task not in §20", set_(["paths", DEVICES, "get", "x-task"], "P2-T99"), "is not a task ID of §20"),
    ("x-task against the §13.2 table", set_(["paths", DEVICES, "get", "x-task"], "P4-T06"),
     "does not match the §13.2 traceability table"),
    # x-audit-action
    ("missing x-audit-action", pop(["paths", DEVICES, "get", "x-audit-action"]), "x-audit-action missing"),
    ("malformed x-audit-action", set_(["paths", DEVICES, "get", "x-audit-action"], "DeviceList"), "x-audit-action"),
    # tenant only from the path (§13.1)
    ("tenant in the query", add_param(DEVICES, "get", {"name": "tenant_id", "in": "query",
                                                        "schema": {"type": "string", "format": "uuid"}}),
     "tenant taken from the query parameter 'tenant_id'"),
    ("tenant in a header", add_param("/platform/health", "get", {"name": "X-Tenant-Id", "in": "header",
                                                                 "schema": {"type": "string"}}),
     "tenant taken from the header parameter 'X-Tenant-Id'"),
    ("tenant in a cookie", add_param("/auth/session", "get", {"name": "mg_tenant", "in": "cookie",
                                                              "schema": {"type": "string"}}),
     "tenant taken from the cookie parameter 'mg_tenant'"),
    ("tenant in the request body", set_(["components", "schemas", "DeviceRename", "properties", "tenant_id"],
                                        {"type": "string", "format": "uuid"}), "carries tenant field(s) ['tenant_id']"),
    ("tenant segment not named tenantId", lambda s: (move_path(DEVICES, "/tenants/{id}/devices")(s), set_(
        ["paths", "/tenants/{id}/devices", "get", "parameters", 0], {"name": "id", "in": "path", "required": True,
                                                                     "schema": {"type": "string", "format": "uuid"}})(s)),
     "must be the path parameter {tenantId}"),
    ("path ID not a UUID", set_(["components", "parameters", "DeviceId", "schema"], {"type": "string"}),
     "path parameter 'deviceId' must be a UUID string"),
    # action paths (§13.1)
    ("action as {id}:action", move_path(EXPIRE, DEVICE + ":expire"), "mixes a {param} with text"),
    ("action with ':' on a collection", move_path(SYNC, DEVICES + ":sync"), "contains ':'"),
    ("param mixed with text", move_path(EXPIRE, DEVICES + "/dev-{deviceId}/expire"), "mixes a {param} with text"),
    ("segment not kebab-case", move_path(EXPIRE, DEVICE + "/Expire_Now"), "is not lowercase kebab-case"),
    ("undeclared path parameter", lambda s: op(s, "get", DEVICE).__setitem__(
        "parameters", [p for p in op(s, "get", DEVICE)["parameters"] if "DeviceId" not in p.get("$ref", "")]),
     "path parameter {deviceId} is not declared"),
    # problem+json (RFC 9457, §13.1, §13.3)
    ("error response as application/json", lambda s: s["components"]["responses"]["NotFound"].__setitem__(
        "content", {"application/json": {"schema": PROBLEM_REF}}), "must be application/problem+json only"),
    ("error response with another schema", set_(["paths", DEVICES, "get", "responses", "404"], {
        "description": "x", "content": {"application/problem+json": {"schema": {"type": "object"}}}}),
     "must use the schema #/components/schemas/Problem"),
    ("Problem without request_id", pop(["components", "schemas", "Problem", "properties", "request_id"]),
     "components.schemas.Problem"),
    ("missing 401", pop(["paths", DEVICE, "get", "responses", "401"]), "missing error response(s) ['401']"),
    ("missing 422 with query parameters", pop(["paths", DEVICES, "get", "responses", "422"]),
     "missing error response(s) ['422']"),
    ("success as problem+json", set_(["paths", DEVICE, "get", "responses", "200", "content"],
                                     {"application/problem+json": {"schema": PROBLEM_REF}}),
     "success response 200 must not be application/problem+json"),
    # security (§8.3)
    ("public operation inheriting the session", pop(["paths", "/auth/login", "get", "security"]),
     "must declare security: []"),
    ("unsafe method without CSRF", set_(["paths", DEVICE, "patch", "security"], [{"sessionCookie": []}]),
     "X-CSRF-Token"),
    ("operation without session", set_(["paths", DEVICE, "get", "security"], []), "must require the session cookie"),
    # 202 + Location, Idempotency-Key (§13.1)
    ("202 without Location", pop(["paths", SYNC, "post", "responses", "202", "headers"]),
     "must carry Location of the job"),
    ("POST 202 without Idempotency-Key", lambda s: op(s, "post", EXPIRE).__setitem__(
        "parameters", [p for p in op(s, "post", EXPIRE)["parameters"] if "Idempotency" not in p.get("$ref", "")]),
     "must require the Idempotency-Key header"),
    # pagination (§13.1)
    ("list without cursor", lambda s: op(s, "get", DEVICES).__setitem__(
        "parameters", [p for p in op(s, "get", DEVICES)["parameters"] if "Cursor" not in p.get("$ref", "")]),
     "both limit and cursor"),
    ("limit above 200", set_(["components", "parameters", "Limit", "schema", "maximum"], 500), "maximum <= 200"),
    # operationId and document
    ("duplicate operationId", set_(["paths", DEVICE, "get", "operationId"], "listDevices"), "duplicate operationId"),
    ("operationId not lowerCamelCase", set_(["paths", DEVICE, "get", "operationId"], "GetDevice"), "lowerCamelCase"),
    ("OpenAPI 3.0", set_(["openapi"], "3.0.3"), "must be 3.1.x"),
    ("servers without /api/v1", set_(["servers"], [{"url": "/api"}]), "must contain the url /api/v1"),
    ("no CSRF security scheme", pop(["components", "securitySchemes", "csrfToken"]), "no apiKey scheme for the header"),
]
for name, mutate, fragment in FIXTURES:
    s = copy.deepcopy(spec)
    mutate(s)
    found = ol.lint(s, master)
    check(any(fragment in e for e in found), f"fixture fails: {name}",
          f"no error containing {fragment!r}; got {found or 'no errors'}")

# ====================================================================== standalone fixture specs through the CLI

MINI_HEAD = """openapi: 3.1.0
info: {title: fixture, version: '1'}
servers:
  - url: /api/v1
security:
  - s: []
components:
  securitySchemes:
    s: {type: apiKey, in: cookie, name: __Host-mg_session}
    c: {type: apiKey, in: header, name: X-CSRF-Token}
  responses:
    E:
      description: problem
      content:
        application/problem+json:
          schema: {$ref: '#/components/schemas/Problem'}
  schemas:
    Problem:
      type: object
      properties: {type: {}, title: {}, status: {}, detail: {}, instance: {}, code: {}, request_id: {}, errors: {}}
"""
MINI_OK = MINI_HEAD + """paths:
  /tenants/{tenantId}/dashboard:
    get:
      operationId: getTenantDashboard
      x-permission: tenant.dashboard:read
      x-task: P2-T13a
      x-audit-action: dashboard.read
      parameters:
        - {name: tenantId, in: path, required: true, schema: {type: string, format: uuid}}
      responses:
        '200':
          description: ok
        '401': {$ref: '#/components/responses/E'}
        '403': {$ref: '#/components/responses/E'}
        '404': {$ref: '#/components/responses/E'}
        '429': {$ref: '#/components/responses/E'}
        default: {$ref: '#/components/responses/E'}
"""
MINI_BAD = MINI_HEAD + """paths:
  /tenants/{tenantId}/devices/{deviceId}:expire:
    post:
      operationId: expireDevice
      x-task: P2-T13
      x-audit-action: device.expire
      parameters:
        - {name: tenantId, in: path, required: true, schema: {type: string, format: uuid}}
        - {name: tenant, in: query, schema: {type: string}}
      responses:
        '202':
          description: accepted
        '404':
          description: not found
          content:
            application/json:
              schema: {type: object}
"""
with tempfile.TemporaryDirectory() as d:
    ok_file, bad_file = pathlib.Path(d) / "ok.yaml", pathlib.Path(d) / "bad.yaml"
    ok_file.write_text(MINI_OK, encoding="utf-8")
    bad_file.write_text(MINI_BAD, encoding="utf-8")
    check(cli("--spec", str(ok_file)) == 0, "CLI: minimal valid fixture spec passes (exit 0)")
    check(cli("--spec", str(bad_file)) == 1, "CLI: bad fixture spec fails (exit 1)")
    bad = ol.lint(ol.load_yaml(MINI_BAD), master)
    for fragment in ("mixes a {param} with text", "missing x-permission", "tenant taken from the query parameter",
                     "must be application/problem+json only", "must carry Location", "Idempotency-Key", "X-CSRF-Token"):
        check(any(fragment in e for e in bad), f"bad fixture spec reports: {fragment}", str(bad))
    yaml_err = pathlib.Path(d) / "broken.yaml"
    yaml_err.write_text("openapi: 3.1.0\npaths: &p {}\n", encoding="utf-8")
    check(cli("--spec", str(yaml_err)) == 2, "CLI: unsupported YAML is a usage error (exit 2)")
    same, other = pathlib.Path(d) / "same.json", pathlib.Path(d) / "other.json"
    same.write_text(json.dumps(spec), encoding="utf-8")
    changed = copy.deepcopy(spec)
    changed["info"]["version"] = "9"
    other.write_text(json.dumps(changed), encoding="utf-8")
    check(cli("--compare-json", str(same)) == 0, "CLI: --compare-json equal parse (exit 0)")
    check(cli("--compare-json", str(other)) == 1, "CLI: --compare-json detects a difference (exit 1)")

print(f"\n{'OK' if not failures else f'{failures} FAILURE(S)'}")
sys.exit(1 if failures else 0)
