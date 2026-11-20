// Connectivity Diagnostics (P5-T08): trạng thái control plane kèm thời điểm quan sát + "không khả dụng" kèm lý do (không
// số giả), form kiểm kết nối (thiết bị/tài nguyên/cổng, kiểm phía client chỉ để hướng dẫn), kết quả: kết luận, phép kiểm,
// checklist theo OS có nút sao chép; điều hướng theo rbac (End User thấy mục, không thấy phần trạng thái tenant và tài
// nguyên; Tenant Viewer không thấy mục); axe vi/en; khóa i18n động có trong cả hai catalog.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi as vitest } from "vitest";
import type { components } from "../../api/schema";
import { i18n } from "../../i18n";
import en from "../../i18n/locales/en.json";
import vi from "../../i18n/locales/vi.json";
import { json, mockApi, problem, renderApp, TENANT_A, tenantBody, tenantSession } from "../../test/helpers";
import { resource } from "../../test/network";
import { DEV_1, DEV_2, device, SYNCED } from "../../test/portal";
import { CHECK_TONE, OS_LIST, VERDICT_TONE } from "./DiagnosticsPage";

type S = components["schemas"];
const base = `/tenants/${TENANT_A}`;

function instanceState(over: Partial<S["TenantDiagnostics"]> = {}): S["TenantDiagnostics"] {
  return {
    checked_at: "2026-11-20T08:00:00Z",
    tenant_status: "active",
    instance: {
      status: "running",
      health: { status: "healthy", checked_at: "2026-11-20T07:59:00Z" },
      api_key: { status: "expiring", expires_at: "2026-11-27T00:00:00Z" },
    },
    edge: { status: "reachable", checked_at: "2026-11-20T07:58:00Z" },
    relays: [
      { code: "mg-tenant-a", name: "MeshGuard tenant-a", hostname: "tenant-a.mesh.example.test", status: "active", health: "healthy", checked_at: "2026-11-20T07:58:00Z", derp_ok: true, stun_ok: true },
    ],
    policy: { applied: true, version: 7, applied_sha256: "a".repeat(64), applied_at: "2026-11-20T07:00:00Z", trigger: "manual", desired_version: 7 },
    devices: { total: 4, online: 3, offline: 1, expired: 1, synced_at: SYNCED },
    unavailable: [
      { section: "noise", reason: "no_probe", detail: "x" },
      { section: "p2p_path", reason: "not_observable", detail: "y" },
    ],
    ...over,
  };
}

function diagnosis(over: Partial<S["ConnectivityDiagnosis"]> = {}): S["ConnectivityDiagnosis"] {
  const dev = (id: string, name: string, ip: string): S["DiagnosticsDevice"] => ({
    id,
    name,
    given_name: name,
    ip_addresses: [ip],
    tags: [],
    online: true,
    last_seen: null,
    expiry: null,
    revocation_state: "none",
    synced_at: SYNCED,
  });
  const cmds: S["DiagnosticsCommand"][] = [];
  for (const os of ["linux", "macos", "windows"] as const) {
    cmds.push({ id: "status", os, run_on: "source", command: "tailscale status" });
    cmds.push({ id: "ping", os, run_on: "source", command: "tailscale ping --c 5 100.64.0.2" });
    cmds.push({ id: "netcheck", os, run_on: "source", command: "tailscale netcheck" });
    cmds.push({ id: "debug_derp", os, run_on: "source", command: "tailscale debug derp mg-tenant-a" });
    cmds.push({
      id: "tcp_connect",
      os,
      run_on: "source",
      command: os === "windows" ? "Test-NetConnection -ComputerName 100.64.0.2 -Port 443" : "nc -vz -w 5 100.64.0.2 443",
    });
  }
  return {
    checked_at: "2026-11-20T08:01:00Z",
    path_observable: false,
    verdict: "allowed",
    source: dev(DEV_1, "laptop-1", "100.64.0.1"),
    target: { kind: "device", device: dev(DEV_2, "laptop-2", "100.64.0.2"), routers: [] },
    port: 443,
    checks: [
      { id: "tenant_active", status: "pass" },
      { id: "source_online", status: "pass" },
      { id: "policy_grant", status: "pass" },
      { id: "relay_healthy", status: "warn", reason: "relay_unhealthy" },
    ],
    policy: { applied: true, version: 7, access: { decision: "allowed", grants: [0], allowed: ["tcp:443"], unresolved: [] } },
    relay_code: "mg-tenant-a",
    commands: cmds,
    ...over,
  };
}

function apiFor(role: string, extra: Record<string, Response | ((r: Request) => Response | Promise<Response>)> = {}) {
  return {
    "GET /auth/session": json(200, tenantSession([{ tenantId: TENANT_A, slug: "tenant-a", name: "Tenant A", role }])),
    [`GET ${base}`]: json(200, tenantBody(TENANT_A, "tenant-a")),
    [`GET ${base}/notifications`]: json(200, { items: [], next_cursor: null }),
    [`GET ${base}/diagnostics/instance`]: json(200, instanceState()),
    [`GET ${base}/devices`]: json(200, { items: [device(DEV_1), device(DEV_2)], next_cursor: null }),
    [`GET ${base}/resources`]: json(200, { items: [resource()], next_cursor: null }),
    [`POST ${base}/diagnostics/connectivity`]: json(200, diagnosis()),
    ...extra,
  };
}

async function violations(): Promise<string[]> {
  const r = await axe.run(document.body, {
    runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"] },
    rules: { "color-contrast": { enabled: false } },
  });
  return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
}

async function runCheck(user: ReturnType<typeof userEvent.setup>, port = "443") {
  const form = await screen.findByTestId("diag-form");
  const [src, dst] = within(form).getAllByRole("combobox");
  await user.selectOptions(src!, DEV_1);
  await user.selectOptions(dst!, DEV_2);
  if (port) await user.type(within(form).getByRole("textbox"), port);
  await user.click(within(form).getByTestId("diag-run"));
}

afterEach(() => {
  vitest.unstubAllGlobals();
});

describe("Connectivity Diagnostics", () => {
  it("Tenant Owner: trạng thái control plane kèm thời điểm, không khả dụng kèm lý do", async () => {
    await i18n.changeLanguage("vi");
    mockApi(apiFor("tenant_owner"));
    renderApp({ path: `/t/${TENANT_A}/diagnostics` });
    const inst = await screen.findByTestId("diag-card-instance");
    expect(within(inst).getByTestId("diag-instance-health")).toHaveTextContent("Khỏe");
    expect(within(inst).getByTestId("diag-api-key")).toHaveTextContent("Sắp hết hạn");
    expect(within(inst).getAllByRole("time").length).toBeGreaterThan(0);
    expect(screen.getByTestId("diag-edge")).toHaveTextContent("Tới được");
    expect(screen.getByTestId("diag-policy-version")).toHaveTextContent("7");
    expect(screen.getByTestId("diag-devices-expired")).toHaveTextContent("1");
    expect(screen.getAllByTestId("diag-relay")).toHaveLength(1);
    expect(screen.getAllByTestId("unavailable-section")).toHaveLength(2);
    expect(screen.getByTestId("diag-not-observable")).toHaveTextContent("không thể quan sát");
  });

  it("dữ liệu thiếu ⇒ 'không khả dụng', không số giả", async () => {
    await i18n.changeLanguage("en");
    mockApi(
      apiFor("tenant_admin", {
        [`GET ${base}/diagnostics/instance`]: json(
          200,
          instanceState({
            tenant_status: "suspended",
            policy: { applied: false },
            devices: { total: 0, online: 0, offline: 0, expired: 0, synced_at: null },
            relays: [],
            edge: { status: "unknown", reason: "no_relay", checked_at: null },
            instance: { health: { status: "unknown", reason: "no_instance", checked_at: null }, api_key: { status: "unknown", expires_at: null } },
          }),
        ),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/diagnostics` });
    expect(await screen.findByTestId("diag-devices-unavailable")).toHaveTextContent("unavailable");
    expect(screen.queryByTestId("diag-devices-total")).toBeNull();
    expect(screen.getByTestId("diag-policy-none")).toBeInTheDocument();
    expect(screen.getByTestId("diag-tenant-status")).toHaveTextContent("Suspended");
    expect(screen.queryByTestId("diag-card-relays")).toBeNull();
  });

  it("kiểm kết nối: gửi đúng body, hiện kết luận, phép kiểm, checklist theo OS có nút sao chép", async () => {
    await i18n.changeLanguage("vi");
    const user = userEvent.setup();
    const { requests } = mockApi(apiFor("tenant_owner"));
    const writeText = vitest.fn(() => Promise.resolve());
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    renderApp({ path: `/t/${TENANT_A}/diagnostics` });
    await runCheck(user);
    const result = await screen.findByTestId("diag-result");
    const post = requests.find((r) => r.method === "POST");
    expect(await post?.json()).toEqual({ source_device_id: DEV_1, target_device_id: DEV_2, port: 443 });
    expect(post?.headers.get("X-CSRF-Token")).toBeTruthy();
    expect(within(result).getByTestId("diag-verdict")).toHaveTextContent("Control plane cho phép");
    expect(within(result).getByTestId("diag-result-not-observable")).toBeInTheDocument();
    expect(within(result).getAllByTestId("diag-check")).toHaveLength(4);
    expect(within(result).getByTestId("diag-access")).toHaveTextContent("tcp:443");
    // Linux mặc định: 5 lệnh, có nc; đổi sang Windows ⇒ Test-NetConnection
    let cmds = within(result).getAllByTestId("diag-command");
    expect(cmds).toHaveLength(5);
    expect(within(result).getByText("nc -vz -w 5 100.64.0.2 443")).toBeInTheDocument();
    await user.click(within(result).getByRole("radio", { name: "Windows (PowerShell)" }));
    cmds = within(result).getAllByTestId("diag-command");
    expect(within(result).getByText("Test-NetConnection -ComputerName 100.64.0.2 -Port 443")).toBeInTheDocument();
    await user.click(within(cmds[4]!).getByRole("button", { name: /Sao chép lệnh: Test-NetConnection/ }));
    expect(writeText).toHaveBeenCalledWith("Test-NetConnection -ComputerName 100.64.0.2 -Port 443");
    expect(await within(cmds[4]!).findByRole("status")).toHaveTextContent("Đã sao chép.");
  });

  it("kiểm phía client: thiếu nguồn/đích, cổng sai ⇒ không gửi", async () => {
    await i18n.changeLanguage("en");
    const user = userEvent.setup();
    const { requests } = mockApi(apiFor("tenant_owner"));
    renderApp({ path: `/t/${TENANT_A}/diagnostics` });
    const form = await screen.findByTestId("diag-form");
    await user.type(within(form).getByRole("textbox"), "70000");
    await user.click(within(form).getByTestId("diag-run"));
    expect(within(form).getAllByText("Required.")).toHaveLength(2);
    expect(within(form).getByRole("textbox")).toHaveAttribute("aria-invalid", "true");
    expect(requests.some((r) => r.method === "POST")).toBe(false);
  });

  it("tài nguyên đích (có tenant.resource:read) ⇒ target_resource_id; 404 hiện lỗi", async () => {
    await i18n.changeLanguage("en");
    const user = userEvent.setup();
    const { requests } = mockApi(apiFor("tenant_admin", { [`POST ${base}/diagnostics/connectivity`]: problem(404, "not_found") }));
    renderApp({ path: `/t/${TENANT_A}/diagnostics` });
    const form = await screen.findByTestId("diag-form");
    await user.click(within(form).getByRole("radio", { name: "Network resource" }));
    const [src, dst] = within(form).getAllByRole("combobox");
    await user.selectOptions(src!, DEV_1);
    await user.selectOptions(dst!, resource().id);
    await user.click(within(form).getByTestId("diag-run"));
    await screen.findByRole("alert");
    const post = requests.find((r) => r.method === "POST");
    expect(await post?.json()).toEqual({ source_device_id: DEV_1, target_resource_id: resource().id });
  });

  it("End User: thấy mục, không gọi trạng thái tenant, không có lựa chọn tài nguyên", async () => {
    await i18n.changeLanguage("vi");
    const { requests } = mockApi(apiFor("end_user"));
    renderApp({ path: `/t/${TENANT_A}/diagnostics` });
    const form = await screen.findByTestId("diag-form");
    expect(screen.getByRole("link", { name: "Chẩn đoán" })).toBeInTheDocument();
    expect(screen.queryByTestId("diag-instance")).toBeNull();
    expect(within(form).queryByRole("radio", { name: "Tài nguyên mạng" })).toBeNull();
    await waitFor(() => expect(requests.some((r) => r.url.includes("/devices"))).toBe(true));
    expect(requests.some((r) => r.url.includes("/diagnostics/instance") || r.url.includes("/resources"))).toBe(false);
  });

  it("Tenant Viewer: không có mục, vào thẳng ⇒ không được phép", async () => {
    await i18n.changeLanguage("en");
    const { requests } = mockApi(apiFor("tenant_viewer"));
    renderApp({ path: `/t/${TENANT_A}/diagnostics` });
    await screen.findByRole("heading", { level: 1 });
    expect(screen.queryByRole("link", { name: "Diagnostics" })).toBeNull();
    expect(screen.queryByTestId("diag-form")).toBeNull();
    expect(requests.some((r) => r.url.includes("/diagnostics"))).toBe(false);
  });

  it("tenant chỉ-đọc (suspended) ⇒ nút kiểm bị khóa", async () => {
    await i18n.changeLanguage("en");
    mockApi(apiFor("tenant_owner", { [`GET ${base}`]: json(200, tenantBody(TENANT_A, "tenant-a", "suspended")) }));
    renderApp({ path: `/t/${TENANT_A}/diagnostics` });
    const form = await screen.findByTestId("diag-form");
    await waitFor(() => expect(within(form).getByTestId("diag-run")).toBeDisabled());
  });
});

describe.each(["vi", "en"] as const)("axe Diagnostics (%s)", (lng) => {
  it("trạng thái + form + kết quả", async () => {
    await i18n.changeLanguage(lng);
    const user = userEvent.setup();
    mockApi(apiFor("tenant_owner"));
    renderApp({ path: `/t/${TENANT_A}/diagnostics` });
    await screen.findByTestId("diag-card-instance");
    await screen.findByTestId("diag-form");
    expect(await violations()).toEqual([]);
    await runCheck(user);
    await screen.findByTestId("diag-result");
    expect(await violations()).toEqual([]);
  });

  it("lỗi field phía client", async () => {
    await i18n.changeLanguage(lng);
    const user = userEvent.setup();
    mockApi(apiFor("tenant_owner"));
    renderApp({ path: `/t/${TENANT_A}/diagnostics` });
    const form = await screen.findByTestId("diag-form");
    await user.click(within(form).getByTestId("diag-run"));
    expect(await violations()).toEqual([]);
  });
});

type Tree = { [k: string]: string | Tree };
function has(tree: Tree, key: string): boolean {
  let node: string | Tree | undefined = tree;
  for (const part of key.split(".")) {
    if (typeof node !== "object") return false;
    node = node[part] ?? node[`${part}_other`];
  }
  return typeof node === "string";
}

describe("khóa i18n động của P5-T08", () => {
  it("enum của API mà màn hình dịch có trong vi và en", () => {
    const checks: S["DiagnosticsCheck"]["id"][] = [
      "tenant_active",
      "instance_healthy",
      "inventory_fresh",
      "source_online",
      "source_not_expired",
      "source_not_revoked",
      "target_online",
      "target_not_expired",
      "target_not_revoked",
      "route_approved",
      "policy_applied",
      "policy_grant",
      "relay_healthy",
    ];
    const commands: S["DiagnosticsCommand"]["id"][] = [
      "status",
      "ping",
      "netcheck",
      "debug_derp",
      "accept_routes",
      "tcp_connect",
      "http_probe",
      "listen_check",
    ];
    const keyStatus: S["DiagnosticsAPIKey"]["status"][] = ["valid", "expiring", "expired", "unknown"];
    const edge: S["DiagnosticsEdge"]["status"][] = ["reachable", "unreachable", "unknown"];
    const reasons = [
      "offline",
      "expired",
      "revocation_pending",
      "revocation_applied",
      "tenant_suspended",
      "no_approved_route",
      "router_offline",
      "tailnet_address",
      "stale_inventory",
      "latest_application_failed",
      "relay_unhealthy",
      "relay_unknown",
      "instance_unknown",
      "instance_unhealthy",
      "never_applied",
      "no_applied_policy",
      "no_matching_grant",
      "port_not_allowed",
      "no_tcp_allowed",
      "unreadable_policy",
      "unsupported_policy",
      "unresolved_principals",
    ];
    const keys = [
      ...checks.map((c) => `diagnostics.checks.${c}`),
      ...commands.flatMap((c) => [`diagnostics.commands.items.${c}.title`, `diagnostics.commands.items.${c}.expect`]),
      ...Object.keys(CHECK_TONE).map((s) => `diagnostics.checkStatus.${s}`),
      ...Object.keys(VERDICT_TONE).flatMap((v) => [`diagnostics.verdict.${v}`, `diagnostics.verdictExplain.${v}`]),
      ...OS_LIST.map((o) => `diagnostics.os.${o}`),
      ...keyStatus.map((s) => `diagnostics.apiKey.${s}`),
      ...edge.map((s) => `diagnostics.edge.${s}`),
      ...reasons.map((r) => `diagnostics.checkReasons.${r}`),
      ...["noise", "p2p_path", "devices", "policies", "relay"].map((s) => `diagnostics.sections.${s}`),
      ...["no_probe", "not_observable", "never_synced", "never_applied", "no_relay"].map((r) => `diagnostics.reasons.${r}`),
      "diagnostics.commands.runOn.source",
      "diagnostics.commands.runOn.target",
      "diagnostics.form.kinds.device",
      "diagnostics.form.kinds.resource",
    ];
    expect(keys.filter((k) => !has(vi as Tree, k) || !has(en as Tree, k))).toEqual([]);
  });
});
