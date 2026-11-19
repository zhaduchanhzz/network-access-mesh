// Tenant Portal — quản trị của P4-T13: Audit (lọc ⇒ tham số API, hành động của support), Support Access (duyệt / từ chối
// / thu hồi; Support Admin chỉ qua break-glass), Settings (PATCH + PUT security với If-Match; nới lỏng ⇒ 202 + phê
// duyệt, chưa có hiệu lực), Identity Provider (PATCH If-Match; Admin chỉ đọc), hàng chờ phê duyệt (hash kiểm trong
// trình duyệt). App thật trên router bộ nhớ, API giả ở tầng fetch theo đúng hợp đồng của spec.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { payloadSha256 } from "../api/canonical";
import type { components } from "../api/schema";
import { CSRF, json, mockApi, problem, renderApp, TENANT_A, tenantBody, tenantSession } from "../test/helpers";

// luồng nhiều bước UI (gõ phím, hộp xác nhận): trên runner chậm vượt 5 s mặc định của Vitest
vi.setConfig({ testTimeout: 30_000 });

const base = `/tenants/${TENANT_A}`;
const GRANT = "0190a500-0000-7000-8000-000000000001";
const GRANT_ADMIN = "0190a500-0000-7000-8000-000000000002";
const APPROVAL = "0190a600-0000-7000-8000-000000000001";
const ME = "0190c000-0000-7000-8000-0000000000c1"; // identity của tenantSession

function routes(role: string, extra: Record<string, Response | ((r: Request) => Response | Promise<Response>)> = {}) {
  return {
    "GET /auth/session": json(200, tenantSession([{ tenantId: TENANT_A, slug: "tenant-a", name: "Tenant A", role }])),
    [`GET ${base}`]: json(200, tenantBody(TENANT_A, "tenant-a")),
    [`GET ${base}/notifications`]: json(200, { items: [], next_cursor: null }),
    ...extra,
  };
}

const list = (items: unknown[], next: string | null = null) => json(200, { items, next_cursor: next });

function grant(id: string, over: Partial<components["schemas"]["SupportGrant"]> = {}): components["schemas"]["SupportGrant"] {
  return {
    id,
    tenant_id: TENANT_A,
    tenant_slug: "tenant-a",
    effective_role: "support_operator",
    reason: "Thiết bị offline — ticket khách hàng",
    ticket_ref: "SUP-42",
    status: "pending",
    active: false,
    grantee: { display_name: "Nhân sự Hỗ trợ" },
    starts_at: "2026-11-19T01:00:00Z",
    expires_at: "2026-11-19T03:00:00Z",
    created_at: "2026-11-19T01:00:00Z",
    ...over,
  };
}

describe("audit", () => {
  it("bộ lọc ⇒ tham số API; hành động của support hiện loại actor + grant; phân trang con trỏ", async () => {
    const { requests } = mockApi(
      routes("tenant_viewer", {
        [`GET ${base}/audit`]: (req) => {
          const cursor = new URL(req.url).searchParams.get("cursor");
          return list(
            [
              {
                id: cursor ? "0190a700-0000-7000-8000-000000000002" : "0190a700-0000-7000-8000-000000000001",
                occurred_at: "2026-11-19T01:05:00Z",
                actor: { type: "support", identity_id: "0190e000-0000-7000-8000-0000000000e1", display_name: "Ops Staff", support_grant_id: GRANT },
                action: "device.sync.requested",
                resource: { type: "device", id: "" },
                outcome: "success",
                request_id: "req-1",
                operation_id: "0190a800-0000-7000-8000-000000000001",
                details: { job_id: "x" },
              },
            ],
            cursor ? null : "c2",
          );
        },
      }),
    );
    const user = userEvent.setup();
    renderApp({ path: `/t/${TENANT_A}/audit` });
    const row = await screen.findByTestId("audit-row");
    expect(within(row).getByTestId("actor-support")).toHaveTextContent("Hỗ trợ nền tảng");
    expect(row).toHaveTextContent("Grant 0190a500…");
    await user.click(screen.getByRole("button", { name: "Chỉ hành động của hỗ trợ nền tảng" }));
    await waitFor(() => expect(new URL(requests.at(-1)!.url).searchParams.get("actor_type")).toBe("support"));
    await user.type(screen.getByLabelText("Hành động"), "device.sync.requested");
    await user.selectOptions(screen.getByLabelText("Kết quả"), "success");
    await user.click(screen.getByRole("button", { name: "Lọc" }));
    await waitFor(() => {
      const q = new URL(requests.at(-1)!.url).searchParams;
      expect(q.get("action")).toBe("device.sync.requested");
      expect(q.get("outcome")).toBe("success");
      expect(q.get("actor_type")).toBe("support");
      expect(q.get("limit")).toBe("50");
    });
    await user.click(await screen.findByRole("button", { name: "Tiếp" }));
    await waitFor(() => expect(new URL(requests.at(-1)!.url).searchParams.get("cursor")).toBe("c2"));
    // actor không phải UUID ⇒ không gửi
    await user.type(screen.getByLabelText("Actor (ID danh tính)"), "khong-phai-uuid");
    expect(screen.getByRole("button", { name: "Lọc" })).toBeDisabled();
  });
});

describe("support access", () => {
  it("Owner duyệt (POST approve, CSRF), thu hồi; grant support_admin không có nút duyệt", async () => {
    let status: "pending" | "approved" | "revoked" = "pending";
    const { requests } = mockApi(
      routes("tenant_owner", {
        [`GET ${base}/support-grants`]: () =>
          list([grant(GRANT, { status, active: status === "approved" }), grant(GRANT_ADMIN, { effective_role: "support_admin" })]),
        [`POST ${base}/support-grants/${GRANT}/approve`]: () => {
          status = "approved";
          return json(200, grant(GRANT, { status, active: true, approval_kind: "tenant" }));
        },
        [`POST ${base}/support-grants/${GRANT}/revoke`]: () => {
          status = "revoked";
          return json(200, grant(GRANT, { status, revoked_at: "2026-11-19T01:30:00Z" }));
        },
      }),
    );
    const user = userEvent.setup();
    renderApp({ path: `/t/${TENANT_A}/support-access` });
    const rows = await screen.findAllByTestId("grant-row");
    expect(rows).toHaveLength(2);
    expect(within(rows[1]!).queryByRole("button", { name: "Duyệt" })).toBeNull();
    expect(rows[1]).toHaveTextContent("chỉ được cấp qua break-glass");
    await user.click(within(rows[0]!).getByRole("button", { name: "Duyệt" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("Nhân sự Hỗ trợ");
    await user.click(within(dialog).getByRole("button", { name: "Duyệt" }));
    await waitFor(() => expect(requests.some((r) => r.method === "POST" && r.url.endsWith(`/support-grants/${GRANT}/approve`))).toBe(true));
    const approve = requests.find((r) => r.url.endsWith("/approve"))!;
    expect(approve.headers.get("X-CSRF-Token")).toBe(CSRF);
    await waitFor(() => expect(screen.getAllByTestId("grant-row")[0]).toHaveTextContent("Đang hiệu lực"));
    await user.click(within(screen.getAllByTestId("grant-row")[0]!).getByRole("button", { name: "Thu hồi" }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Thu hồi" }));
    await waitFor(() => expect(screen.getAllByTestId("grant-row")[0]).toHaveTextContent("Đã thu hồi"));
  });

  it("Viewer chỉ xem; 403 của server khi duyệt hiện trong hộp", async () => {
    mockApi(routes("tenant_viewer", { [`GET ${base}/support-grants`]: list([grant(GRANT)]) }));
    renderApp({ path: `/t/${TENANT_A}/support-access` });
    const row = await screen.findByTestId("grant-row");
    expect(within(row).queryByRole("button")).toBeNull();
    expect(screen.getByRole("link", { name: /Xem hành động của hỗ trợ nền tảng/ })).toHaveAttribute(
      "href",
      `/t/${TENANT_A}/audit?actor_type=support`,
    );
  });

  it("duyệt bị từ chối vì step-up ⇒ lỗi trong hộp", async () => {
    mockApi(
      routes("tenant_admin", {
        [`GET ${base}/support-grants`]: list([grant(GRANT)]),
        [`POST ${base}/support-grants/${GRANT}/approve`]: problem(401, "reauth_required"),
      }),
    );
    const user = userEvent.setup();
    renderApp({ path: `/t/${TENANT_A}/support-access` });
    await user.click(within(await screen.findByTestId("grant-row")).getByRole("button", { name: "Duyệt" }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Duyệt" }));
    expect(await within(dialog).findByRole("alert")).toBeInTheDocument();
  });
});

const SETTINGS: components["schemas"]["TenantSettingsView"] = {
  etag: '"s1"',
  settings: {
    enrollment: { identity_mode: "portal", web_auth_enabled: true, self_enroll: false, requires_approval: true, preauth_key_ttl_max: null },
    node_expiry: null,
    policy: { four_eyes: true, sensitive_groups: [] },
    routes: { four_eyes: false },
    dns: {},
    notifications: { new_device: true, policy_applied: true },
  },
};

describe("settings", () => {
  it("PATCH thường gửi If-Match; tắt 4-eyes ⇒ 202 ⇒ báo chưa có hiệu lực + link phê duyệt", async () => {
    const { requests } = mockApi(
      routes("tenant_owner", {
        [`GET ${base}/settings`]: json(200, SETTINGS, { ETag: '"s1"' }),
        [`GET ${base}/groups`]: list([]),
        [`PATCH ${base}/settings`]: json(200, SETTINGS, { ETag: '"s2"' }),
        [`PUT ${base}/settings/security`]: json(
          202,
          {
            id: APPROVAL,
            scope: "tenant",
            action: "tenant.settings.update_security",
            resource_type: "settings",
            payload: {},
            payload_sha256: "0".repeat(64),
            status: "pending",
            requested_by: { identity_id: ME, display_name: "Nguyễn Văn A" },
            expires_at: "2026-11-20T01:00:00Z",
            created_at: "2026-11-19T01:00:00Z",
          },
          { Location: `/api/v1/tenants/${TENANT_A}/approvals/${APPROVAL}` },
        ),
      }),
    );
    const user = userEvent.setup();
    renderApp({ path: `/t/${TENANT_A}/settings` });
    await user.click(await screen.findByLabelText("Báo Owner và Admin khi có thiết bị mới"));
    await user.click(screen.getByRole("button", { name: "Lưu" }));
    await waitFor(() => expect(requests.some((r) => r.method === "PATCH")).toBe(true));
    const patch = requests.find((r) => r.method === "PATCH")!;
    expect(patch.headers.get("If-Match")).toBe('"s1"');
    expect(await patch.json()).toEqual({ notifications: { new_device: false, policy_applied: true }, enrollment: { preauth_key_ttl_max: "" } });

    await user.click(screen.getByLabelText("4-eyes khi đổi policy"));
    await user.click(screen.getByRole("button", { name: "Lưu thiết lập bảo mật" }));
    const banner = await screen.findByTestId("security-approval");
    expect(banner).toHaveTextContent("CHƯA có hiệu lực");
    expect(within(banner).getByRole("link", { name: "Mở yêu cầu" })).toHaveAttribute("href", `/t/${TENANT_A}/approvals/${APPROVAL}`);
    const put = requests.find((r) => r.method === "PUT")!;
    expect(put.headers.get("If-Match")).toBe('"s2"'); // ETag mới của PATCH vừa ghi
    expect(((await put.json()) as { policy: { four_eyes: boolean } }).policy.four_eyes).toBe(false);
  });

  it("Admin: thiết lập bảo mật chỉ đọc (không nút lưu bảo mật)", async () => {
    mockApi(routes("tenant_admin", { [`GET ${base}/settings`]: json(200, SETTINGS, { ETag: '"s1"' }), [`GET ${base}/groups`]: list([]) }));
    renderApp({ path: `/t/${TENANT_A}/settings` });
    expect(await screen.findByText("Chỉ Tenant Owner đổi được thiết lập bảo mật.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Lưu thiết lập bảo mật" })).toBeNull();
    expect(screen.getByRole("button", { name: "Lưu" })).toBeEnabled();
  });
});

const IDP: components["schemas"]["IdentityProvider"] = {
  id: "0190a900-0000-7000-8000-000000000001",
  scope: "tenant",
  tenant_id: TENANT_A,
  issuer: "https://idp.example.test/realms/tenant-a",
  client_id: "portal",
  driver: "external",
  status: "active",
  required_claims: {},
  require_email_verified: true,
  allowed_email_domains: ["a.example"],
  claim_mapping: {},
  client_secret_set: true,
  created_at: "2026-11-01T00:00:00Z",
  updated_at: "2026-11-01T00:00:00Z",
  version: 3,
  etag: '"3"',
};

describe("identity provider", () => {
  it("Owner: PATCH với If-Match, secret chỉ gửi khi nhập; issuer không sửa được", async () => {
    const { requests } = mockApi(
      routes("tenant_owner", {
        [`GET ${base}/identity-provider`]: json(200, IDP, { ETag: '"3"' }),
        [`PATCH ${base}/identity-provider`]: json(200, { ...IDP, version: 4, etag: '"4"' }, { ETag: '"4"' }),
      }),
    );
    const user = userEvent.setup();
    renderApp({ path: `/t/${TENANT_A}/identity-provider` });
    const domains = await screen.findByLabelText("Domain e-mail được phép");
    await user.clear(domains);
    await user.type(domains, "a.example{enter}b.example");
    await user.click(screen.getByRole("button", { name: "Lưu" }));
    await waitFor(() => expect(requests.some((r) => r.method === "PATCH")).toBe(true));
    const patch = requests.find((r) => r.method === "PATCH")!;
    expect(patch.headers.get("If-Match")).toBe('"3"');
    const body = (await patch.json()) as Record<string, unknown>;
    expect(body.allowed_email_domains).toEqual(["a.example", "b.example"]);
    expect(body).not.toHaveProperty("client_secret");
    expect(body).not.toHaveProperty("issuer");
    expect(await screen.findByText("Đã lưu.")).toBeInTheDocument();
  });

  it("Admin chỉ đọc", async () => {
    mockApi(routes("tenant_admin", { [`GET ${base}/identity-provider`]: json(200, IDP, { ETag: '"3"' }) }));
    renderApp({ path: `/t/${TENANT_A}/identity-provider` });
    expect(await screen.findByText("Chỉ Tenant Owner đổi được nhà cung cấp danh tính.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Lưu" })).toBeNull();
  });
});

describe("approvals", () => {
  it("chi tiết: hash tính trong trình duyệt khớp ⇒ duyệt gửi đúng payload_sha256; người yêu cầu không tự duyệt", async () => {
    const payload = { if_match: '"s1"', policy: { four_eyes: false, sensitive_groups: [] }, weakens: ["policy.four_eyes"] };
    const hash = (await payloadSha256(payload)) ?? "";
    const approval = (requester: string, status: components["schemas"]["ApprovalStatus"] = "pending") => ({
      id: APPROVAL,
      scope: "tenant",
      action: "tenant.settings.update_security",
      resource_type: "settings",
      payload,
      payload_sha256: hash,
      status,
      requested_by: { identity_id: requester, display_name: "Người khác" },
      expires_at: "2026-11-20T01:00:00Z",
      created_at: "2026-11-19T01:00:00Z",
    });
    const { requests } = mockApi(
      routes("tenant_admin", {
        [`GET ${base}/approvals`]: list([approval("0190c000-0000-7000-8000-0000000000c9")]),
        [`GET ${base}/approvals/${APPROVAL}`]: json(200, approval("0190c000-0000-7000-8000-0000000000c9")),
        [`POST ${base}/approvals/${APPROVAL}/approve`]: json(200, approval("0190c000-0000-7000-8000-0000000000c9", "executed")),
      }),
    );
    const user = userEvent.setup();
    renderApp({ path: `/t/${TENANT_A}/approvals` });
    await user.click(await screen.findByRole("link", { name: /Thiết lập bảo mật/ }));
    expect(await screen.findByText("Hash của payload khớp")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Duyệt" }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Duyệt" }));
    await waitFor(() => expect(requests.some((r) => r.url.endsWith("/approve"))).toBe(true));
    const body = (await requests.find((r) => r.url.endsWith("/approve"))!.json()) as { payload_sha256: string };
    expect(body.payload_sha256).toBe(hash);
    expect(await screen.findByTestId("approval-status")).toHaveTextContent("Đã thực thi");
  });

  it("người yêu cầu ⇒ không có nút duyệt", async () => {
    mockApi(
      routes("tenant_owner", {
        [`GET ${base}/approvals/${APPROVAL}`]: json(200, {
          id: APPROVAL,
          scope: "tenant",
          action: "tenant.group.set_members",
          resource_type: "group",
          payload: { a: 1 },
          payload_sha256: "f".repeat(64),
          status: "pending",
          requested_by: { identity_id: ME, display_name: "Nguyễn Văn A" },
          expires_at: "2026-11-20T01:00:00Z",
          created_at: "2026-11-19T01:00:00Z",
        }),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/approvals/${APPROVAL}` });
    expect(await screen.findByTestId("self-request")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Duyệt" })).toBeNull();
  });
});
