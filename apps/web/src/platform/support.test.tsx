// Platform Console — Support Access (P4-T13, §8.7) và audit platform: xin grant (POST, Idempotency-Key + CSRF, chỉ tenant
// active/suspended), break-glass (gõ lại slug; 403 của người xin hiện trong hộp), thu hồi; grant đang hiệu lực của chính
// mình mở tenant; quyền theo role (Platform Viewer chỉ xem). Audit platform: lọc ⇒ tham số API.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { components } from "../api/schema";
import { CSRF, json, mockApi, platformSession, problem, renderApp } from "../test/helpers";
import { T1, T2, tenant } from "../test/platformFixtures";

vi.setConfig({ testTimeout: 30_000 });

const G1 = "0190f500-0000-7000-8000-000000000001";
const G2 = "0190f500-0000-7000-8000-000000000002";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function grant(id: string, over: Partial<components["schemas"]["SupportGrant"]> = {}): components["schemas"]["SupportGrant"] {
  return {
    id,
    tenant_id: T1,
    tenant_slug: "acme",
    effective_role: "support_operator",
    reason: "Khách báo thiết bị offline",
    ticket_ref: "SUP-7",
    status: "pending",
    active: false,
    grantee: { display_name: "Ops Staff" },
    starts_at: "2026-11-19T01:00:00Z",
    expires_at: "2026-11-19T02:00:00Z",
    created_at: "2026-11-19T01:00:00Z",
    ...over,
  };
}

const list = (items: unknown[], next: string | null = null) => json(200, { items, next_cursor: next });

describe("Support Access (platform)", () => {
  it("xin grant: chỉ tenant mở, POST đúng hợp đồng với Idempotency-Key + CSRF", async () => {
    const { requests } = mockApi({
      "GET /auth/session": json(200, platformSession("platform_support")),
      "GET /platform/support-grants": list([]),
      "GET /platform/tenants": list([tenant(T1, "acme"), tenant(T2, "gone", "deprovisioning")]),
      "POST /platform/support-grants": json(201, grant(G1)),
    });
    const user = userEvent.setup();
    renderApp({ path: "/platform/support-access", console: "platform" });
    const select = await screen.findByLabelText("Tenant");
    await waitFor(() => expect(within(select).getAllByRole("option")).toHaveLength(2)); // gợi ý + acme (gone bị loại)
    // G4b-E7: lọc trạng thái ở server (active, suspended) — không chỉ trang đầu của mọi tenant; gợi ý "gõ để tìm"
    const statuses = requests.filter((r) => new URL(r.url).pathname.endsWith("/platform/tenants")).map((r) => new URL(r.url).searchParams.get("status"));
    expect(new Set(statuses)).toEqual(new Set(["active", "suspended"]));
    expect(screen.getByLabelText("Tìm tenant")).toHaveAccessibleDescription(/gõ slug hoặc tên để tìm/);
    await user.selectOptions(select, T1);
    await user.type(screen.getByLabelText("Mã ticket"), "SUP-7");
    await user.type(screen.getByLabelText("Lý do"), "Khách báo thiết bị offline");
    await user.selectOptions(screen.getByLabelText("Thời lượng"), "120");
    await user.click(screen.getByRole("button", { name: "Gửi yêu cầu" }));
    await waitFor(() => expect(requests.some((r) => r.method === "POST")).toBe(true));
    const post = requests.find((r) => r.method === "POST")!;
    expect(post.headers.get("Idempotency-Key")).toMatch(UUID);
    expect(post.headers.get("X-CSRF-Token")).toBe(CSRF);
    expect(await post.json()).toEqual({ tenant_id: T1, effective_role: "support_operator", reason: "Khách báo thiết bị offline",
      ticket_ref: "SUP-7", duration_minutes: 120 });
    expect(await screen.findByText("Đã gửi yêu cầu — chờ tenant quyết định.")).toBeInTheDocument();
    // Platform Support: không break-glass, không thu hồi
    expect(screen.queryByRole("button", { name: "Duyệt break-glass" })).toBeNull();
  });

  it("Super Admin: break-glass cần gõ lại slug; 403 (người xin tự duyệt) hiện trong hộp; thu hồi", async () => {
    let breakglass = 0;
    const { requests } = mockApi({
      "GET /auth/session": json(200, platformSession("super_admin")),
      "GET /platform/support-grants": list([grant(G1), grant(G2, { status: "approved", active: true, approval_kind: "tenant" })]),
      "GET /platform/tenants": list([tenant(T1, "acme")]),
      [`POST /platform/support-grants/${G1}/approve-breakglass`]: () => {
        breakglass++;
        return problem(403, "forbidden", { detail: "Break-glass needs a second Super Admin: not the requester, not the grantee." });
      },
      [`POST /platform/support-grants/${G2}/revoke`]: json(200, grant(G2, { status: "revoked", revoked_at: "2026-11-19T01:10:00Z" })),
    });
    const user = userEvent.setup();
    renderApp({ path: "/platform/support-access", console: "platform" });
    const rows = await screen.findAllByTestId("grant-row");
    await user.click(within(rows[0]!).getByRole("button", { name: "Duyệt break-glass" }));
    const dialog = await screen.findByRole("alertdialog");
    const confirm = within(dialog).getByRole("button", { name: "Duyệt break-glass" });
    expect(confirm).toBeDisabled();
    await user.type(within(dialog).getByLabelText("Gõ slug của tenant để xác nhận"), "acme");
    await user.click(confirm);
    // giao diện vi: câu dịch theo code, không in `detail` tiếng Anh của 403 (G4b-E3)
    expect(await within(dialog).findByText("Bạn không có quyền thực hiện thao tác này.")).toBeInTheDocument();
    expect(dialog).not.toHaveTextContent("second Super Admin");
    expect(breakglass).toBe(1);
    await user.click(within(dialog).getByRole("button", { name: "Hủy" }));
    expect(within(rows[1]!).queryByRole("button", { name: "Duyệt break-glass" })).toBeNull();
    await user.click(within(rows[1]!).getByRole("button", { name: "Thu hồi" }));
    await user.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Thu hồi" }));
    await waitFor(() => expect(requests.some((r) => r.url.endsWith(`/support-grants/${G2}/revoke`))).toBe(true));
  });

  it("grant đang hiệu lực của chính mình ⇒ mở tenant; Platform Viewer chỉ xem", async () => {
    mockApi({
      "GET /auth/session": json(
        200,
        platformSession("platform_viewer", [{ id: G2, tenant_id: T1, effective_role: "support_operator", expires_at: "2099-01-01T00:00:00Z" }]),
      ),
      "GET /platform/support-grants": list([grant(G2, { status: "approved", active: true })]),
    });
    renderApp({ path: "/platform/support-access", console: "platform" });
    const row = await screen.findByTestId("grant-row");
    expect(within(row).getByRole("link", { name: "Mở tenant" })).toHaveAttribute("href", `/t/${T1}`);
    expect(screen.queryByRole("button", { name: "Gửi yêu cầu" })).toBeNull();
    expect(within(row).queryByRole("button")).toBeNull();
  });
});

describe("Audit (platform)", () => {
  it("danh sách sự kiện platform; lọc loại actor ⇒ tham số API", async () => {
    const { requests } = mockApi({
      "GET /auth/session": json(200, platformSession("platform_viewer")),
      "GET /platform/audit": list([
        {
          id: "0190f600-0000-7000-8000-000000000001",
          occurred_at: "2026-11-19T01:00:00Z",
          actor: { type: "identity", identity_id: "0190e000-0000-7000-8000-0000000000e1", display_name: "Ops Staff", support_grant_id: G1 },
          action: "platform.support_grant.request",
          resource: { type: "support_grant", id: G1 },
          outcome: "success",
          request_id: "req-1",
          details: { tenant_slug: "acme" },
        },
      ]),
    });
    const user = userEvent.setup();
    renderApp({ path: "/platform/audit", console: "platform" });
    const row = await screen.findByTestId("audit-row");
    expect(row).toHaveTextContent("platform.support_grant.request");
    await user.click(within(row).getByRole("button", { name: "Chi tiết" }));
    expect(await screen.findByText(/tenant_slug/)).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Loại actor"), "system");
    await user.click(screen.getByRole("button", { name: "Lọc" }));
    await waitFor(() => expect(new URL(requests.at(-1)!.url).searchParams.get("actor_type")).toBe("system"));
  });
});
