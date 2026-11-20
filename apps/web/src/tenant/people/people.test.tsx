// Users / Groups / Invitations (P4-T09a): chạy cả App trên router bộ nhớ với API giả ở tầng fetch theo đúng hợp đồng
// của spec (JSON / problem+json, ETag, Location). Kiểm: thao tác hiện theo role + quy tắc 3a (UI) nhưng lỗi của server
// (403/409/412/401 reauth_required) luôn hiện đúng; If-Match = ETag đã đọc; Idempotency-Key; offboard hai pha poll tới
// applied; group sensitive ⇒ 202 + phê duyệt (thành viên chưa đổi) ⇒ executed ⇒ đọc lại.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { queryKeys } from "../../api/queryClient";
import { i18n } from "../../i18n";
import { CSRF, json, mockApi, problem, renderApp, TENANT_A, tenantBody, tenantSession, type Handler } from "../../test/helpers";
import {
  ADMIN_2,
  approval,
  APPROVAL_1,
  END_USER,
  group,
  GROUP_1,
  INV_1,
  INV_ADMIN,
  invitation,
  INVITE_JOB,
  job,
  ME,
  member,
  MEMBERS,
  OFFBOARD_JOB,
  OFFBOARDED,
  OPERATOR,
  OWNER_2,
} from "../../test/people";

const base = `/tenants/${TENANT_A}`;
const list = (items: unknown[], next: string | null = null) => json(200, { items, next_cursor: next });
const etagged = (body: unknown, etag: string) => json(200, body, { ETag: etag });

function routes(role: string, extra: Record<string, Handler | Response> = {}, status: "active" | "suspended" = "active") {
  return {
    "GET /auth/session": json(200, tenantSession([{ tenantId: TENANT_A, slug: "tenant-a", name: "Tenant A", role }])),
    [`GET ${base}`]: json(200, tenantBody(TENANT_A, "tenant-a", status)),
    [`GET ${base}/notifications`]: list([]),
    ...extra,
  };
}

const writes = (requests: Request[]) => requests.filter((r) => r.method !== "GET");
const dialog = () => screen.getByRole("alertdialog");

describe("Users — danh sách", () => {
  it("cột role/trạng thái/offboard, '(bạn)', bộ lọc ⇒ tham số API, phân trang con trỏ; nút mời theo quyền", async () => {
    const { requests } = mockApi(
      routes("tenant_admin", {
        [`GET ${base}/users`]: (req) => {
          const u = new URL(req.url).searchParams;
          if (u.get("cursor") === "c2") return list([MEMBERS.endUser]);
          return list([MEMBERS.me("tenant_admin"), MEMBERS.owner2, MEMBERS.offboarded, member(OPERATOR, "tenant_operator", { status: "locked" })], "c2");
        },
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/users` });
    const table = await screen.findByTestId("users-table");
    expect(within(table).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Tên", "Role", "Trạng thái"]);
    const rows = within(table).getAllByTestId("user-row");
    expect(rows[0]).toHaveTextContent("(bạn)");
    expect(rows[1]).toHaveTextContent("Tenant Owner");
    expect(within(rows[2]!).getByTestId("offboard-state")).toHaveTextContent("Offboard đã áp dụng");
    expect(rows[3]).toHaveTextContent("Đã khóa");
    expect(screen.getByRole("button", { name: "Mời thành viên" })).toBeEnabled();

    await userEvent.click(screen.getByRole("button", { name: "Trang sau" }));
    await waitFor(() => expect(screen.getAllByTestId("user-row")).toHaveLength(1));
    await userEvent.selectOptions(screen.getByLabelText("Role"), "tenant_operator");
    await userEvent.selectOptions(screen.getByLabelText("Trạng thái"), "locked");
    await userEvent.type(screen.getByLabelText("Tìm theo tên hoặc email"), "nguyen");
    await userEvent.click(screen.getByRole("button", { name: "Lọc" }));
    await waitFor(() => {
      const last = new URL(requests.filter((r) => r.url.includes("/users")).at(-1)!.url).searchParams;
      expect([last.get("role"), last.get("status"), last.get("q"), last.get("cursor")]).toEqual(["tenant_operator", "locked", "nguyen", null]);
    });
  });

  it("Tenant Viewer: không có nút mời; offboard đang pending ⇒ danh sách tự làm mới", async () => {
    let n = 0;
    mockApi(
      routes("tenant_viewer", {
        [`GET ${base}/users`]: () =>
          list([member(END_USER, "end_user", { status: "offboarded", offboarding: { state: ++n > 1 ? "applied" : "pending", job_id: OFFBOARD_JOB } })]),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/users` });
    expect(await screen.findByTestId("offboard-state")).toHaveTextContent("Đang offboard");
    expect(screen.queryByRole("button", { name: "Mời thành viên" })).toBeNull();
    await waitFor(() => expect(screen.getByTestId("offboard-state")).toHaveTextContent("Offboard đã áp dụng"), { timeout: 8000 });
  }, 12_000);
});

describe("Users — chi tiết: quy tắc 3a ở UI, server vẫn quyết định", () => {
  it("Tenant Admin xem Admin khác / Owner / chính mình: không có thao tác, kèm lý do", async () => {
    mockApi(
      routes("tenant_admin", {
        [`GET ${base}/users/${ADMIN_2}`]: etagged(MEMBERS.admin2, '"3"'),
        [`GET ${base}/users/${OWNER_2}`]: etagged(MEMBERS.owner2, '"3"'),
        [`GET ${base}/users/${ME}`]: etagged(MEMBERS.me("tenant_admin"), '"3"'),
      }),
    );
    const { router } = renderApp({ path: `/t/${TENANT_A}/users/${ADMIN_2}` });
    await screen.findByRole("heading", { name: "Người 2", level: 1 });
    expect(screen.getByTestId("no-actions")).toHaveTextContent("chỉ tác động lên role thấp hơn hẳn role của bạn");
    for (const name of ["Khóa", "Thu hồi session", "Đổi role", "Offboard…", "Chuyển quyền sở hữu…"]) {
      expect(screen.queryByRole("button", { name })).toBeNull();
    }
    await router.navigate(`/t/${TENANT_A}/users/${OWNER_2}`);
    await screen.findByRole("heading", { name: "Người 1", level: 1 });
    expect(screen.getByTestId("no-actions")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Khóa" })).toBeNull();
    await router.navigate(`/t/${TENANT_A}/users/${ME}`);
    await screen.findByRole("heading", { name: "Nguyễn Văn A", level: 1 });
    expect(screen.getByTestId("no-actions")).toHaveTextContent("tài khoản của bạn");
  });

  it("Tenant Admin xem Operator: khóa/offboard có; role chỉ gồm role dưới Admin; không chuyển quyền sở hữu", async () => {
    mockApi(routes("tenant_admin", { [`GET ${base}/users/${OPERATOR}`]: etagged(MEMBERS.operator, '"3"') }));
    renderApp({ path: `/t/${TENANT_A}/users/${OPERATOR}` });
    await screen.findByRole("heading", { name: "Người 3", level: 1 });
    expect(screen.getByRole("button", { name: "Khóa" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Offboard…" })).toBeEnabled();
    const opts = within(screen.getByLabelText("Role mới")).getAllByRole("option").map((o) => o.getAttribute("value"));
    expect(opts).toEqual(["tenant_viewer", "end_user"]);
    expect(screen.queryByRole("button", { name: "Chuyển quyền sở hữu…" })).toBeNull();
  });

  it("Tenant Viewer: không thao tác, không thông báo quy tắc", async () => {
    mockApi(routes("tenant_viewer", { [`GET ${base}/users/${END_USER}`]: etagged(MEMBERS.endUser, '"3"') }));
    renderApp({ path: `/t/${TENANT_A}/users/${END_USER}` });
    await screen.findByRole("heading", { name: "Người 4", level: 1 });
    expect(screen.queryByRole("button", { name: "Khóa" })).toBeNull();
    expect(screen.queryByTestId("no-actions")).toBeNull();
  });

  it("khóa: PATCH {status: locked} với If-Match = ETag đã đọc + CSRF ⇒ trạng thái mới; 403 của server hiện trong hộp", async () => {
    let n = 0;
    const { requests } = mockApi(
      routes("tenant_owner", {
        [`GET ${base}/users/${END_USER}`]: etagged(MEMBERS.endUser, '"3"'),
        [`PATCH ${base}/users/${END_USER}`]: () =>
          ++n === 1 ? problem(403, "forbidden", { detail: "The request is not allowed." }) : etagged({ ...MEMBERS.endUser, status: "locked", version: 4 }, '"4"'),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/users/${END_USER}` });
    await screen.findByRole("heading", { name: "Người 4", level: 1 });
    await userEvent.click(screen.getByRole("button", { name: "Khóa" }));
    await userEvent.click(within(dialog()).getByRole("button", { name: "Khóa" }));
    expect(await within(dialog()).findByRole("alert")).toHaveTextContent("Bạn không có quyền");
    await userEvent.click(within(dialog()).getByRole("button", { name: "Khóa" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(screen.getByText("Đã khóa", { selector: "[data-status=locked]" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Mở khóa" })).toBeInTheDocument();
    const patch = writes(requests).filter((r) => r.method === "PATCH");
    expect(patch.map((r) => r.headers.get("If-Match"))).toEqual(['"3"', '"3"']);
    expect(patch[1]!.headers.get("X-CSRF-Token")).toBe(CSRF);
    expect(await patch[1]!.json()).toEqual({ status: "locked" });
  });

  it("412 (bản đã cũ) ⇒ lỗi hiện + đọc lại thành viên; lần sau gửi ETag mới", async () => {
    let gets = 0;
    let patches = 0;
    const { requests } = mockApi(
      routes("tenant_owner", {
        [`GET ${base}/users/${END_USER}`]: () => (++gets === 1 ? etagged(MEMBERS.endUser, '"3"') : etagged({ ...MEMBERS.endUser, version: 5 }, '"5"')),
        [`PATCH ${base}/users/${END_USER}`]: () =>
          ++patches === 1 ? problem(412, "precondition_failed") : etagged({ ...MEMBERS.endUser, status: "locked" }, '"6"'),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/users/${END_USER}` });
    await screen.findByRole("heading", { name: "Người 4", level: 1 });
    await userEvent.click(screen.getByRole("button", { name: "Khóa" }));
    await userEvent.click(within(dialog()).getByRole("button", { name: "Khóa" }));
    expect(await within(dialog()).findByRole("alert")).toHaveTextContent("đã bị thay đổi");
    await waitFor(() => expect(gets).toBe(2));
    await userEvent.click(within(dialog()).getByRole("button", { name: "Khóa" }));
    await waitFor(() => expect(patches).toBe(2));
    expect(writes(requests).map((r) => r.headers.get("If-Match"))).toEqual(['"3"', '"5"']);
  });

  it("đổi role: dưới Admin ⇒ PUT /role; lên Admin ⇒ PUT /admin-role; 401 reauth_required ⇒ nút xác thực lại trong hộp", async () => {
    let adminCalls = 0;
    const { requests } = mockApi(
      routes("tenant_owner", {
        [`GET ${base}/users/${END_USER}`]: etagged(MEMBERS.endUser, '"3"'),
        [`PUT ${base}/users/${END_USER}/role`]: async (req) => {
          const b = (await req.json()) as { role: string };
          return etagged({ ...MEMBERS.endUser, role: b.role, version: 4 }, '"4"');
        },
        [`PUT ${base}/users/${END_USER}/admin-role`]: () =>
          ++adminCalls === 1 ? problem(401, "reauth_required") : etagged({ ...MEMBERS.endUser, role: "tenant_admin", version: 5 }, '"5"'),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/users/${END_USER}` });
    await screen.findByRole("heading", { name: "Người 4", level: 1 });
    const select = screen.getByLabelText("Role mới");
    expect(within(select).getAllByRole("option").map((o) => o.getAttribute("value"))).toEqual(["tenant_admin", "tenant_operator", "tenant_viewer"]);
    await userEvent.selectOptions(select, "tenant_viewer");
    await userEvent.click(screen.getByRole("button", { name: "Đổi role" }));
    await userEvent.click(within(dialog()).getByRole("button", { name: "Đổi role" }));
    await waitFor(() => expect(screen.getByTestId("user-role")).toHaveTextContent("Tenant Viewer"));
    expect(await writes(requests)[0]!.json()).toEqual({ role: "tenant_viewer" });
    expect(writes(requests)[0]!.headers.get("If-Match")).toBe('"3"');

    await userEvent.selectOptions(screen.getByLabelText("Role mới"), "tenant_admin");
    expect(screen.getByText(/cần đăng nhập lại gần đây \(step-up\)/, { selector: "p.hint" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Đổi role" }));
    await userEvent.click(within(dialog()).getByRole("button", { name: "Đổi role" }));
    expect(await within(dialog()).findByRole("button", { name: "Xác thực lại" })).toBeInTheDocument();
    await userEvent.click(within(dialog()).getByRole("button", { name: "Đổi role" }));
    await waitFor(() => expect(screen.getByTestId("user-role")).toHaveTextContent("Tenant Admin"));
    const admin = writes(requests).filter((r) => r.url.endsWith("/admin-role"));
    expect(admin.map((r) => r.headers.get("If-Match"))).toEqual(['"4"', '"4"']);
  });

  it("Owner hạ một Admin ⇒ PUT /admin-role (không phải /role)", async () => {
    const { requests } = mockApi(
      routes("tenant_owner", {
        [`GET ${base}/users/${ADMIN_2}`]: etagged(MEMBERS.admin2, '"7"'),
        [`PUT ${base}/users/${ADMIN_2}/admin-role`]: etagged({ ...MEMBERS.admin2, role: "tenant_operator" }, '"8"'),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/users/${ADMIN_2}` });
    await screen.findByRole("heading", { name: "Người 2", level: 1 });
    await userEvent.selectOptions(screen.getByLabelText("Role mới"), "tenant_operator");
    await userEvent.click(screen.getByRole("button", { name: "Đổi role" }));
    await userEvent.click(within(dialog()).getByRole("button", { name: "Đổi role" }));
    await waitFor(() => expect(writes(requests)).toHaveLength(1));
    expect(writes(requests)[0]!.url).toMatch(/\/admin-role$/);
    expect(await writes(requests)[0]!.json()).toEqual({ role: "tenant_operator" });
  });

  it("thu hồi session ⇒ DELETE …/sessions", async () => {
    const { requests } = mockApi(
      routes("tenant_admin", {
        [`GET ${base}/users/${END_USER}`]: etagged(MEMBERS.endUser, '"3"'),
        [`DELETE ${base}/users/${END_USER}/sessions`]: () => new Response(null, { status: 204 }),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/users/${END_USER}` });
    await screen.findByRole("heading", { name: "Người 4", level: 1 });
    await userEvent.click(screen.getByRole("button", { name: "Thu hồi session" }));
    await userEvent.click(within(dialog()).getByRole("button", { name: "Thu hồi session" }));
    expect(await screen.findByTestId("sessions-revoked")).toBeInTheDocument();
    expect(writes(requests).map((r) => `${r.method} ${new URL(r.url).pathname}`)).toEqual([`DELETE /api/v1${base}/users/${END_USER}/sessions`]);
  });

  it("offboard: phải gõ lại email ⇒ DELETE ⇒ 202 pending (không nói đã xong) ⇒ poll tới applied; job hiện kèm", async () => {
    let state: "none" | "pending" | "applied" = "none";
    let polls = 0;
    const current = () =>
      state === "none" ? MEMBERS.endUser : { ...MEMBERS.endUser, status: "offboarded", offboarding: { state, job_id: OFFBOARD_JOB } };
    const { requests } = mockApi(
      routes("tenant_admin", {
        [`GET ${base}/users/${END_USER}`]: () => {
          if (state === "pending" && ++polls >= 2) state = "applied";
          return etagged(current(), '"9"');
        },
        [`DELETE ${base}/users/${END_USER}`]: () => {
          state = "pending";
          return json(202, current(), { Location: `/api/v1/tenants/${TENANT_A}/jobs/${OFFBOARD_JOB}` });
        },
        [`GET ${base}/jobs/${OFFBOARD_JOB}`]: () => json(200, job(OFFBOARD_JOB, "member.offboard", state === "applied" ? "succeeded" : "running")),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/users/${END_USER}` });
    await screen.findByRole("heading", { name: "Người 4", level: 1 });
    await userEvent.click(screen.getByRole("button", { name: "Offboard…" }));
    const confirm = within(dialog()).getByRole("button", { name: "Offboard" });
    expect(confirm).toBeDisabled();
    await userEvent.type(within(dialog()).getByLabelText("Gõ lại email (hoặc tên) của thành viên để xác nhận"), "u4@example.test");
    expect(confirm).toBeEnabled();
    await userEvent.click(confirm);
    const panel = await screen.findByTestId("offboard-panel");
    expect(panel).toHaveAttribute("data-state", "pending");
    expect(panel).toHaveTextContent("CHƯA chắc đã hết hạn");
    expect(panel).not.toHaveTextContent("Đã áp dụng và xác minh");
    await waitFor(() => expect(screen.getByTestId("offboard-panel")).toHaveAttribute("data-state", "applied"), { timeout: 8000 });
    expect(screen.getByTestId("offboard-panel")).toHaveTextContent("Đã áp dụng và xác minh");
    await waitFor(() => expect(screen.getByTestId("offboard-job-status")).toHaveAttribute("data-status", "succeeded"), { timeout: 8000 });
    expect(screen.queryByRole("button", { name: "Khóa" })).toBeNull();
    expect(writes(requests).filter((r) => r.method === "DELETE")).toHaveLength(1);
  }, 15_000);

  it("offboard lỗi ⇒ nút offboard lại (DELETE tạo job mới); 409 của server hiện", async () => {
    const failed = { ...MEMBERS.endUser, status: "offboarded", offboarding: { state: "failed" as const, job_id: OFFBOARD_JOB } };
    const { requests } = mockApi(
      routes("tenant_owner", {
        [`GET ${base}/users/${END_USER}`]: etagged(failed, '"9"'),
        [`GET ${base}/jobs/${OFFBOARD_JOB}`]: json(200, { ...job(OFFBOARD_JOB, "member.offboard", "failed"), error: { code: "instance_unavailable" } }),
        [`DELETE ${base}/users/${END_USER}`]: problem(409, "conflict"),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/users/${END_USER}` });
    expect(await screen.findByTestId("offboard-panel")).toHaveAttribute("data-state", "failed");
    expect(await screen.findByText("Mã lỗi: instance_unavailable")).toBeInTheDocument(); // mã lỗi là chi tiết kỹ thuật nhỏ (G4b-E11)
    await userEvent.click(screen.getByRole("button", { name: "Offboard lại…" }));
    await userEvent.type(within(dialog()).getByLabelText("Gõ lại email (hoặc tên) của thành viên để xác nhận"), "u4@example.test");
    await userEvent.click(within(dialog()).getByRole("button", { name: "Offboard" }));
    expect(await within(dialog()).findByRole("alert")).toHaveTextContent("Xung đột");
    expect(writes(requests)).toHaveLength(1);
  });

  it("chuyển quyền sở hữu (Owner): gõ lại email, mặc định previous_owner_role = tenant_admin; chọn giữ ⇒ tenant_owner; phiên được đọc lại", async () => {
    const { requests } = mockApi(
      routes("tenant_owner", {
        [`GET ${base}/users/${OPERATOR}`]: etagged(MEMBERS.operator, '"3"'),
        [`POST ${base}/ownership-transfer`]: json(200, { ...MEMBERS.operator, role: "tenant_owner" }),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/users/${OPERATOR}` });
    await screen.findByRole("heading", { name: "Người 3", level: 1 });
    await userEvent.click(screen.getByRole("button", { name: "Chuyển quyền sở hữu…" }));
    await userEvent.type(within(dialog()).getByLabelText("Gõ lại email (hoặc tên) của người nhận để xác nhận"), "u3@example.test");
    await userEvent.click(within(dialog()).getByLabelText("Tôi vẫn giữ role Owner (tenant có hai Owner)"));
    await userEvent.click(within(dialog()).getByRole("button", { name: "Chuyển quyền" }));
    await waitFor(() => expect(writes(requests)).toHaveLength(1));
    expect(await writes(requests)[0]!.json()).toEqual({ membership_id: OPERATOR, previous_owner_role: "tenant_owner" });
    await waitFor(() => expect(requests.filter((r) => r.url.endsWith("/auth/session")).length).toBeGreaterThan(1));
  });

  it("tenant tạm ngưng ⇒ mọi nút ghi bị khóa; id không phải UUID ⇒ 404 không gọi API; 404 thống nhất", async () => {
    const { requests } = mockApi(
      routes("tenant_owner", { [`GET ${base}/users/${END_USER}`]: etagged(MEMBERS.endUser, '"3"'), [`GET ${base}/users/${OFFBOARDED}`]: problem(404, "not_found") }, "suspended"),
    );
    const { router } = renderApp({ path: `/t/${TENANT_A}/users/${END_USER}` });
    await screen.findByRole("heading", { name: "Người 4", level: 1 });
    await waitFor(() => expect(screen.getByRole("button", { name: "Khóa" })).toBeDisabled());
    expect(screen.getByRole("button", { name: "Offboard…" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Đổi role" })).toBeDisabled();
    await router.navigate(`/t/${TENANT_A}/users/khong-phai-uuid`);
    await screen.findByRole("heading", { name: "Không tìm thấy", level: 1 });
    expect(requests.some((r) => r.url.includes("khong-phai-uuid"))).toBe(false);
    await router.navigate(`/t/${TENANT_A}/users/${OFFBOARDED}`);
    await screen.findByRole("heading", { name: "Không tìm thấy", level: 1 });
  });
});

describe("Invitations", () => {
  it("mời: Tenant Admin không được chọn tenant_admin; POST đúng body + Idempotency-Key + CSRF; lỗi mạng gửi lại cùng khóa ⇒ trang Lời mời theo dõi job IdP", async () => {
    let posts = 0;
    let jobPolls = 0;
    const created = invitation(INV_1, "tenant_viewer", { email: "new@example.test" });
    const { requests } = mockApi(
      routes("tenant_admin", {
        [`GET ${base}/users`]: list([MEMBERS.me("tenant_admin")]),
        [`POST ${base}/invitations`]: () => (++posts === 1 ? Promise.reject(new TypeError("network")) : json(201, created)),
        [`GET ${base}/invitations`]: list([created]),
        [`GET ${base}/jobs`]: () => list(++jobPolls < 2 ? [] : [job(INVITE_JOB, "member.idp_invite", jobPolls < 3 ? "running" : "succeeded", { type: "invitation", id: INV_1 })]),
      }),
    );
    const { router } = renderApp({ path: `/t/${TENANT_A}/users` });
    await userEvent.click(await screen.findByRole("button", { name: "Mời thành viên" }));
    const d = screen.getByRole("dialog");
    expect(within(d).getAllByRole("option").map((o) => o.getAttribute("value"))).toEqual(["tenant_operator", "tenant_viewer", "end_user"]);
    await userEvent.type(within(d).getByLabelText("Email"), "khong-hop-le");
    expect(within(d).getByText("Email không hợp lệ.")).toBeInTheDocument();
    await userEvent.clear(within(d).getByLabelText("Email"));
    await userEvent.type(within(d).getByLabelText("Email"), "new@example.test");
    await userEvent.selectOptions(within(d).getByLabelText("Role"), "tenant_viewer");
    await userEvent.click(within(d).getByRole("button", { name: "Gửi lời mời" }));
    expect(await within(d).findByRole("alert")).toHaveTextContent("Không kết nối được");
    await userEvent.click(within(d).getByRole("button", { name: "Gửi lời mời" }));
    await waitFor(() => expect(router.state.location.pathname).toBe(`/t/${TENANT_A}/invitations`));
    const sent = requests.filter((r) => r.method === "POST");
    expect(sent).toHaveLength(2);
    expect(sent[0]!.headers.get("Idempotency-Key")).toMatch(/^[0-9a-f-]{36}$/);
    expect(sent[1]!.headers.get("Idempotency-Key")).toBe(sent[0]!.headers.get("Idempotency-Key"));
    expect(sent[1]!.headers.get("X-CSRF-Token")).toBe(CSRF);
    expect(await sent[1]!.json()).toEqual({ email: "new@example.test", role: "tenant_viewer", expires_in_hours: 168 });
    // G4b-E17: trang Lời mời nhận focus ở h1; G4b-E1: thông báo hai pha — lời mời đã tạo, bước IdP đang xử lý ⇒ xong
    await waitFor(() => expect(screen.getByRole("heading", { name: "Lời mời", level: 1 })).toHaveFocus());
    const banner = await screen.findByTestId("invitation-created");
    expect(banner).toHaveTextContent("Đã tạo lời mời.");
    expect(banner).not.toHaveTextContent("Đã gửi lời mời");
    await waitFor(() => expect(within(screen.getByTestId("invitation-idp")).getByText("Thành công")).toHaveAttribute("data-status", "succeeded"), { timeout: 8000 });
    expect(banner).toHaveAttribute("data-idp", "done");
    const kinds = requests.filter((r) => r.url.includes("/jobs")).map((r) => new URL(r.url).searchParams.get("kind"));
    expect(new Set(kinds)).toEqual(new Set(["member.idp_invite"]));
  }, 15_000);

  it("Owner được mời tenant_admin; 409 của server (đã có lời mời) hiện trong hộp", async () => {
    mockApi(
      routes("tenant_owner", {
        [`GET ${base}/invitations`]: list([]),
        [`GET ${base}/jobs`]: list([]),
        [`POST ${base}/invitations`]: problem(409, "conflict", { detail: "An invitation is pending." }),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/invitations` });
    await userEvent.click(await screen.findByRole("button", { name: "Mời thành viên" }));
    const d = screen.getByRole("dialog");
    expect(within(d).getAllByRole("option").map((o) => o.getAttribute("value"))).toEqual(["tenant_admin", "tenant_operator", "tenant_viewer", "end_user"]);
    await userEvent.type(within(d).getByLabelText("Email"), "x@example.test");
    await userEvent.click(within(d).getByRole("button", { name: "Gửi lời mời" }));
    expect(await within(d).findByRole("alert")).toHaveTextContent("An invitation is pending.");
  });

  it("job IdP thất bại ⇒ câu hướng dẫn đã dịch theo mã (mã thô chỉ ở tooltip), thông báo sau khi gửi lại là cảnh báo; lời mời do provision tạo (G4b-E1, E16)", async () => {
    const failed = (code: string, id: string, resource: string) => ({ ...job(id, "member.idp_invite", "failed", { type: "invitation", id: resource }), error: { code } });
    const INV_2 = INV_1.replace(/.$/, "9");
    const INV_3 = INV_1.replace(/.$/, "8");
    let resent = false;
    mockApi(
      routes("tenant_owner", {
        [`GET ${base}/invitations`]: list([
          invitation(INV_1, "end_user"),
          invitation(INV_2, "tenant_owner", { invited_by: undefined, email: "owner@example.test" }),
          invitation(INV_3, "end_user"),
        ]),
        [`GET ${base}/jobs`]: () =>
          list([
            failed("idp_email_failed", INVITE_JOB, INV_1),
            failed("idp_user_disabled", INVITE_JOB.replace(/.$/, "9"), INV_2),
            failed(resent ? "idp_email_failed" : "wat_new_code", INVITE_JOB.replace(/.$/, "8"), INV_3),
          ]),
        [`POST ${base}/invitations/${INV_3}/resend`]: () => {
          resent = true;
          return json(200, invitation(INV_3, "end_user"));
        },
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/invitations` });
    await screen.findAllByTestId("invitation-row");
    const row = (id: string) => screen.getAllByTestId("invitation-row").find((r) => r.getAttribute("data-invitation") === id)!;
    const idp = (id: string) => within(row(id)).getByTestId("invitation-idp");
    await waitFor(() => expect(idp(INV_1)).toHaveTextContent("thư thiết lập chưa gửi được — liên hệ quản trị nền tảng"));
    expect(idp(INV_1)).toHaveTextContent("Gửi lại");
    expect(idp(INV_1)).not.toHaveTextContent("idp_email_failed");
    expect(within(idp(INV_1)).getByTestId("idp-error")).toHaveAttribute("title", "idp_email_failed");
    expect(idp(INV_2)).toHaveTextContent("kích hoạt lại");
    expect(idp(INV_3)).toHaveTextContent("Bước IdP thất bại — liên hệ quản trị nền tảng.");
    expect(idp(INV_3)).not.toHaveTextContent("wat_new_code");
    // E16: lời mời Owner do provision tạo (không có người mời)
    expect(row(INV_2)).toHaveTextContent("Tạo khi provision (nền tảng)");
    // gửi lại ⇒ job vẫn thất bại ⇒ thông báo là cảnh báo, không khẳng định đã gửi thư
    await userEvent.click(within(row(INV_3)).getByRole("button", { name: "Gửi lại" }));
    await userEvent.click(within(dialog()).getByRole("button", { name: "Gửi lại" }));
    const banner = await screen.findByTestId("invitation-created");
    await waitFor(() => expect(banner).toHaveAttribute("data-idp", "failed"));
    expect(banner).toHaveAttribute("role", "alert");
    expect(banner).toHaveTextContent("Đã gửi lại lời mời");
    expect(banner).toHaveTextContent("bước IdP thất bại");
    expect(banner).toHaveTextContent("thư thiết lập chưa gửi được");
  });

  it("en: mã lỗi IdP dịch sang tiếng Anh", async () => {
    await i18n.changeLanguage("en");
    mockApi(
      routes("tenant_owner", {
        [`GET ${base}/invitations`]: list([invitation(INV_1, "end_user", { invited_by: undefined })]),
        [`GET ${base}/jobs`]: list([{ ...job(INVITE_JOB, "member.idp_invite", "failed", { type: "invitation", id: INV_1 }), error: { code: "idp_email_failed" } }]),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/invitations` });
    const cell = await screen.findByTestId("invitation-idp");
    await waitFor(() => expect(cell).toHaveTextContent("its setup e-mail could not be sent"));
    expect(screen.getByTestId("invitation-row")).toHaveTextContent("Created at provisioning (platform)");
  });

  it("gửi lại / thu hồi chỉ với lời mời role thấp hơn (3a): Tenant Admin không thấy nút trên lời mời Admin", async () => {
    const { requests } = mockApi(
      routes("tenant_admin", {
        [`GET ${base}/invitations`]: list([invitation(INV_1, "end_user"), invitation(INV_ADMIN, "tenant_admin")]),
        [`GET ${base}/jobs`]: list([]),
        [`POST ${base}/invitations/${INV_1}/resend`]: json(200, invitation(INV_1, "end_user")),
        [`DELETE ${base}/invitations/${INV_1}`]: () => new Response(null, { status: 204 }),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/invitations` });
    const rows = await screen.findAllByTestId("invitation-row");
    expect(within(rows[1]!).queryByRole("button")).toBeNull();
    await userEvent.click(within(rows[0]!).getByRole("button", { name: "Gửi lại" }));
    await userEvent.click(within(dialog()).getByRole("button", { name: "Gửi lại" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    await userEvent.click(within(screen.getAllByTestId("invitation-row")[0]!).getByRole("button", { name: "Thu hồi" }));
    await userEvent.click(within(dialog()).getByRole("button", { name: "Thu hồi" }));
    await waitFor(() => expect(writes(requests)).toHaveLength(2));
    expect(writes(requests).map((r) => `${r.method} ${new URL(r.url).pathname.replace(`/api/v1${base}`, "")}`)).toEqual([
      `POST /invitations/${INV_1}/resend`,
      `DELETE /invitations/${INV_1}`,
    ]);
    expect(await writes(requests)[0]!.json()).toEqual({ expires_in_hours: 168 });
  });
});

describe("Groups", () => {
  it("danh sách (sensitive, nguồn, số thành viên) + tạo: tên kiểm theo pattern, Idempotency-Key, 201 ⇒ chi tiết", async () => {
    const created = group({ id: GROUP_1, name: "ops-team", member_count: 0, members: [], description: undefined });
    const { requests } = mockApi(
      routes("tenant_admin", {
        [`GET ${base}/groups`]: list([group({ sensitive: true })]),
        [`POST ${base}/groups`]: json(201, created, { ETag: '"1"' }),
        [`GET ${base}/groups/${GROUP_1}`]: etagged(created, '"1"'),
      }),
    );
    const { router } = renderApp({ path: `/t/${TENANT_A}/groups` });
    const row = await screen.findByTestId("group-row");
    expect(row).toHaveTextContent("engineering");
    expect(within(row).getByTestId("sensitive-badge")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Tạo group" }));
    const d = screen.getByRole("dialog");
    const name = within(d).getByLabelText("Tên");
    await userEvent.type(name, "9bad");
    expect(name).toHaveAttribute("aria-invalid", "true");
    expect(within(d).getByRole("button", { name: "Tạo" })).toBeDisabled();
    await userEvent.clear(name);
    await userEvent.type(name, "Ops-Team");
    expect(name).toHaveValue("ops-team");
    await userEvent.click(within(d).getByRole("button", { name: "Tạo" }));
    await waitFor(() => expect(router.state.location.pathname).toBe(`/t/${TENANT_A}/groups/${GROUP_1}`));
    const post = writes(requests)[0]!;
    expect(post.headers.get("Idempotency-Key")).toMatch(/^[0-9a-f-]{36}$/);
    expect(await post.json()).toEqual({ name: "ops-team" });
    // G4b-E17: hộp đóng + route đổi ⇒ focus vào h1 của trang mới (không rơi về <body>)
    await waitFor(() => expect(screen.getByRole("heading", { name: "ops-team", level: 1 })).toHaveFocus());
  });

  it("đặt thành viên: thêm từ kết quả tìm (chỉ active), bỏ người cũ ⇒ PUT If-Match, tập đã sắp xếp ⇒ 200 cập nhật", async () => {
    const after = group({ member_count: 1, members: [{ membership_id: END_USER, display_name: "Người 4", role: "end_user", status: "active" }], version: 5 });
    const { requests } = mockApi(
      routes("tenant_admin", {
        [`GET ${base}/groups/${GROUP_1}`]: etagged(group(), '"4"'),
        [`GET ${base}/users`]: list([MEMBERS.endUser, MEMBERS.operator]),
        [`PUT ${base}/groups/${GROUP_1}/members`]: etagged(after, '"5"'),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/groups/${GROUP_1}` });
    await screen.findByRole("heading", { name: "engineering", level: 1 });
    await userEvent.click(screen.getByRole("button", { name: "Sửa thành viên" }));
    expect(screen.getByRole("button", { name: "Lưu thành viên" })).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Tìm thành viên để thêm"), "Người");
    await userEvent.click(within(screen.getByRole("search", { name: "Tìm thành viên" })).getByRole("button", { name: "Lọc" }));
    await waitFor(() => expect(requests.some((r) => r.url.includes("/users") && new URL(r.url).searchParams.get("q") === "Người")).toBe(true));
    await userEvent.click(await screen.findByRole("button", { name: "Thêm Người 4" }));
    expect(screen.getByRole("button", { name: "Thêm Người 3" })).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Bỏ Người 3" }));
    await userEvent.click(screen.getByRole("button", { name: "Lưu thành viên" }));
    await waitFor(() => expect(screen.getByTestId("group-member-count")).toHaveTextContent("1"));
    const put = writes(requests)[0]!;
    expect(put.headers.get("If-Match")).toBe('"4"');
    expect(await put.json()).toEqual({ membership_ids: [END_USER] });
    const search = new URL(requests.find((r) => r.url.includes("/users"))!.url).searchParams;
    expect(search.get("status")).toBe("active");
    expect(screen.queryByTestId("members-editor")).toBeNull();
  });

  it("group sensitive: PUT ⇒ 202 + Location phê duyệt ⇒ thành viên CHƯA đổi, poll yêu cầu ⇒ executed ⇒ đọc lại group", async () => {
    let decided = false;
    let gets = 0;
    const sensitive = group({ sensitive: true });
    const { requests } = mockApi(
      routes("tenant_admin", {
        [`GET ${base}/groups/${GROUP_1}`]: () => {
          gets++;
          return decided ? etagged({ ...sensitive, member_count: 2, version: 6 }, '"6"') : etagged(sensitive, '"4"');
        },
        [`GET ${base}/users`]: list([MEMBERS.endUser]),
        [`GET ${base}/approvals`]: () => list(decided ? [] : [approval(), approval({ id: "0190d400-0000-7000-8000-000000000009", resource_id: "0190d200-0000-7000-8000-000000000999" })]),
        [`PUT ${base}/groups/${GROUP_1}/members`]: json(202, approval(), { Location: `/api/v1/tenants/${TENANT_A}/approvals/${APPROVAL_1}` }),
        [`GET ${base}/approvals/${APPROVAL_1}`]: () => {
          const a = approval({ status: decided ? "executed" : "pending" });
          decided = true;
          return json(200, a);
        },
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/groups/${GROUP_1}` });
    await screen.findByRole("heading", { name: "engineering", level: 1 });
    expect(screen.getByText(/Group nhạy cảm: đổi thành viên cần/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Sửa thành viên" }));
    expect(screen.getByTestId("sensitive-note")).toHaveTextContent("KHÔNG đổi ngay");
    await userEvent.click(await screen.findByRole("button", { name: "Thêm Người 4" }));
    await userEvent.click(screen.getByRole("button", { name: "Gửi yêu cầu phê duyệt" }));
    const panel = await screen.findByTestId("approval-panel");
    expect(screen.getByTestId("approval-id")).toHaveTextContent(APPROVAL_1);
    expect(panel).toHaveTextContent("thành viên CHƯA đổi");
    expect(panel).toHaveTextContent("2 thành viên");
    expect(screen.getByTestId("group-member-count")).toHaveTextContent("1");
    await waitFor(() => expect(screen.getByTestId("approval-panel")).toHaveAttribute("data-status", "executed"), { timeout: 8000 });
    await waitFor(() => expect(screen.getByTestId("group-member-count")).toHaveTextContent("2"));
    expect(gets).toBeGreaterThanOrEqual(2);
    expect(writes(requests)).toHaveLength(1);
  }, 15_000);

  it("yêu cầu đang chờ của group hiện (chỉ của đúng group); 412 khi lưu ⇒ đọc lại + gợi ý lưu lại", async () => {
    let gets = 0;
    mockApi(
      routes("tenant_owner", {
        [`GET ${base}/groups/${GROUP_1}`]: () => etagged(group(), `"${String(4 + gets++)}"`),
        [`GET ${base}/users`]: list([MEMBERS.endUser]),
        [`GET ${base}/approvals`]: list([approval(), approval({ id: "0190d400-0000-7000-8000-000000000009", resource_id: "0190d200-0000-7000-8000-000000000999" })]),
        [`PUT ${base}/groups/${GROUP_1}/members`]: problem(412, "precondition_failed"),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/groups/${GROUP_1}` });
    const pending = await screen.findByTestId("group-pending-approvals");
    expect(within(pending).getAllByRole("listitem")).toHaveLength(1);
    expect(pending).toHaveTextContent(APPROVAL_1);
    await userEvent.click(screen.getByRole("button", { name: "Sửa thành viên" }));
    await userEvent.click(await screen.findByRole("button", { name: "Thêm Người 4" }));
    await userEvent.click(screen.getByRole("button", { name: "Lưu thành viên" }));
    expect(await screen.findByText(/vừa bị người khác đổi/)).toBeInTheDocument();
    await waitFor(() => expect(gets).toBe(2));
  });

  it("sửa tên ⇒ PATCH chỉ trường đổi + If-Match; xóa: gõ lại tên, If-Match; 409 (sensitive còn thành viên) hiện", async () => {
    let deletes = 0;
    const { requests } = mockApi(
      routes("tenant_admin", {
        [`GET ${base}/groups/${GROUP_1}`]: etagged(group(), '"4"'),
        [`GET ${base}/groups`]: list([]),
        [`PATCH ${base}/groups/${GROUP_1}`]: etagged(group({ name: "eng", version: 5 }), '"5"'),
        [`DELETE ${base}/groups/${GROUP_1}`]: () => (++deletes === 1 ? problem(409, "conflict", { detail: "A sensitive group with members cannot be deleted." }) : new Response(null, { status: 204 })),
      }),
    );
    const { router } = renderApp({ path: `/t/${TENANT_A}/groups/${GROUP_1}` });
    await screen.findByRole("heading", { name: "engineering", level: 1 });
    const editName = within(screen.getByRole("region", { name: "Sửa group" })).getByLabelText("Tên");
    await userEvent.clear(editName);
    await userEvent.type(editName, "eng");
    await userEvent.click(screen.getByRole("button", { name: "Lưu" }));
    await screen.findByRole("heading", { name: "eng", level: 1 });
    expect(await writes(requests)[0]!.json()).toEqual({ name: "eng" });
    expect(writes(requests)[0]!.headers.get("If-Match")).toBe('"4"');
    await userEvent.click(screen.getByRole("button", { name: "Xóa group" }));
    const confirm = within(dialog()).getByRole("button", { name: "Xóa group" });
    expect(confirm).toBeDisabled();
    await userEvent.type(within(dialog()).getByLabelText("Gõ lại tên group để xác nhận"), "eng");
    await userEvent.click(confirm);
    expect(await within(dialog()).findByRole("alert")).toHaveTextContent("A sensitive group with members cannot be deleted.");
    await userEvent.click(within(dialog()).getByRole("button", { name: "Xóa group" }));
    await waitFor(() => expect(router.state.location.pathname).toBe(`/t/${TENANT_A}/groups`));
    expect(writes(requests).filter((r) => r.method === "DELETE").map((r) => r.headers.get("If-Match"))).toEqual(['"5"', '"5"']);
  });

  it("Tenant Viewer: đọc được, không có nút ghi; query key bắt đầu bằng tenantId", async () => {
    mockApi(routes("tenant_viewer", { [`GET ${base}/groups/${GROUP_1}`]: etagged(group(), '"4"') }));
    const { queryClient } = renderApp({ path: `/t/${TENANT_A}/groups/${GROUP_1}` });
    await screen.findByRole("heading", { name: "engineering", level: 1 });
    for (const name of ["Sửa thành viên", "Xóa group", "Lưu"]) expect(screen.queryByRole("button", { name })).toBeNull();
    const keys = queryClient.getQueryCache().getAll().map((q) => q.queryKey[0]);
    expect(keys.every((k) => k === "_global" || k === TENANT_A)).toBe(true);
    expect(queryClient.getQueryData(queryKeys.tenant(TENANT_A, "people", "group", GROUP_1))).toBeTruthy();
  });
});
