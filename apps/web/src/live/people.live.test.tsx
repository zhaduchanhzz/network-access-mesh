// E2E chức năng của Users / Groups / Invitations (P4-T09a) trên stack dev/CI THẬT — chỉ chạy khi
// tests/e2e/harness/peopleui.py đặt MG_LIVE_OWNER/MG_LIVE_ADMIN (mặc định bỏ qua). App, router, QueryClient, client
// openapi-fetch đều thật; fetch của SPA (cùng origin /api/v1) được chuyển nguyên văn tới proxy cục bộ của harness — mỗi
// proxy giữ phiên (cookie HttpOnly) của một người đã đăng nhập Keycloak + TOTP qua edge trên app.<domain>.
// Harness đọc MG_LIVE_OUT trong lúc ca chạy và làm phần "người khác": khi thấy `invitation_id` ⇒ người được mời đăng nhập
// lần đầu; khi thấy `approval_id` ⇒ Owner (step-up) duyệt. Kết quả: FUNCTIONAL (§22.1).
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { api, callWithResponse } from "../api/client";
import { callWithETag, ifMatch } from "../api/etag";
import { ApiError } from "../api/problem";
import { renderApp } from "../test/helpers";

const OWNER = process.env.MG_LIVE_OWNER ?? "";
const ADMIN = process.env.MG_LIVE_ADMIN ?? "";
const T = process.env.MG_LIVE_TENANT_A ?? "";
const INVITEE = process.env.MG_LIVE_INVITEE_EMAIL ?? "";
const ADMIN2 = process.env.MG_LIVE_ADMIN2 ?? "";
const OWNER_MID = process.env.MG_LIVE_OWNER_MID ?? "";
const SENSITIVE = process.env.MG_LIVE_SENSITIVE_GROUP ?? "";
const MEMBER_NAME = process.env.MG_LIVE_MEMBER_NAME ?? "";
const OUT = process.env.MG_LIVE_OUT ?? "";
const RUN = (process.env.MG_LIVE_RUN ?? "000000").slice(0, 6);
const LONG = 300_000;
const realFetch = globalThis.fetch.bind(globalThis);

const facts: Record<string, unknown> = { run: RUN };
function record(k: string, v: unknown) {
  facts[k] = v;
  if (OUT) writeFileSync(OUT, JSON.stringify(facts, null, 2));
}

/** Mọi fetch của SPA ⇒ proxy của một người (giữ path + query, method, header, body). */
function as(proxy: string) {
  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = input instanceof Request ? input : new Request(input, init);
    const u = new URL(req.url);
    expect(u.pathname.startsWith("/api/v1/")).toBe(true);
    const body = req.method === "GET" || req.method === "HEAD" ? undefined : await req.text();
    return realFetch(`${proxy}${u.pathname}${u.search}`, { method: req.method, headers: req.headers, body: body || undefined });
  });
}

const dialog = () => screen.getByRole("alertdialog");
function until<T>(fn: () => T, timeout = 30_000): Promise<T> {
  return waitFor(fn, { timeout, interval: 500 });
}

describe.skipIf(!OWNER || !ADMIN || !T)("Users / Groups / Invitations trên stack thật", () => {
  it(
    "UI-11 Owner: mời (job member.idp_invite) → người được mời đăng nhập → đổi role (role, admin-role) → offboard tới applied",
    async () => {
      as(OWNER);
      const { router, queryClient, unmount } = renderApp({ path: `/t/${T}/users` });
      await userEvent.click(await screen.findByRole("button", { name: "Mời thành viên" }, { timeout: 30_000 }));
      const d = screen.getByRole("dialog");
      await userEvent.type(within(d).getByLabelText("Email"), INVITEE);
      await userEvent.selectOptions(within(d).getByLabelText("Role"), "end_user");
      await userEvent.click(within(d).getByRole("button", { name: "Gửi lời mời" }));
      await until(() => expect(router.state.location.pathname).toBe(`/t/${T}/invitations`));
      const row = await until(() => {
        const r = screen.getAllByTestId("invitation-row").find((x) => x.textContent.includes(INVITEE));
        expect(r).toBeTruthy();
        return r!;
      });
      record("invitation_id", row.getAttribute("data-invitation"));
      await until(() => {
        const cell = screen.getAllByTestId("invitation-row").find((x) => x.textContent.includes(INVITEE))!;
        expect(within(cell).getByTestId("invitation-idp").querySelector("[data-status]")?.getAttribute("data-status")).toBe("succeeded");
      }, 120_000);
      record("idp_job_seen", "succeeded");

      // harness: người được mời đăng nhập lần đầu ⇒ membership xuất hiện
      await router.navigate(`/t/${T}/users?q=${encodeURIComponent(INVITEE)}`);
      const link = await until(() => {
        void queryClient.invalidateQueries();
        const r = screen.getAllByTestId("user-row")[0];
        expect(r?.textContent).toContain(INVITEE);
        return within(r!).getByRole("link");
      }, 180_000);
      await userEvent.click(link);
      const mid = await until(() => {
        const id = router.state.location.pathname.split("/").pop() ?? "";
        expect(id).toMatch(/^[0-9a-f-]{36}$/);
        return id;
      });
      record("membership_id", mid);
      await until(() => expect(screen.getByTestId("user-role")).toHaveTextContent("End User"));

      await userEvent.selectOptions(screen.getByLabelText("Role mới"), "tenant_viewer");
      await userEvent.click(screen.getByRole("button", { name: "Đổi role" }));
      await userEvent.click(within(dialog()).getByRole("button", { name: "Đổi role" }));
      await until(() => expect(screen.getByTestId("user-role")).toHaveTextContent("Tenant Viewer"));
      record("role_after_role", "tenant_viewer");
      await userEvent.selectOptions(screen.getByLabelText("Role mới"), "tenant_admin");
      await userEvent.click(screen.getByRole("button", { name: "Đổi role" }));
      await userEvent.click(within(dialog()).getByRole("button", { name: "Đổi role" }));
      await until(() => expect(screen.getByTestId("user-role")).toHaveTextContent("Tenant Admin"));
      record("role_after_admin_role", "tenant_admin");

      await userEvent.click(screen.getByRole("button", { name: "Offboard…" }));
      await userEvent.type(within(dialog()).getByLabelText("Gõ lại email (hoặc tên) của thành viên để xác nhận"), INVITEE);
      await userEvent.click(within(dialog()).getByRole("button", { name: "Offboard" }));
      const panel = await screen.findByTestId("offboard-panel", {}, { timeout: 30_000 });
      record("offboard_first_state", panel.getAttribute("data-state"));
      await until(() => expect(screen.getByTestId("offboard-panel")).toHaveAttribute("data-state", "applied"), 180_000);
      record("offboard_state", "applied");
      await until(() => expect(screen.getByTestId("offboard-job-status")).toHaveAttribute("data-status", "succeeded"));
      record("offboard_job_seen", "succeeded");
      expect(screen.queryByRole("button", { name: "Khóa" })).toBeNull();
      unmount();
    },
    LONG,
  );

  it(
    "UI-12 Tenant Admin: Admin khác / Owner không có thao tác (server 403); tạo group + đặt thành viên; group sensitive ⇒ 202 phê duyệt ⇒ executed",
    async () => {
      as(ADMIN);
      const { router, unmount } = renderApp({ path: `/t/${T}/users/${ADMIN2}` });
      await screen.findByTestId("no-actions", {}, { timeout: 30_000 });
      const hidden = ["Khóa", "Thu hồi session", "Đổi role", "Offboard…"].every((name) => screen.queryByRole("button", { name }) === null);
      await router.navigate(`/t/${T}/users/${OWNER_MID}`);
      await until(() => expect(screen.getByTestId("no-actions")).toBeInTheDocument());
      const hiddenOwner = ["Khóa", "Offboard…", "Chuyển quyền sở hữu…"].every((name) => screen.queryByRole("button", { name }) === null);
      record("admin_ui_hidden", hidden && hiddenOwner);
      // UI ẩn chỉ là UX: gửi thẳng lệnh khóa Admin khác qua client của SPA ⇒ server từ chối
      const cur = await callWithETag(api.GET("/tenants/{tenantId}/users/{membershipId}", { params: { path: { tenantId: T, membershipId: ADMIN2 } } }));
      let refused: unknown = null;
      try {
        await callWithResponse(
          api.PATCH("/tenants/{tenantId}/users/{membershipId}", {
            params: { path: { tenantId: T, membershipId: ADMIN2 }, header: ifMatch(cur.etag) },
            body: { status: "locked" },
          }),
          { notify: false },
        );
      } catch (e) {
        refused = e;
      }
      record("direct_lock_admin", refused instanceof ApiError ? `${refused.status} ${refused.code}` : String(refused));

      // group thường: tạo + thêm một thành viên ⇒ 200
      await router.navigate(`/t/${T}/groups`);
      await userEvent.click(await screen.findByRole("button", { name: "Tạo group" }, { timeout: 30_000 }));
      await userEvent.type(within(screen.getByRole("dialog")).getByLabelText("Tên"), `ui-${RUN}`);
      await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Tạo" }));
      await screen.findByRole("heading", { name: `ui-${RUN}`, level: 1 }, { timeout: 30_000 });
      record("group_id", router.state.location.pathname.split("/").pop());
      await addMember();
      await userEvent.click(screen.getByRole("button", { name: "Lưu thành viên" }));
      await until(() => expect(screen.getByTestId("group-member-count")).toHaveTextContent("1"));
      record("group_members", 1);

      // group sensitive ⇒ 202 + phê duyệt; harness (Owner, step-up) duyệt ⇒ executed ⇒ group đọc lại
      await router.navigate(`/t/${T}/groups/${SENSITIVE}`);
      await screen.findByTestId("sensitive-badge", {}, { timeout: 30_000 });
      const before = screen.getByTestId("group-member-count").textContent;
      await addMember();
      await userEvent.click(screen.getByRole("button", { name: "Gửi yêu cầu phê duyệt" }));
      const panel = await screen.findByTestId("approval-panel", {}, { timeout: 30_000 });
      record("approval_first_status", panel.getAttribute("data-status"));
      record("members_before_approval", `${before}/${screen.getByTestId("group-member-count").textContent}`);
      record("approval_id", screen.getByTestId("approval-id").textContent);
      await until(() => expect(screen.getByTestId("approval-panel")).toHaveAttribute("data-status", "executed"), 180_000);
      await until(() => expect(screen.getByTestId("group-member-count")).toHaveTextContent("1"));
      record("approval_status", "executed");
      unmount();
    },
    LONG,
  );
});

async function addMember() {
  await userEvent.click(await screen.findByRole("button", { name: "Sửa thành viên" }, { timeout: 30_000 }));
  await userEvent.type(screen.getByLabelText("Tìm thành viên để thêm"), MEMBER_NAME);
  await userEvent.click(within(screen.getByTestId("members-editor")).getByRole("button", { name: "Lọc" }));
  await userEvent.click(await screen.findByRole("button", { name: `Thêm ${MEMBER_NAME}` }, { timeout: 30_000 }));
}
