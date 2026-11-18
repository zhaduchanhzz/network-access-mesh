// E2E chức năng của Platform Console (P4-T02) trên stack dev/CI THẬT — chỉ chạy khi tests/e2e/harness/platformui.py
// đặt MG_LIVE_SA1/MG_LIVE_SA2 (mặc định bỏ qua). App, router, QueryClient, client openapi-fetch đều thật; fetch của SPA
// (cùng origin /api/v1) được chuyển nguyên văn tới proxy cục bộ của harness — mỗi proxy giữ phiên (cookie HttpOnly) của
// một Super Admin đã đăng nhập Keycloak + TOTP qua edge, như trình duyệt của người đó. Kết quả: FUNCTIONAL (§22.1).
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { renderApp } from "../test/helpers";

const SA1 = process.env.MG_LIVE_SA1 ?? "";
const SA2 = process.env.MG_LIVE_SA2 ?? "";
const TENANT_A = process.env.MG_LIVE_TENANT_A ?? "";
const OUT = process.env.MG_LIVE_OUT ?? "";
const SLUG = `ui-${(process.env.MG_LIVE_RUN ?? "000000").slice(0, 6)}`;
const LONG = 240_000;
const realFetch = globalThis.fetch.bind(globalThis);

const facts: Record<string, unknown> = { slug: SLUG };
function record(k: string, v: unknown) {
  facts[k] = v;
  if (OUT) writeFileSync(OUT, JSON.stringify(facts, null, 2));
}

/** Mọi fetch của SPA ⇒ proxy của một Super Admin (giữ path + query, method, header, body). */
function as(proxy: string) {
  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = input instanceof Request ? input : new Request(input, init);
    const u = new URL(req.url);
    expect(u.pathname.startsWith("/api/v1/")).toBe(true);
    const body = req.method === "GET" || req.method === "HEAD" ? undefined : await req.text();
    return realFetch(`${proxy}${u.pathname}${u.search}`, { method: req.method, headers: req.headers, body: body || undefined });
  });
}

const pathOf = (router: ReturnType<typeof renderApp>["router"]) => router.state.location.pathname;

describe.skipIf(!SA1 || !SA2 || !TENANT_A)("Platform Console trên stack thật", () => {
  it(
    "UI-01 danh sách tenant (registry thật) → wizard tạo tenant → job tenant.provision: 19 bước, 2 bước của API xong",
    async () => {
      as(SA1);
      const { router, unmount } = renderApp({ path: "/platform/tenants", console: "platform" });
      expect(await screen.findByRole("link", { name: "tenant-a" }, { timeout: 30_000 })).toHaveAttribute("href", `/platform/tenants/${TENANT_A}`);
      expect(screen.getByRole("link", { name: "tenant-b" })).toBeInTheDocument();
      await userEvent.click(screen.getByRole("link", { name: "Tạo tenant" }));
      await userEvent.type(await screen.findByLabelText("Slug"), SLUG);
      await userEvent.type(screen.getByLabelText("Tên hiển thị"), "UI E2E");
      await userEvent.type(screen.getByLabelText("Email Tenant Owner"), `owner@${SLUG}.example.test`);
      await userEvent.click(screen.getByRole("button", { name: "Tiếp" }));
      await screen.findByRole("heading", { name: "Identity Provider", level: 2 });
      await userEvent.click(screen.getByRole("button", { name: "Tiếp" }));
      await userEvent.click(await screen.findByRole("button", { name: "Tạo tenant" }));
      await screen.findByRole("heading", { name: "Job tenant.provision", level: 1 }, { timeout: 30_000 });
      const jobId = pathOf(router).split("/").pop();
      record("provision_job", jobId);
      const steps = within(screen.getByRole("list", { name: "Timeline của job" })).getAllByRole("listitem");
      expect(steps).toHaveLength(19);
      expect(steps.slice(0, 2).map((s) => s.getAttribute("data-step-status"))).toEqual(["succeeded", "succeeded"]);
      expect(steps.slice(2).every((s) => s.getAttribute("data-step-status") === "pending")).toBe(true);
      expect(screen.getByTestId("tenant-created")).toBeInTheDocument();
      expect(screen.getByTestId("poll-status")).toHaveTextContent("Đang tự cập nhật");
      record("provision_status_seen", document.querySelector("[data-status]")?.getAttribute("data-status"));

      // UI-02: hủy job chưa chạy (stack không có Host Agent — job nằm ở queued) ⇒ cancelled, tenant failed
      await userEvent.click(screen.getByRole("button", { name: "Hủy job" }));
      const dialog = await screen.findByRole("alertdialog", { name: "Hủy job tenant.provision?" });
      await userEvent.click(within(dialog).getByRole("button", { name: "Hủy job" }));
      await waitFor(() => {
        expect(screen.getByTestId("poll-status")).toHaveTextContent("trạng thái cuối");
      }, { timeout: 30_000 });
      expect(screen.getAllByText("Đã hủy")[0]).toHaveAttribute("data-status", "cancelled");
      await userEvent.click(screen.getByRole("link", { name: "Mở chi tiết tenant" }));
      await screen.findByRole("heading", { name: "UI E2E", level: 1 }, { timeout: 30_000 });
      const tenantId = pathOf(router).split("/").pop();
      record("tenant_id", tenantId);
      expect(await screen.findByText("Lỗi", { selector: "[data-status=failed]" }, { timeout: 30_000 })).toBeInTheDocument();
      expect(await screen.findByText("Tenant chưa có instance.")).toBeInTheDocument();
      expect(await screen.findByRole("link", { name: "tenant.provision" })).toHaveAttribute("href", `/platform/jobs/${String(jobId)}`);

      // UI-03: xin xóa (2P) — gõ lại slug + lý do ⇒ yêu cầu phê duyệt; người yêu cầu không có nút duyệt
      await userEvent.click(screen.getByRole("button", { name: "Xóa tenant…" }));
      const del = await screen.findByRole("alertdialog", { name: `Xin xóa tenant ${SLUG}` });
      await userEvent.type(within(del).getByLabelText("Gõ lại slug của tenant để xác nhận"), SLUG);
      await userEvent.type(within(del).getByLabelText("Lý do (ticket, yêu cầu của khách hàng)"), "P4-T02 UI E2E");
      await userEvent.click(within(del).getByRole("button", { name: "Gửi yêu cầu xóa" }));
      await screen.findByTestId("approval-requested", {}, { timeout: 30_000 });
      record("approval_id", pathOf(router).split("/").pop());
      expect(await screen.findByTestId("self-request")).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Duyệt" })).toBeNull();
      await waitFor(() => {
        expect(screen.getByTestId("hash-check")).toHaveTextContent("Hash khớp");
      });
      unmount();
    },
    LONG,
  );

  it(
    "UI-04 người thứ hai: hàng chờ 2P → payload + hash khớp → duyệt (gõ lại slug) ⇒ executed + job",
    async () => {
      as(SA2);
      const { unmount } = renderApp({ path: "/platform/approvals", console: "platform" });
      const id = String(facts.approval_id);
      const link = await screen.findByRole("link", { name: /Xóa tenant/ }, { timeout: 30_000 });
      expect(link).toHaveAttribute("href", `/platform/approvals/${id}`);
      await userEvent.click(link);
      await waitFor(() => {
        expect(screen.getByTestId("hash-check")).toHaveTextContent("Hash khớp");
      }, { timeout: 30_000 });
      expect(screen.getByTestId("local-hash").textContent).toBe(screen.getByTestId("server-hash").textContent);
      record("payload_sha256", screen.getByTestId("server-hash").textContent);
      await userEvent.click(screen.getByRole("button", { name: "Duyệt" }));
      const dialog = await screen.findByRole("alertdialog", { name: "Duyệt yêu cầu này?" });
      await userEvent.type(within(dialog).getByLabelText("Gõ lại slug của tenant sẽ bị xóa"), SLUG);
      await userEvent.click(within(dialog).getByRole("button", { name: "Duyệt" }));
      expect(await screen.findByText(/Yêu cầu ở trạng thái Đã thực thi/, {}, { timeout: 30_000 })).toBeInTheDocument();
      const job = screen.getByRole("link", { name: /^[0-9a-f-]{36}$/ });
      record("deprovision_job", job.textContent);
      await userEvent.click(job);
      await screen.findByRole("heading", { name: "Job tenant.deprovision", level: 1 }, { timeout: 30_000 });
      record("deprovision_status_seen", document.querySelector("[data-status]")?.getAttribute("data-status"));
      unmount();
    },
    LONG,
  );

  it(
    "UI-05 tenant-a: chi tiết (instance, relay, job) → tạm ngưng → job tenant.suspend chạy xong (poll) → khôi phục",
    async () => {
      as(SA1);
      const { router, unmount } = renderApp({ path: `/platform/tenants/${TENANT_A}`, console: "platform" });
      const inst = await screen.findByTestId("instance", {}, { timeout: 30_000 });
      expect(within(inst).getByText("Đang chạy")).toHaveAttribute("data-status", "running");
      await screen.findByRole("heading", { name: "Relay", level: 2 });
      await userEvent.click(await screen.findByRole("button", { name: "Tạm ngưng" }));
      const dialog = await screen.findByRole("alertdialog", { name: "Tạm ngưng tenant tenant-a?" });
      await userEvent.click(within(dialog).getByRole("button", { name: "Tạm ngưng" }));
      await screen.findByRole("heading", { name: "Job tenant.suspend", level: 1 }, { timeout: 30_000 });
      record("suspend_job", pathOf(router).split("/").pop());
      await waitFor(() => {
        expect(screen.getByTestId("poll-status")).toHaveTextContent("trạng thái cuối");
      }, { timeout: 180_000 });
      const status = document.querySelector("[data-status]")?.getAttribute("data-status");
      record("suspend_status", status);
      expect(status).toBe("succeeded");
      await userEvent.click(screen.getByRole("link", { name: TENANT_A }));
      expect(await screen.findByRole("button", { name: "Khôi phục" }, { timeout: 30_000 })).toBeInTheDocument();
      expect(screen.getByText("Tạm ngưng", { selector: "[data-status=suspended]" })).toBeInTheDocument();
      await userEvent.click(screen.getByRole("button", { name: "Khôi phục" }));
      const resume = await screen.findByRole("alertdialog", { name: "Khôi phục tenant tenant-a?" });
      await userEvent.click(within(resume).getByRole("button", { name: "Khôi phục" }));
      await screen.findByRole("heading", { name: "Job tenant.resume", level: 1 }, { timeout: 30_000 });
      record("resume_job", pathOf(router).split("/").pop());
      await waitFor(() => {
        expect(screen.getByTestId("poll-status")).toHaveTextContent("trạng thái cuối");
      }, { timeout: 180_000 });
      record("resume_status", document.querySelector("[data-status]")?.getAttribute("data-status"));
      expect(document.querySelector("[data-status]")?.getAttribute("data-status")).toBe("succeeded");
      unmount();
    },
    LONG * 2,
  );
});
