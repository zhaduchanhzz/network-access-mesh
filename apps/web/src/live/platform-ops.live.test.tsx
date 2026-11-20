// E2E chức năng của các màn hình P4-T03 trên stack dev/CI THẬT — chỉ chạy khi tests/e2e/harness/platformui.py đặt
// MG_LIVE_SA1/MG_LIVE_SA2 và MG_LIVE_TARGET_SUB (mặc định bỏ qua). App thật trong Vitest + jsdom; fetch của SPA chuyển
// nguyên văn tới proxy của harness — mỗi proxy giữ phiên (cookie HttpOnly) của một Super Admin đã đăng nhập Keycloak +
// TOTP qua edge (cùng cách với platform.live.test.tsx của P4-T02). Kết quả: FUNCTIONAL (§22.1).
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { renderApp } from "../test/helpers";

const SA1 = process.env.MG_LIVE_SA1 ?? "";
const SA2 = process.env.MG_LIVE_SA2 ?? "";
const TENANT_A = process.env.MG_LIVE_TENANT_A ?? "";
const TARGET_SUB = process.env.MG_LIVE_TARGET_SUB ?? "";
const OUT = process.env.MG_LIVE_OUT ?? "";
const LONG = 240_000;
const T = { timeout: 30_000 };
const realFetch = globalThis.fetch.bind(globalThis);

const facts: Record<string, unknown> = {};
function record(k: string, v: unknown) {
  facts[k] = v;
  if (OUT) writeFileSync(OUT, JSON.stringify(facts, null, 2));
}

function as(proxy: string) {
  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = input instanceof Request ? input : new Request(input, init);
    const u = new URL(req.url);
    expect(u.pathname.startsWith("/api/v1/")).toBe(true);
    const body = req.method === "GET" || req.method === "HEAD" ? undefined : await req.text();
    return realFetch(`${proxy}${u.pathname}${u.search}`, { method: req.method, headers: req.headers, body: body || undefined });
  });
}

/** Lời gọi API trực tiếp của một Super Admin (không qua SPA) — người thứ hai sửa thiết lập trong lúc người kia đang sửa. */
async function direct(proxy: string, method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
  const s = (await (await realFetch(`${proxy}/api/v1/auth/session`)).json()) as { csrf_token: string };
  return realFetch(`${proxy}/api/v1${path}`, {
    method,
    headers: { "Content-Type": "application/json", "X-CSRF-Token": s.csrf_token, ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

const pathOf = (router: ReturnType<typeof renderApp>["router"]) => router.state.location.pathname;
const idOf = (router: ReturnType<typeof renderApp>["router"]) => pathOf(router).split("/").pop();

/** SA2: hàng chờ ⇒ mở yêu cầu theo id ⇒ hash trình duyệt = server ⇒ duyệt ⇒ executed. */
async function approveAsSA2(approvalId: string, prefix: string) {
  as(SA2);
  const { unmount } = renderApp({ path: "/platform/approvals", console: "platform" });
  await screen.findAllByRole("link", { name: new RegExp(prefix) }, T);
  expect(screen.getAllByRole("link").some((a) => a.getAttribute("href") === `/platform/approvals/${approvalId}`)).toBe(true);
  unmount();
  const view = renderApp({ path: `/platform/approvals/${approvalId}`, console: "platform" });
  await waitFor(() => {
    expect(screen.getByTestId("hash-check")).toHaveTextContent("Hash khớp");
  }, T);
  expect(screen.getByTestId("local-hash").textContent).toBe(screen.getByTestId("server-hash").textContent);
  const hash = screen.getByTestId("server-hash").textContent;
  await userEvent.click(screen.getByRole("button", { name: "Duyệt" }));
  const dialog = await screen.findByRole("alertdialog", { name: "Duyệt yêu cầu này?" });
  await userEvent.click(within(dialog).getByRole("button", { name: "Duyệt" }));
  expect(await screen.findByText(/Yêu cầu ở trạng thái Đã thực thi/, {}, T)).toBeInTheDocument();
  view.unmount();
  return hash;
}

describe.skipIf(!SA1 || !SA2 || !TENANT_A || !TARGET_SUB)("Platform Console P4-T03 trên stack thật", () => {
  it(
    "UI-06 nhân sự nền tảng: SA1 thêm user (sub thật) ⇒ xin gán Super Admin (2P) ⇒ không tự duyệt ⇒ SA2 duyệt ⇒ executed",
    async () => {
      as(SA1);
      const { router, unmount } = renderApp({ path: "/platform/users", console: "platform" });
      const mine = await screen.findAllByTestId("platform-user", {}, T);
      const me = mine.find((r) => within(r).queryByText("(bạn)"));
      expect(me).toBeDefined();
      expect(within(me!).queryByRole("button")).toBeNull();
      await userEvent.click(screen.getByRole("button", { name: "Thêm nhân sự" }));
      const create = await screen.findByRole("dialog", { name: "Thêm nhân sự nền tảng" });
      await userEvent.type(within(create).getByLabelText("Subject (sub) ở IdP platform"), TARGET_SUB);
      await userEvent.selectOptions(within(create).getByLabelText("Role"), "platform_viewer");
      await userEvent.type(within(create).getByLabelText("Tên hiển thị (tùy chọn)"), "UI Target");
      await userEvent.click(within(create).getByRole("button", { name: "Thêm nhân sự" }));
      const row = await waitFor(() => {
        const r = screen.getAllByTestId("platform-user").find((x) => x.dataset.subject === TARGET_SUB);
        expect(r).toBeDefined();
        return r!;
      }, T);
      expect(within(row).getByText("Platform Viewer")).toBeInTheDocument();
      await userEvent.click(within(row).getByRole("button", { name: "Gán Super Admin cho UI Target" }));
      const dialog = await screen.findByRole("dialog", { name: "Xin gán Super Admin cho UI Target" });
      await userEvent.type(within(dialog).getByLabelText("Lý do (người duyệt sẽ đọc)"), "P4-T03 UI E2E");
      await userEvent.click(within(dialog).getByRole("button", { name: "Gửi yêu cầu phê duyệt" }));
      await screen.findByTestId("approval-requested", {}, T);
      const approvalId = idOf(router)!;
      record("sa_approval_id", approvalId);
      expect(await screen.findByTestId("self-request")).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Duyệt" })).toBeNull();
      expect(screen.getByText("Gán/gỡ Super Admin")).toBeInTheDocument();
      unmount();

      record("sa_payload_sha256", await approveAsSA2(approvalId, "Gán/gỡ Super Admin"));
      as(SA1);
      const after = renderApp({ path: "/platform/users", console: "platform" });
      await waitFor(() => {
        const r = screen.getAllByTestId("platform-user").find((x) => x.dataset.subject === TARGET_SUB);
        expect(r && within(r).queryByText("Super Admin")).toBeTruthy();
      }, T);
      record("target_role_seen", "super_admin");
      after.unmount();
    },
    LONG,
  );

  it(
    "UI-07 thiết lập: SA1 mở sửa approval.ttl_hours ⇒ SA2 sửa trước (API) ⇒ SA1 lưu với ETag cũ ⇒ 412 hiện bản mới ⇒ dùng bản mới ⇒ 200",
    async () => {
      as(SA1);
      const { unmount } = renderApp({ path: "/platform/settings", console: "platform" });
      const row = await waitFor(() => {
        const r = screen.getAllByTestId("setting-row").find((x) => x.dataset.key === "approval.ttl_hours");
        expect(r).toBeDefined();
        return r!;
      }, T);
      await userEvent.click(within(row).getByRole("button", { name: "Sửa approval.ttl_hours" }));
      const dialog = await screen.findByRole("dialog", { name: "Sửa thiết lập approval.ttl_hours" });

      // người thứ hai sửa trong lúc hộp đang mở (API trực tiếp, đúng ETag hiện tại)
      const cur = await realFetch(`${SA2}/api/v1/platform/settings/approval.ttl_hours`);
      const etag = cur.headers.get("ETag") ?? "";
      const put2 = await direct(SA2, "PUT", "/platform/settings/approval.ttl_hours", { value: 36 }, { "If-Match": etag });
      record("sa2_put_status", put2.status);
      expect(put2.status).toBe(200);

      const input = within(dialog).getByLabelText("Giá trị (JSON)");
      await userEvent.clear(input);
      await userEvent.type(input, "48");
      await userEvent.click(within(dialog).getByRole("button", { name: "Lưu" }));
      const stale = await within(dialog).findByTestId("stale-setting", {}, T);
      expect(stale).toHaveTextContent("Dữ liệu đã bị thay đổi bởi người khác");
      await waitFor(() => {
        expect(within(stale).getByTestId("latest-value")).toHaveTextContent("36");
      }, T);
      record("stale_seen", true);
      await userEvent.click(within(stale).getByRole("button", { name: "Dùng bản mới nhất rồi sửa lại" }));
      expect(within(dialog).getByLabelText("Giá trị (JSON)")).toHaveValue("36");
      await userEvent.clear(within(dialog).getByLabelText("Giá trị (JSON)"));
      await userEvent.type(within(dialog).getByLabelText("Giá trị (JSON)"), "48");
      await userEvent.click(within(dialog).getByRole("button", { name: "Lưu" }));
      await waitFor(() => {
        expect(screen.queryByRole("dialog")).toBeNull();
      }, T);
      await waitFor(() => {
        const r = screen.getAllByTestId("setting-row").find((x) => x.dataset.key === "approval.ttl_hours")!;
        expect(within(r).getByTestId("setting-value")).toHaveTextContent("48");
      }, T);
      record("setting_final", 48);
      unmount();
    },
    LONG,
  );

  it(
    "UI-08 IdP của tenant-a: issuer chỉ đọc ⇒ sửa claim_mapping ⇒ 202 + yêu cầu 2P (chưa hiệu lực) ⇒ SA2 duyệt ⇒ có hiệu lực",
    async () => {
      as(SA1);
      const { router, unmount } = renderApp({ path: "/platform/identity-providers", console: "platform" });
      await userEvent.selectOptions(await screen.findByLabelText("Phạm vi", {}, T), "tenant");
      const row = await waitFor(() => {
        // tenant hiện theo tên (G4b-E12) — tìm hàng theo đích của link, không theo UUID
        const r = screen.getAllByTestId("idp-row").find((x) => x.querySelector(`a[href="/platform/tenants/${TENANT_A}"]`));
        expect(r).toBeDefined();
        return r!;
      }, T);
      await userEvent.click(within(row).getAllByRole("link")[0]!);
      await screen.findByTestId("idp-issuer", {}, T);
      const idpId = idOf(router)!;
      record("idp_id", idpId);
      expect(screen.queryByRole("textbox", { name: /Issuer/ })).toBeNull();
      await userEvent.click(screen.getByRole("button", { name: "Sửa ràng buộc claim…" }));
      const dialog = await screen.findByRole("dialog", { name: "Sửa ràng buộc claim" });
      expect(within(dialog).getByTestId("tenant-idp-2p")).toBeInTheDocument();
      const name = within(dialog).getByLabelText("Trường name ← claim");
      await userEvent.clear(name);
      await userEvent.type(name, "preferred_username");
      await userEvent.click(within(dialog).getByRole("button", { name: "Gửi yêu cầu thay đổi" }));
      await screen.findByTestId("approval-requested", {}, T);
      const approvalId = idOf(router)!;
      record("idp_approval_id", approvalId);
      expect(await screen.findByTestId("self-request")).toBeInTheDocument();
      unmount();
      // chưa có hiệu lực trước khi duyệt
      const before = (await (await realFetch(`${SA1}/api/v1/platform/identity-providers/${idpId}`)).json()) as { claim_mapping: Record<string, string> };
      record("idp_name_before_approval", before.claim_mapping.name ?? null);
      expect(before.claim_mapping.name).not.toBe("preferred_username");

      record("idp_payload_sha256", await approveAsSA2(approvalId, "Sửa IdP của tenant"));
      as(SA1);
      const view = renderApp({ path: `/platform/identity-providers/${idpId}`, console: "platform" });
      expect(await screen.findByText("preferred_username", {}, T)).toBeInTheDocument();
      view.unmount();
    },
    LONG,
  );

  it(
    "UI-09 instance của tenant-a: health + checked_at, version cấu hình, host (STUN), Platform Health ⇒ restart qua UI ⇒ job instance.restart ⇒ hủy",
    async () => {
      as(SA1);
      const { router, unmount } = renderApp({ path: "/platform/health", console: "platform" });
      const api = (await (await realFetch(`${SA1}/api/v1/platform/health`)).json()) as { tenants: { total: number }; instances: { total: number } };
      await waitFor(() => {
        expect(screen.getByTestId("health-tenants")).toHaveTextContent(String(api.tenants.total));
      }, T);
      expect(screen.getByTestId("health-instances")).toHaveTextContent(String(api.instances.total));
      record("health_tenants_total", api.tenants.total);

      await router.navigate("/platform/hosts");
      const hosts = await screen.findAllByTestId("host-row", {}, T);
      record("hosts_seen", hosts.length);
      record("stun_free_text", within(hosts[0]!).getByTestId("stun-free").textContent);

      const inst = (await (await realFetch(`${SA1}/api/v1/platform/tenants/${TENANT_A}/instances`)).json()) as { items: { id: string }[] };
      const instanceId = inst.items[0]?.id ?? "";
      record("instance_id", instanceId);
      await router.navigate("/platform/instances");
      const link = await waitFor(() => {
        const a = screen.getAllByRole("link").find((x) => x.getAttribute("href") === `/platform/instances/${instanceId}`);
        expect(a).toBeDefined();
        return a!;
      }, T);
      await userEvent.click(link);
      await screen.findByTestId("image-digest", {}, T);
      const config = screen.getByRole("region", { name: "Version cấu hình" });
      await waitFor(() => {
        expect(within(config).queryByTestId("config-current") ?? within(config).queryByTestId("empty")).not.toBeNull();
      }, T);
      record("config_current", within(config).queryByTestId("config-current")?.textContent ?? "none");
      const health = screen.getAllByTestId("health")[0]!;
      record("instance_health", health.getAttribute("data-health"));
      expect(health).toHaveTextContent("Kiểm lúc");
      record("image_digest_shown", screen.getByTestId("image-digest").textContent);

      await userEvent.click(screen.getByRole("button", { name: "Restart" }));
      const dialog = await screen.findByRole("alertdialog");
      await userEvent.click(within(dialog).getByRole("button", { name: "Restart" }));
      await screen.findByRole("heading", { name: "Job instance.restart", level: 1 }, T);
      record("restart_job", idOf(router));
      record("restart_status_seen", document.querySelector("[data-status]")?.getAttribute("data-status"));
      // stack không có Host Agent: worker không chạy instance.restart ⇒ job nằm ở queued; hủy để trả stack về như cũ
      await userEvent.click(screen.getByRole("button", { name: "Hủy job" }));
      const cancel = await screen.findByRole("alertdialog");
      await userEvent.click(within(cancel).getByRole("button", { name: "Hủy job" }));
      await waitFor(() => {
        expect(screen.getByTestId("poll-status")).toHaveTextContent("trạng thái cuối");
      }, T);
      record("restart_final", document.querySelector("[data-status]")?.getAttribute("data-status"));
      unmount();
    },
    LONG,
  );
});
