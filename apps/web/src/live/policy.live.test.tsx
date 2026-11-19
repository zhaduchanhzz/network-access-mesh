// E2E chức năng của trang Policies/Tags (P4-T11) trên stack dev/CI THẬT — chỉ chạy khi tests/e2e/harness/policyui.py đặt
// MG_LIVE_ADMIN/MG_LIVE_OWNER (mặc định bỏ qua). App, router, QueryClient, client openapi-fetch đều thật; fetch của SPA
// (cùng origin /api/v1) được chuyển nguyên văn tới proxy cục bộ của harness — mỗi proxy giữ phiên (cookie HttpOnly) của
// một người đã đăng nhập Keycloak + TOTP qua edge app.<domain>: Tenant Admin và Tenant Owner của tenant-a. Hai pha
// (MG_LIVE_PHASE): "a" với 4-eyes bật (harness đặt), "b" với 4-eyes tắt. Kết quả: FUNCTIONAL (§22.1).
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { renderApp } from "../test/helpers";

const ADMIN = process.env.MG_LIVE_ADMIN ?? "";
const OWNER = process.env.MG_LIVE_OWNER ?? "";
const TENANT = process.env.MG_LIVE_TENANT_A ?? "";
const GROUP = process.env.MG_LIVE_GROUP ?? "";
const PHASE = process.env.MG_LIVE_PHASE ?? "";
const OUT = process.env.MG_LIVE_OUT ?? "";
const RUN = (process.env.MG_LIVE_RUN ?? "000000").slice(0, 6);
const TAG = `tag:ui-${RUN}`;
const LONG = 300_000;
const T = { timeout: 30_000 };
const realFetch = globalThis.fetch.bind(globalThis);

const facts: Record<string, unknown> = OUT && existsSync(OUT) ? (JSON.parse(readFileSync(OUT, "utf8")) as Record<string, unknown>) : {};
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

/** Lời gọi API trực tiếp qua proxy (một "tab" khác của cùng người): CSRF token lấy từ /auth/session. */
async function direct(proxy: string, method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
  const s = (await (await realFetch(`${proxy}/api/v1/auth/session`)).json()) as { csrf_token: string; principal: { email?: string } };
  const r = await realFetch(`${proxy}/api/v1/tenants/${TENANT}${path}`, {
    method,
    headers: { "Content-Type": "application/json", "X-CSRF-Token": s.csrf_token, ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await r.text();
  return { status: r.status, json: (text ? JSON.parse(text) : {}) as Record<string, unknown> };
}

async function myEmail(proxy: string): Promise<string> {
  const s = (await (await realFetch(`${proxy}/api/v1/auth/session`)).json()) as { principal: { email?: string } };
  return s.principal.email ?? "";
}

const pathOf = (router: ReturnType<typeof renderApp>["router"]) => router.state.location.pathname;
const lastId = (router: ReturnType<typeof renderApp>["router"]) => pathOf(router).split("/").pop() ?? "";

async function hujson(text: string) {
  const box = await screen.findByLabelText("Văn bản HuJSON", {}, T);
  fireEvent.change(box, { target: { value: text } });
  await userEvent.click(screen.getByRole("button", { name: "Dịch sang biểu mẫu" }));
}

async function saveDraft() {
  const before = screen.getByTestId("version-etag").textContent;
  await userEvent.click(screen.getByRole("button", { name: "Lưu bản nháp" }));
  await waitFor(() => expect(screen.getByTestId("version-etag").textContent).not.toBe(before), T);
}

async function validate(): Promise<string> {
  const before = screen.getByTestId("version-etag").textContent;
  await userEvent.click(screen.getByRole("button", { name: "Kiểm tra" }));
  // validate tăng revision (ETag) và báo cáo mang đúng revision đó
  await waitFor(() => expect(screen.getByTestId("version-etag").textContent).not.toBe(before), { timeout: 60_000 });
  const report = screen.getByTestId("policy-report");
  return report.getAttribute("data-result") ?? "";
}

async function newDraft(router: ReturnType<typeof renderApp>["router"]): Promise<string> {
  await userEvent.click(await screen.findByRole("button", { name: "Soạn version mới" }, T));
  await waitFor(() => expect(pathOf(router)).toMatch(/\/policies\/[0-9a-f-]{36}$/), T);
  await screen.findByTestId("version-etag", {}, T);
  return lastId(router);
}

async function approveInDialog(label: string) {
  await userEvent.click(await screen.findByRole("button", { name: label }, T));
  const dialog = await screen.findByRole("alertdialog", {}, T);
  await userEvent.click(within(dialog).getByRole("checkbox"));
  await userEvent.click(within(dialog).getByRole("button", { name: "Duyệt" }));
  await waitFor(() => expect(screen.getByTestId("version-state")).toHaveTextContent("Đã duyệt"), T);
}

async function applyAndWait(router: ReturnType<typeof renderApp>["router"], button: string): Promise<string> {
  await userEvent.click(await screen.findByRole("button", { name: button }, T));
  const dialog = await screen.findByRole("alertdialog", {}, T);
  await userEvent.click(within(dialog).getByRole("button", { name: button }));
  await waitFor(() => expect(router.state.location.search).toMatch(/^\?job=/), T);
  await waitFor(() => expect(screen.getByTestId("apply-job").getAttribute("data-status")).toMatch(/^(succeeded|failed|cancelled)$/), {
    timeout: 180_000,
  });
  return router.state.location.search.slice("?job=".length);
}

async function appliedSha(router: ReturnType<typeof renderApp>["router"], version: string): Promise<string> {
  await router.navigate(`/t/${TENANT}/policies`);
  // trạng thái áp dụng được làm mới khi job xong: chờ lần áp hiện hành là của đúng version
  await waitFor(() => {
    const cur = screen.getByTestId("current-applied");
    expect(within(cur).getByRole("link").getAttribute("href")).toBe(`/t/${TENANT}/policies/${version}`);
  }, { timeout: 60_000 });
  return screen.getByTestId("current-applied").getAttribute("data-sha") ?? "";
}

describe.skipIf(!ADMIN || !OWNER || !TENANT || PHASE !== "a")("Policies trên stack thật — pha a (4-eyes bật)", () => {
  it(
    "UI-10 Tags: khai báo tag qua SPA (Idempotency-Key, danh mục thật)",
    async () => {
      as(ADMIN);
      const { unmount } = renderApp({ path: `/t/${TENANT}/tags` });
      const name = await screen.findByLabelText("Tên tag", {}, T);
      await userEvent.clear(name);
      await userEvent.type(name, TAG);
      await userEvent.click(screen.getByRole("button", { name: "Khai báo" }));
      expect(await screen.findByTestId("tag-created", {}, T)).toHaveTextContent(TAG);
      await screen.findByText(TAG, { selector: "td" }, T);
      record("tag", TAG);
      unmount();
    },
    LONG,
  );

  it(
    "UI-11 Admin: soạn → HuJSON thiếu grants ⇒ L1 → * ở dst ⇒ validate L4 → sửa → validate đạt (CheckPolicy) → gửi duyệt; người soạn không duyệt được",
    async () => {
      as(ADMIN);
      const email = await myEmail(ADMIN);
      const { router, unmount } = renderApp({ path: `/t/${TENANT}/policies` });
      await screen.findByTestId("policy-current", {}, T);
      const id = await newDraft(router);
      record("version_a", id);
      record("version_a_number", screen.getByRole("heading", { level: 1 }).textContent);
      // L1: HuJSON không có grants (bộ dịch phía server)
      await userEvent.click(screen.getByRole("radio", { name: "HuJSON" }));
      await hujson('{"ssh": []}');
      const errs = await screen.findByTestId("import-errors", {}, T);
      expect(errs.querySelector("[data-rule=L1]")).not.toBeNull();
      record("l1_seen", errs.querySelector("[data-rule=L1]")?.getAttribute("data-code"));
      // L4: * làm đích ⇒ validate chặn (cần Owner xác nhận)
      await hujson('{"grants": [{"src": ["autogroup:member"], "dst": ["*"], "ip": ["*"]}]}');
      await screen.findByTestId("policy-form", {}, T);
      await saveDraft();
      expect(await validate()).toBe("failed");
      const l4 = screen.getByTestId("policy-report").querySelector("[data-rule=L4]");
      expect(l4).not.toBeNull();
      record("l4_seen", l4?.getAttribute("data-code"));
      expect(screen.getByTestId("version-state")).toHaveTextContent("Bản nháp");
      // sửa: luật thật (group + e-mail của chính Admin + tag vừa khai báo), qua HuJSON có chú thích
      await userEvent.click(screen.getByRole("radio", { name: "HuJSON" }));
      await hujson(
        `// P4-T11 E2E\n{\n  "grants": [\n    {"src": ["autogroup:member"], "dst": ["autogroup:member"], "ip": ["tcp:8000"]},\n` +
          `    {"src": ["group:${GROUP}", "${email}"], "dst": ["${TAG}"], "ip": ["tcp:443"]},\n  ],\n}\n`,
      );
      await screen.findByTestId("policy-form", {}, T);
      // chip của principal (không tính <option> của bộ chọn)
      expect(within(screen.getByTestId("grant-1")).getByText(`group:${GROUP}`, { selector: "li span" })).toBeInTheDocument();
      expect(within(screen.getByTestId("grant-1")).getByText(TAG, { selector: "li span" })).toBeInTheDocument();
      await saveDraft();
      expect(await validate()).toBe("passed");
      expect(screen.getByTestId("policy-report")).toHaveAttribute("data-check", "passed");
      record("validated_etag", screen.getByTestId("version-etag").textContent);
      // 4-eyes: gửi duyệt; người soạn/gửi không có nút Duyệt
      await userEvent.click(screen.getByRole("button", { name: "Gửi duyệt" }));
      await waitFor(() => expect(screen.getByTestId("version-state")).toHaveTextContent("Chờ duyệt"), T);
      expect(await screen.findByTestId("four-eyes-self", {}, T)).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Duyệt" })).toBeNull();
      record("author_has_approve_button", screen.queryByRole("button", { name: "Duyệt" }) !== null);
      // server quyết định: ép gọi approve như người soạn ⇒ 403
      const etag = screen.getByTestId("version-etag").textContent ?? "";
      const sha = screen.getByTestId("content-sha").textContent ?? "";
      const forced = await direct(ADMIN, "POST", `/policies/${id}/approve`, { content_sha256: sha }, { "If-Match": etag });
      record("author_forced_approve", { status: forced.status, code: forced.json.code });
      expect(forced.status).toBe(403);
      unmount();
    },
    LONG,
  );

  it(
    "UI-12 Owner (người khác): duyệt (peer) → áp dụng (step-up đủ mới) → job policy.apply succeeded → trạng thái áp dụng có sha256",
    async () => {
      as(OWNER);
      const id = String(facts.version_a);
      const { router, unmount } = renderApp({ path: `/t/${TENANT}/policies/${id}` });
      await screen.findByTestId("version-state", {}, T);
      expect(screen.queryByTestId("four-eyes-self")).toBeNull();
      await approveInDialog("Duyệt");
      record("approved_by_shown", screen.getByTestId("approved-by").textContent);
      const job = await applyAndWait(router, "Áp dụng");
      record("apply_job", job);
      record("apply_status", screen.getByTestId("apply-job").getAttribute("data-status"));
      expect(screen.getByTestId("apply-job")).toHaveAttribute("data-status", "succeeded");
      record("applied_sha_a", await appliedSha(router, id));
      unmount();
    },
    LONG,
  );
});

describe.skipIf(!ADMIN || !OWNER || !TENANT || PHASE !== "b")("Policies trên stack thật — pha b (4-eyes tắt)", () => {
  it(
    "UI-13 Admin: hai bản nháp cùng gốc; B (deny-all) tự duyệt + áp dụng; C sửa với revision cũ ⇒ 412; C áp dụng ⇒ 409 stale_base ⇒ soạn lại; rollback về A; xóa tag còn tham chiếu ⇒ 409",
    async () => {
      as(ADMIN);
      const { router, unmount } = renderApp({ path: `/t/${TENANT}/policies` });
      await screen.findByTestId("policy-current", {}, T);
      const b = await newDraft(router);
      await router.navigate(`/t/${TENANT}/policies`);
      const c = await newDraft(router);
      record("version_b", b);
      record("version_c", c);
      // B: deny-all (gỡ mọi luật) → lưu → kiểm tra → tự xác nhận → áp dụng
      await router.navigate(`/t/${TENANT}/policies/${b}`);
      await screen.findByTestId("grant-1", {}, T);
      await userEvent.click(screen.getByRole("button", { name: "Gỡ luật 2" }));
      await userEvent.click(screen.getByRole("button", { name: "Gỡ luật 1" }));
      await saveDraft();
      expect(await validate()).toBe("passed");
      await approveInDialog("Xác nhận và duyệt");
      record("apply_b_job", await applyAndWait(router, "Áp dụng"));
      record("apply_b_status", screen.getByTestId("apply-job").getAttribute("data-status"));
      // C: một "tab" khác sửa trước (If-Match "1" ⇒ revision 2) — tab này sửa với revision cũ ⇒ 412, tải lại
      await router.navigate(`/t/${TENANT}/policies/${c}`);
      await screen.findByTestId("grant-0", {}, T);
      const other = await direct(ADMIN, "GET", `/policies/${c}`);
      const patched = await direct(ADMIN, "PATCH", `/policies/${c}`, { source: other.json.source }, { "If-Match": String(other.json.etag) });
      record("other_tab_patch", patched.status);
      const ip = screen.getByLabelText("Giao thức/cổng (ip) của luật 1");
      await userEvent.clear(ip);
      await userEvent.type(ip, "tcp:8000, tcp:8001");
      await userEvent.click(screen.getByRole("button", { name: "Lưu bản nháp" }));
      const stale = await screen.findByTestId("stale-revision", {}, T);
      record("stale_412_seen", stale.textContent?.includes("412") ?? false);
      await userEvent.click(within(stale).getByRole("button", { name: "Tải lại bản mới nhất" }));
      await waitFor(() => expect(screen.getByTestId("version-etag")).toHaveTextContent('"2"'), T);
      // C: kiểm tra → tự xác nhận → áp dụng ⇒ 409 stale_base (B đã là mong muốn)
      expect(await validate()).toBe("passed");
      await approveInDialog("Xác nhận và duyệt");
      expect(screen.getByText("base đã cũ")).toBeInTheDocument();
      await userEvent.click(screen.getByRole("button", { name: "Áp dụng" }));
      const dialog = await screen.findByRole("alertdialog", {}, T);
      await userEvent.click(within(dialog).getByRole("button", { name: "Áp dụng" }));
      expect(await within(dialog).findByTestId("stale-base-dialog", {}, T)).toBeInTheDocument();
      await userEvent.click(within(dialog).getByRole("button", { name: "Hủy" }));
      record("stale_base_seen", (await screen.findByTestId("stale-base", {}, T)).textContent?.includes("stale_base") ?? false);
      await userEvent.click(screen.getByRole("button", { name: "Tạo bản nháp mới từ nội dung này" }));
      await waitFor(() => expect(lastId(router)).not.toBe(c), T);
      await screen.findByTestId("version-etag", {}, T);
      record("version_d", lastId(router));
      // rollback về nội dung của A (đã duyệt — phê duyệt được kế thừa)
      await router.navigate(`/t/${TENANT}/policies/${String(facts.version_a)}`);
      await waitFor(() => expect(screen.getByTestId("version-state")).toHaveAttribute("data-status", "superseded"), T);
      const rb = await screen.findByRole("button", { name: "Rollback về nội dung này" }, T);
      record("rollback_button", {
        disabled: (rb as HTMLButtonElement).disabled,
        path: pathOf(router),
        actions: screen.getByTestId("policy-actions").textContent,
        bodyStyle: document.body.getAttribute("style"),
      });
      const job = await applyAndWait(router, "Rollback về nội dung này");
      record("rollback_job", job);
      record("rollback_version", lastId(router));
      record("rollback_status", screen.getByTestId("apply-job").getAttribute("data-status"));
      record("applied_sha_rollback", await appliedSha(router, lastId(router)));
      // xóa tag còn được policy tham chiếu ⇒ 409 kèm số lượng
      await router.navigate(`/t/${TENANT}/tags`);
      await userEvent.click(await screen.findByRole("button", { name: `Xóa ${TAG}` }, T));
      const del = await screen.findByRole("alertdialog", {}, T);
      await userEvent.click(within(del).getByRole("button", { name: "Xóa" }));
      await within(del).findByTestId("tag-in-use", {}, T);
      record("tag_delete_problem", within(del).getByRole("alert").textContent);
      unmount();
    },
    LONG * 2,
  );
});
