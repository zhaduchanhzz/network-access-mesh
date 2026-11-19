// E2E chức năng của Thêm thiết bị / trang claim / Enrollment key (P4-T08) trên stack dev/CI THẬT — chỉ chạy khi
// tests/e2e/harness/enrollui.py đặt MG_LIVE_ADMIN (mặc định bỏ qua). App, router, QueryClient, client openapi-fetch đều
// thật; fetch của SPA (cùng origin /api/v1) đi nguyên văn tới proxy cục bộ của harness — proxy giữ phiên (cookie HttpOnly)
// của một Tenant Admin đã đăng nhập Keycloak + TOTP qua edge trên app.<domain>.
// Harness làm phần "thiết bị": thấy tệp `hostname` ⇒ client Tailscale chính thức chạy `tailscale up --hostname <đó>`,
// lấy link /register/<auth_id> client in ra, GET qua edge v10 ⇒ 302 ⇒ ghi path+query của Location vào tệp `claim`; thấy
// tệp `key` ⇒ client chính thức dùng key. Hai tệp nằm trong thư mục bí mật 0700 của harness (MG_LIVE_SECRET_DIR — không
// phải thư mục kết quả), harness xóa sau khi đọc. Kết quả: FUNCTIONAL (§22.1).
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { renderApp } from "../test/helpers";

const ADMIN = process.env.MG_LIVE_ADMIN ?? "";
const T = process.env.MG_LIVE_TENANT_A ?? "";
const SECRET = process.env.MG_LIVE_SECRET_DIR ?? "";
const OUT = process.env.MG_LIVE_OUT ?? "";
const RUN = (process.env.MG_LIVE_RUN ?? "000000").slice(0, 6);
const LONG = 600_000;
const realFetch = globalThis.fetch.bind(globalThis);

const facts: Record<string, unknown> = { run: RUN };
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

function until<T>(fn: () => T, timeout = 60_000): Promise<T> {
  return waitFor(fn, { timeout, interval: 500 });
}

function writeSecret(name: string, value: string) {
  writeFileSync(join(SECRET, name), value, { mode: 0o600 });
}

async function readSecret(name: string, timeout = 180_000): Promise<string> {
  const p = join(SECRET, name);
  await until(() => expect(existsSync(p)).toBe(true), timeout);
  const v = readFileSync(p, "utf8").trim();
  rmSync(p, { force: true });
  return v;
}

/** Secret không còn ở DOM, Web Storage, URL hay cache của TanStack Query. */
function traces(secret: string, router: { state: { location: { pathname: string; search: string } } }, queryClient: { getQueryCache: () => { getAll: () => { state: unknown }[] }; getMutationCache: () => { getAll: () => { state: unknown }[] } }): string[] {
  const out: string[] = [];
  if (document.body.innerHTML.includes(secret)) out.push("dom");
  const dump = (st: Storage) => Array.from({ length: st.length }, (_, i) => `${st.key(i) ?? ""}=${st.getItem(st.key(i) ?? "") ?? ""}`).join(";");
  if ((dump(localStorage) + dump(sessionStorage)).includes(secret)) out.push("storage");
  if ((router.state.location.pathname + router.state.location.search).includes(secret)) out.push("url");
  if (JSON.stringify(queryClient.getQueryCache().getAll().map((q) => q.state)).includes(secret)) out.push("query-cache");
  if (JSON.stringify(queryClient.getMutationCache().getAll().map((m) => m.state)).includes(secret)) out.push("mutation-cache");
  return out;
}

describe.skipIf(!ADMIN || !T || !SECRET)("Enrollment trên stack thật", () => {
  it(
    "UI-14 web-auth: wizard Linux → lệnh mg-<mã> → client chính thức → link qua edge v10 302 → trang claim (gỡ auth_id, cảnh báo, xác nhận) → verified",
    async () => {
      as(ADMIN);
      const label = `ui14-${RUN}`;
      const { router, queryClient, unmount } = renderApp({ path: `/t/${T}/enroll` });
      const wizard = await screen.findByTestId("enroll-wizard", {}, { timeout: 30_000 });
      await userEvent.click(within(wizard).getByLabelText("Linux"));
      const login = await within(wizard).findByTestId("login-server", {}, { timeout: 30_000 });
      record("login_server_shown", /^https:\/\/tenant-a\./.test(login.textContent));
      await userEvent.type(within(wizard).getByLabelText("Nhãn thiết bị (tùy chọn)"), label);
      await until(() => expect(within(wizard).getByRole("radio", { name: /Web-auth/ })).toBeChecked());
      await userEvent.click(within(wizard).getByRole("button", { name: "Tạo lệnh đăng ký" }));
      const issued = await screen.findByTestId("issued-web", {}, { timeout: 30_000 });
      const cmd = within(issued).getByTestId("enroll-command").textContent;
      const hostname = /--hostname=(mg-[a-z2-7]{12})\b/.exec(cmd)?.[1] ?? "";
      record("command_has_login_server", cmd.includes("--login-server=https://tenant-a."));
      record("hostname_shape", /^mg-[a-z2-7]{12}$/.test(hostname));
      record("code_not_stored", traces(hostname, router, queryClient).filter((x) => x !== "dom"));
      writeSecret("hostname", hostname);

      // harness: client chạy lệnh, link của client ⇒ 302 của edge ⇒ Location (path + query trên app.<domain>)
      const claimPath = await readSecret("claim");
      record("claim_path_shape", /^\/enroll\/claim\?tenant=tenant-a&auth_id=hskey-authreq-[A-Za-z0-9_-]{24}$/.test(claimPath));
      const authId = new URLSearchParams(claimPath.split("?")[1] ?? "").get("auth_id") ?? "";
      await router.navigate(claimPath);
      const panel = await screen.findByTestId("claim-confirm", {}, { timeout: 30_000 });
      await until(() => expect(router.state.location.search).toBe("?tenant=tenant-a"));
      record("auth_id_stripped", !router.state.location.search.includes("auth_id"));
      record("pending_seen", (await within(panel).findByTestId("pending-context", {}, { timeout: 90_000 })).textContent.includes(label));
      expect(within(panel).getByRole("button", { name: "Xác nhận thiết bị" })).toBeDisabled();
      await userEvent.click(within(panel).getByLabelText(/Tôi vừa chạy lệnh/));
      await userEvent.click(within(panel).getByRole("button", { name: "Xác nhận thiết bị" }));
      const ok = await screen.findByTestId("claim-verified", {}, { timeout: 120_000 });
      record("claim_result", ok.textContent.includes(label) ? "verified" : ok.textContent);
      record("auth_id_traces", traces(authId, router, queryClient));

      // tab Thêm thiết bị: yêu cầu của tôi đã xác minh
      await router.navigate(`/t/${T}/enroll`);
      const mine = await screen.findByTestId("my-requests", {}, { timeout: 30_000 });
      const row = within(mine).getAllByTestId("enroll-row").find((r) => r.textContent.includes(label));
      record("row_status", row?.getAttribute("data-status"));
      record("request_id", row?.getAttribute("data-request"));
      unmount();
    },
    LONG,
  );

  it(
    "UI-15 pre-auth key: Enrollment key → tạo key một lần (5 phút) → hiển thị một lần → client chính thức Running → đóng hộp, không dấu vết → consumed",
    async () => {
      as(ADMIN);
      const label = `ui15-${RUN}`;
      const { router, queryClient, unmount } = renderApp({ path: `/t/${T}/enrollment-keys` });
      await userEvent.click(await screen.findByRole("button", { name: "Tạo pre-auth key" }, { timeout: 30_000 }));
      const dialog = screen.getByRole("dialog", { name: "Tạo pre-auth key" });
      await userEvent.type(within(dialog).getByLabelText("Nhãn thiết bị (tùy chọn)"), label);
      const ttl = within(dialog).getByLabelText("Hạn của key (phút)");
      await userEvent.clear(ttl);
      await userEvent.type(ttl, "5");
      await userEvent.click(within(dialog).getByRole("button", { name: "Tạo key" }));
      const reveal = await screen.findByRole("dialog", { name: "Pre-auth key (hiển thị một lần)" }, { timeout: 30_000 });
      const key = within(reveal).getByTestId("secret-value").textContent.trim();
      record("key_shape", /^hskey-auth-/.test(key));
      record("key_command_without_key", !within(reveal).getByTestId("key-command").textContent.includes(key));
      record("key_not_stored", traces(key, router, queryClient).filter((x) => x !== "dom"));
      writeSecret("key", key);
      await userEvent.click(within(reveal).getByLabelText("Tôi đã lưu key ở nơi an toàn."));
      await userEvent.click(within(reveal).getByRole("button", { name: "Đóng và xóa key khỏi màn hình" }));
      await until(() => expect(screen.queryByRole("dialog")).toBeNull());
      record("key_traces_after_close", traces(key, router, queryClient));
      // harness: client chính thức dùng key ⇒ Running; job enrollment.reconcile (lịch 2 phút) ⇒ consumed — bảng poll
      const all = screen.getByTestId("all-requests");
      const final = await until(() => {
        const row = within(screen.getByTestId("all-requests")).getAllByTestId("enroll-row").find((r) => r.textContent.includes(label));
        expect(row?.getAttribute("data-status")).toBe("consumed");
        return row;
      }, 360_000).catch(() => within(all).queryAllByTestId("enroll-row").find((r) => r.textContent.includes(label)));
      record("key_row_status", final?.getAttribute("data-status"));
      record("key_request_id", final?.getAttribute("data-request"));
      unmount();
    },
    LONG,
  );
});
