// Luồng enrollment trong trình duyệt thật (P4-T06 backend, P4-T07 edge /register/* v10, P4-T08 UI; G4b — P4-T14):
//   1. End User: wizard theo OS — login_server ĐÚNG của tenant, lệnh MSI/LoginURL (Windows), mobile chỉ pre-auth key,
//      sao chép vào clipboard;
//   2. Tenant Admin: trang claim web-auth từ link /register/<auth_id> THẬT của một client Tailscale chính thức (harness —
//      pwcontrol.py) ⇒ edge 302 ⇒ trang claim (auth_id gỡ khỏi URL) ⇒ cảnh báo phishing + xác nhận tường minh ⇒ verified;
//      link của một client khác khi KHÔNG có yêu cầu đang chờ ⇒ 409 no_pending_request ⇒ trang cảnh báo không nút xác nhận;
//   3. Tenant Admin: pre-auth key hiển thị MỘT lần (client thật dùng được key) — đóng hộp / tải lại ⇒ không còn ở DOM, URL,
//      Web Storage; thu hồi hai pha một key chưa dùng (hộp xác nhận: Esc/Hủy không gửi);
//   4. hàng chờ duyệt: End User tạo yêu cầu (tenant bật duyệt) ⇒ chờ duyệt, không có nút duyệt của chính mình; Tenant Admin
//      duyệt một, từ chối một; người yêu cầu nhận lệnh (/start);
//   5. end-to-end với client thật: claim ⇒ thiết bị xuất hiện ở Devices ⇒ xóa thiết bị (hai pha: "đang chờ" rồi "đã xóa"
//      khi Headscale xác nhận) ⇒ node không còn ở Headscale;
//   C4 (Support Access Grant): enrollment-support.spec.ts (đăng nhập mới + step-up ⇒ file riêng không trace).
// Mỗi ca tự dọn client + node của mình (harness — bài học E2E-118) và chạy lại được (vi + en, hai lượt). Credential chỉ
// đi qua màn hình và kênh harness (redaction), không vào artifact.
import type { Locator, Page } from "@playwright/test";
import { APP, cfg, MESH_HOSTS, storageFile } from "./env";
import { closeAll, requestWebAuth, row } from "./enroll";
import {
  checkA11y,
  checkDestructiveConfirm,
  checkI18n,
  checkNoSecrets,
  checkScreen,
  confirmDialog,
  clickUntil,
  ctl,
  ctlUntil,
  expect,
  lit,
  lngOf,
  newActor,
  settle,
  T,
  test,
  Tv,
  uniq,
  type Actor,
  type Lng,
} from "./support";

const A = cfg.tenantA.id;
const OSES = ["windows", "macos", "linux", "ios", "android"] as const;
const MOBILE: ReadonlySet<string> = new Set(["ios", "android"]);

interface WebClient {
  client: string;
  link: string;
}

/** Yêu cầu web-auth vừa phát trên Add device: hostname mg-<mã> + lệnh (đúng login server, đúng hostname). */
async function issuedHostname(page: Page, lng: Lng): Promise<string> {
  const cmd = page.getByTestId("web-auth-command");
  await expect(cmd).toBeVisible();
  const hostname = ((await cmd.locator("p", { hasText: T(lng, "enroll.issued.hostname") }).locator("code").textContent()) ?? "").trim();
  expect(hostname).toMatch(/^mg-[a-z2-7]{12}$/);
  const command = (await page.getByTestId("enroll-command").textContent()) ?? "";
  expect(command).toContain(cfg.loginServer);
  expect(command).toContain(hostname);
  return hostname;
}

/** Mở link client in ra trong một tab mới của CÙNG trình duyệt (§7.4 bước 6): edge v10 ⇒ 302 ⇒ trang claim của Portal. */
async function openClientLink(actor: { context: Actor["context"] }, link: string): Promise<{ page: Page; redirect: number }> {
  expect(MESH_HOSTS).toContain(new URL(link).hostname);
  const page = await actor.context.newPage();
  const resp = await page.goto(link);
  // chuỗi chuyển hướng: request đầu (link của client) ⇒ 302 của edge ⇒ /enroll/claim?tenant=&auth_id= (SPA)
  let first = resp?.request() ?? null;
  while (first?.redirectedFrom()) first = first.redirectedFrom();
  const redirect = first && first !== resp?.request() ? ((await first.response())?.status() ?? 0) : 0;
  await expect(page).toHaveURL(`${APP}/enroll/claim?tenant=${cfg.tenantA.slug}`); // auth_id đã gỡ khỏi URL
  return { page, redirect };
}

/** Xác nhận tường minh trên trang claim (nút khóa tới khi tick ô xác nhận) tới kết quả `done`. 429 (bucket `enrollment`
 * dùng chung với các GET đang poll của tab Thêm thiết bị): trang tự gửi lại MỘT lần sau Retry-After (F-G4a-1); nếu lần đó
 * cũng 429 thì bấm lại như người dùng. */
async function confirmClaim(claim: Page, lng: Lng, done: Locator): Promise<void> {
  const panel = claim.getByTestId("claim-confirm");
  await expect(panel).toBeVisible({ timeout: 60_000 });
  const button = panel.getByRole("button", { name: T(lng, "enroll.claim.confirm") });
  await expect(button).toBeDisabled();
  await panel.getByLabel(T(lng, "enroll.claim.ack")).check();
  await clickUntil(claim, lng, button, done, 180_000);
}

/** Thu hồi (API, từ trong trang) yêu cầu web-auth còn `issued` của nhãn — dọn khi ca lỗi giữa chừng để phiên này không
 * còn hai yêu cầu đang chờ (ca sau sẽ phải chọn request_id). */
async function revokeIfIssued(page: Page, label: string): Promise<void> {
  if (page.isClosed()) return;
  await page
    .evaluate(
      async ({ tenant, label }) => {
        const s = (await (await fetch("/api/v1/auth/session")).json()) as { csrf_token?: string };
        const list = (await (await fetch(`/api/v1/tenants/${tenant}/enrollment/requests?status=issued&limit=50`)).json()) as {
          items?: { id: string; device_label?: string | null }[];
        };
        for (const r of list.items ?? []) {
          if (r.device_label === label) {
            await fetch(`/api/v1/tenants/${tenant}/enrollment/requests/${r.id}/revoke`, { method: "POST", headers: { "X-CSRF-Token": s.csrf_token ?? "" } });
          }
        }
      },
      { tenant: A, label },
    )
    .catch(() => undefined);
}

// ================================================================================================ End User
test.describe("enrollment — End User", () => {
  test.use({ storageState: storageFile("member") });

  test("End User: wizard theo OS — login_server của tenant, MSI/LoginURL (Windows), mobile chỉ pre-auth key, sao chép, axe", async ({ page, context, guard }, testInfo) => {
    const lng = lngOf(testInfo);
    await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: APP });
    await page.goto(`${APP}/t/${A}/enroll`);
    await checkScreen(page, testInfo, "enroll-member");
    const wizard = page.getByTestId("enroll-wizard");
    const ins = wizard.getByTestId("instructions");
    for (const os of OSES) {
      await wizard.getByRole("radio", { name: T(lng, `enroll.os.${os}.name`), exact: true }).check();
      // bucket `enrollment` của API: 429 ⇒ UI đọc lại theo Retry-After
      await expect(ins).toHaveAttribute("data-os", os, { timeout: 60_000 });
      await expect(ins.getByTestId("login-server")).toHaveText(cfg.loginServer);
      await expect(ins.getByTestId("privacy-notice")).toHaveText(T(lng, "enroll.privacy"));
      const web = wizard.getByRole("radio", { name: lit(T(lng, "enroll.method.web_auth")) });
      if (MOBILE.has(os)) {
        await expect(web).toBeDisabled();
        await expect(ins).toContainText(T(lng, "enroll.instructions.mobileNote"));
        await expect(wizard.getByRole("radio", { name: lit(T(lng, "enroll.method.preauth_key")) })).toBeChecked();
      } else {
        await expect(web).toBeEnabled();
      }
      if (os === "windows") {
        await expect(ins.getByTestId("windows-msi")).toContainText(`TS_LOGINURL=${cfg.loginServer}`);
        await expect(ins.getByTestId("windows-msi")).toContainText(`/v LoginURL /t REG_SZ /d ${cfg.loginServer}`);
      } else {
        await expect(ins.getByTestId("windows-msi")).toHaveCount(0);
      }
      await checkA11y(page, testInfo, `enroll-wizard-${os}`);
      await checkI18n(page, lng, `enroll-wizard-${os}`);
    }
    // sao chép login server (navigator.clipboard — secure context) ⇒ vùng live báo "đã sao chép", clipboard đúng giá trị
    await ins.getByRole("button", { name: T(lng, "enroll.instructions.copyLoginServer") }).click();
    await expect(ins.getByRole("status").filter({ hasText: T(lng, "ui.copied") })).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(cfg.loginServer);
    await checkNoSecrets(context, guard, "wizard");
  });
});

// ================================================================================================ Tenant Admin
test.describe("enrollment — Tenant Admin (phiên của auth.setup)", () => {
  test.use({ storageState: storageFile("admin") });

  test("Trang claim web-auth: link /register/<auth_id> thật của client ⇒ 302 ⇒ trang claim (auth_id gỡ khỏi URL), cảnh báo phishing + xác nhận ⇒ verified; không có yêu cầu đang chờ ⇒ 409 no_pending_request ⇒ cảnh báo, không nút xác nhận", async ({ page, context, guard }, testInfo) => {
    const lng = lngOf(testInfo);
    const label = uniq("c", lng);
    const clients: string[] = [];
    try {
      await page.goto(`${APP}/t/${A}/enroll`);
      await settle(page, lng);
      await requestWebAuth(page, lng, label, page.getByTestId("issued-web"));
      const hostname = await issuedHostname(page, lng);
      await checkA11y(page, testInfo, "enroll-issued-web");
      const web = await ctl<WebClient>("webauth_client", { tag: `c-${label.slice(-6)}`, hostname });
      clients.push(web.client);
      const authId = new URL(web.link).pathname.split("/").pop() ?? "";
      expect(authId).toMatch(/^hskey-authreq-[A-Za-z0-9_-]{24}$/);
      expect(new URL(web.link).hostname).toBe(`tenant-a.${cfg.mesh}`);

      const { page: claim, redirect } = await openClientLink({ context }, web.link);
      expect(redirect, "edge v10: /register/<auth_id> ⇒ 302").toBe(302);
      await expect(claim.locator("h1")).toHaveText(T(lng, "enroll.claim.title"));
      await expect(claim.getByTestId("phishing-caution")).toContainText(T(lng, "enroll.claim.cautionNever"));
      await expect(claim.getByTestId("pending-context")).toContainText(label, { timeout: 60_000 });
      await checkScreen(claim, testInfo, "claim-pending");
      const verified = claim.getByTestId("claim-verified");
      await confirmClaim(claim, lng, verified);
      await expect(verified).toContainText(Tv(lng, "enroll.claim.verified", { label }));
      await checkScreen(claim, testInfo, "claim-verified");
      // lệnh/mã enrollment rời màn hình khi yêu cầu rời `issued`; client thật Running
      await expect(page.getByTestId("issued-status")).toContainText(T(lng, "status.enrollment.verified"), { timeout: 60_000 });
      await expect(page.getByTestId("enroll-command")).toHaveCount(0);
      const state = await ctlUntil<{ state: string }>("client_state", { client: web.client }, (r) => r.state === "Running");
      expect(state.state, "client chính thức Running sau claim").toBe("Running");
      await checkNoSecrets(context, guard, "claim-verified", [authId, hostname]);

      // link của một client khác trong khi phiên này KHÔNG có yêu cầu đang chờ ⇒ 409 no_pending_request
      const other = await ctl<WebClient>("webauth_client", { tag: `x-${label.slice(-6)}`, hostname: uniq("x", lng) });
      clients.push(other.client);
      const otherId = new URL(other.link).pathname.split("/").pop() ?? "";
      const { page: phish } = await openClientLink({ context }, other.link);
      await expect(phish.getByTestId("no-pending-hint")).toHaveText(T(lng, "enroll.claim.noPendingSeen"), { timeout: 60_000 });
      const warn = phish.getByTestId("claim-phishing");
      await confirmClaim(phish, lng, warn);
      await expect(warn).toContainText(T(lng, "enroll.claim.phishingTitle"));
      await expect(phish.getByRole("button", { name: T(lng, "enroll.claim.confirm") })).toHaveCount(0);
      await expect(phish.getByRole("checkbox")).toHaveCount(0);
      await checkScreen(phish, testInfo, "claim-phishing");
      await checkNoSecrets(context, guard, "claim-phishing", [authId, otherId, hostname]);
      const left = await ctl<{ state: string }>("client_state", { client: other.client });
      expect(left.state, "không xác nhận ⇒ client vẫn chờ đăng nhập").toBe("NeedsLogin");
    } finally {
      await revokeIfIssued(page, label);
      await ctl("cleanup", { clients, prefixes: [label, `pwx-${lng}-`] });
    }
  });

  test("Pre-auth key MỘT lần: cảnh báo, sao chép, lệnh không chứa key ⇒ client thật đăng ký; đóng / tải lại ⇒ key không còn ở DOM, URL, Web Storage; thu hồi hai pha một key chưa dùng (Esc/Hủy không gửi)", async ({ page, context, guard }, testInfo) => {
    const lng = lngOf(testInfo);
    const label = uniq("k", lng);
    const spare = uniq("r", lng);
    const clients: string[] = [];
    await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: APP });
    try {
      await page.goto(`${APP}/t/${A}/enrollment-keys`);
      await checkScreen(page, testInfo, "enrollment-keys");
      const create = page.getByRole("button", { name: T(lng, "enroll.key.create"), exact: true });
      const reveal = page.getByRole("dialog", { name: T(lng, "enroll.key.dialogTitle") });
      const issueKey = async (l: string) => {
        await create.click();
        const form = page.getByRole("dialog", { name: T(lng, "enroll.key.createTitle") });
        await expect(form).toBeVisible();
        await form.getByLabel(T(lng, "enroll.wizard.label")).fill(l);
        await form.getByLabel(T(lng, "enroll.wizard.ttl")).fill("5");
        await clickUntil(page, lng, form.getByRole("button", { name: T(lng, "enroll.key.submit") }), reveal);
      };
      await issueKey(label);
      const key = ((await reveal.getByTestId("secret-value").textContent()) ?? "").trim();
      expect(key).toMatch(/^hskey-auth-/);
      await expect(reveal.getByTestId("secret-once-warning")).toHaveText(T(lng, "enroll.key.onceWarning"));
      const command = (await reveal.getByTestId("key-command").textContent()) ?? "";
      expect(command).toContain(cfg.loginServer);
      expect(command.includes(key), "lệnh không chứa key (TS_AUTHKEY)").toBe(false);
      await checkA11y(page, testInfo, "key-reveal");
      await checkI18n(page, lng, "key-reveal");
      await reveal.getByTestId("copy-key").click();
      await expect(reveal.getByRole("status").filter({ hasText: T(lng, "ui.copied") })).toBeVisible();
      expect((await page.evaluate(() => navigator.clipboard.readText())) === key, "clipboard = key").toBe(true);
      await page.evaluate(() => navigator.clipboard.writeText(""));
      // key dùng được: client chính thức đăng ký bằng chính key vừa hiển thị
      const joined = await ctl<{ client: string }>("key_client", { key, tag: `k-${label.slice(-6)}`, hostname: label });
      clients.push(joined.client);
      // đóng: phải xác nhận đã lưu; đóng ⇒ key bị xóa khỏi state
      const close = reveal.getByRole("button", { name: T(lng, "enroll.key.close") });
      await expect(close).toBeDisabled();
      await reveal.getByLabel(T(lng, "enroll.key.saved")).check();
      await close.click();
      await expect(reveal).toHaveCount(0);
      await checkNoSecrets(context, guard, "key-closed", [key]);
      const state = await ctlUntil<{ state: string }>("client_state", { client: joined.client }, (r) => r.state === "Running");
      expect(state.state, "client dùng pre-auth key ⇒ Running").toBe("Running");
      await page.reload();
      await settle(page, lng);
      await expect(row(page.getByTestId("all-requests"), label)).toBeVisible({ timeout: 60_000 });
      await checkNoSecrets(context, guard, "key-reload", [key]);

      // thu hồi hai pha một key chưa dùng: hộp xác nhận (Esc/Hủy không gửi) rồi xác nhận ⇒ "đã thu hồi" khi control plane xác nhận
      await issueKey(spare);
      const spareKey = ((await reveal.getByTestId("secret-value").textContent()) ?? "").trim();
      expect(spareKey).toMatch(/^hskey-auth-/);
      await reveal.getByLabel(T(lng, "enroll.key.saved")).check();
      await reveal.getByRole("button", { name: T(lng, "enroll.key.close") }).click();
      const spareRow = row(page.getByTestId("all-requests"), spare);
      await expect(spareRow).toHaveAttribute("data-status", "issued", { timeout: 60_000 });
      const revoke = spareRow.getByRole("button", { name: Tv(lng, "enroll.actions.revokeFor", { label: spare }) });
      await checkDestructiveConfirm(page, testInfo, {
        label: "key-revoke",
        open: () => revoke.click(),
        title: Tv(lng, "enroll.actions.title.revoke", { label: spare }),
        mentions: [T(lng, "enroll.actions.desc.revoke")],
        confirm: T(lng, "enroll.actions.revoke"),
      });
      await revoke.click();
      // bucket `enrollment` (5 + 1/5 s mỗi danh tính): 429 ⇒ hộp giữ nguyên với lỗi ⇒ bấm lại
      const revoked = page.getByTestId("enroll-done").filter({ hasText: Tv(lng, "enroll.actions.done.revoke", { label: spare }) });
      await clickUntil(page, lng, confirmDialog(page).getByRole("button", { name: T(lng, "enroll.actions.revoke"), exact: true }), revoked);
      await expect(spareRow).toHaveAttribute("data-status", "revoked", { timeout: 60_000 });
      await checkNoSecrets(context, guard, "key-revoked", [key, spareKey]);
    } finally {
      await ctl("cleanup", { clients, prefixes: [label] });
    }
  });

  test("End-to-end với client thật: claim ⇒ thiết bị hiện ở Devices ⇒ xóa thiết bị hai pha (đang chờ ⇒ Headscale xác nhận ⇒ đã xóa), node rời Headscale", async ({ page, context, guard }, testInfo) => {
    const lng = lngOf(testInfo);
    const label = uniq("e", lng);
    const clients: string[] = [];
    try {
      await page.goto(`${APP}/t/${A}/enroll`);
      await settle(page, lng);
      await requestWebAuth(page, lng, label, page.getByTestId("issued-web"));
      const hostname = await issuedHostname(page, lng);
      const web = await ctl<WebClient>("webauth_client", { tag: `e-${label.slice(-6)}`, hostname });
      clients.push(web.client);
      const { page: claim } = await openClientLink({ context }, web.link);
      await confirmClaim(claim, lng, claim.getByTestId("claim-verified"));
      await claim.getByRole("link", { name: T(lng, "enroll.claim.toDevices") }).click();
      await expect(claim).toHaveURL(`${APP}/t/${A}/devices`);
      // sổ thiết bị: claim ghi hàng (enrollment_request_id) + inventory.sync — có thể trễ một nhịp
      const link = claim.locator("main tbody a", { hasText: label });
      for (let i = 0; i < 12 && !(await link.isVisible()); i++) {
        await claim.waitForTimeout(5_000);
        await claim.reload();
        await settle(claim, lng);
      }
      await expect(link).toBeVisible();
      await checkScreen(claim, testInfo, "devices-with-new");
      await link.click();
      await expect(claim.locator("h1")).toHaveText(label);
      await checkScreen(claim, testInfo, "device-new");
      await expect(claim.getByTestId("revocation-panel")).toHaveCount(0);
      const node = await ctl<{ nodes: { given_name: string }[] }>("nodes", { prefixes: [label] });
      expect(node.nodes.map((n) => n.given_name)).toEqual([label]);

      // xóa: hộp xác nhận nêu thiết bị + hậu quả + hai pha; Esc/Hủy không gửi
      const del = claim.getByRole("button", { name: T(lng, "devices.revoke.delete"), exact: true });
      await checkDestructiveConfirm(claim, testInfo, {
        label: "device-delete",
        open: () => del.click(),
        title: Tv(lng, "devices.revoke.confirmDeleteTitle", { name: label }),
        mentions: [T(lng, "devices.revoke.confirmDelete"), T(lng, "devices.revoke.twoPhase")],
        confirm: T(lng, "devices.revoke.delete"),
      });
      await del.click();
      await confirmDialog(claim).getByRole("button", { name: T(lng, "devices.revoke.delete"), exact: true }).click();
      // pha 1: 202 + revocation pending ⇒ "đang chờ … CHƯA bị thu hồi" (không khẳng định quá)
      const kind = T(lng, "devices.revocation.kind.delete");
      await expect(claim.getByTestId("revocation-panel")).toContainText(Tv(lng, "devices.revocation.explain.pending", { kind }), { timeout: 10_000 });
      await expect(claim.getByTestId("revocation-state")).toHaveText(Tv(lng, "devices.revocation.state.pending", { kind }));
      await checkA11y(claim, testInfo, "device-delete-pending");
      // pha 2: chỉ báo "đã xóa" khi Headscale xác nhận (thiết bị rời sổ ⇒ 404)
      await expect(claim.getByTestId("device-deleted")).toHaveText(T(lng, "devices.deleted.description"), { timeout: 90_000 });
      await checkScreen(claim, testInfo, "device-deleted");
      const after = await ctl<{ nodes: unknown[] }>("nodes", { prefixes: [label] });
      expect(after.nodes, "node không còn ở Headscale").toEqual([]);
      await checkNoSecrets(context, guard, "device-deleted", [hostname]);
    } finally {
      await revokeIfIssued(page, label);
      await ctl("cleanup", { clients, prefixes: [label] });
    }
  });
});

// ================================================================================================ hàng chờ duyệt
test.describe("enrollment — hàng chờ duyệt", () => {
  test("Hàng chờ duyệt: End User tạo yêu cầu (tenant bật duyệt) ⇒ chờ duyệt, không có nút duyệt của chính mình; Tenant Admin duyệt một, từ chối một (hộp xác nhận); người yêu cầu nhận lệnh (/start)", async ({ browser, guard }, testInfo) => {
    const lng = lngOf(testInfo);
    const ok = uniq("qa", lng);
    const no = uniq("qr", lng);
    let member: Actor | null = null;
    let admin: Actor | null = null;
    try {
      member = await newActor(browser, testInfo, guard, "member");
      admin = await newActor(browser, testInfo, guard, "admin");
      const m = member.page;
      await m.goto(`${APP}/t/${A}/enroll`);
      await settle(m, lng);
      const mine = m.getByTestId("my-requests");
      await requestWebAuth(m, lng, ok, row(mine, ok));
      await expect(m.getByTestId("pending-approval")).toContainText(T(lng, "enroll.pendingApproval.title"));
      await requestWebAuth(m, lng, no, row(mine, no));
      for (const l of [ok, no]) {
        const r = row(mine, l);
        await expect(r).toHaveAttribute("data-status", "pending_approval", { timeout: 60_000 });
        // người yêu cầu (End User, không có quyền duyệt) không có nút duyệt/từ chối trên yêu cầu của mình
        await expect(r.getByRole("button", { name: lit(T(lng, "enroll.actions.approve")) })).toHaveCount(0);
        await expect(r.getByRole("button", { name: lit(T(lng, "enroll.actions.reject")) })).toHaveCount(0);
      }
      await checkScreen(m, testInfo, "enroll-pending-approval");

      const a = admin.page;
      await a.goto(`${APP}/t/${A}/enrollment-keys`);
      await checkScreen(a, testInfo, "approval-queue");
      const queue = a.getByTestId("approval-queue");
      const approve = row(queue, ok).getByRole("button", { name: Tv(lng, "enroll.actions.approveFor", { label: ok }) });
      await expect(approve).toBeVisible({ timeout: 60_000 });
      await approve.click();
      const dlg = confirmDialog(a);
      await expect(dlg.getByRole("heading")).toHaveText(Tv(lng, "enroll.actions.title.approve", { label: ok }));
      await expect(dlg).toContainText(T(lng, "enroll.actions.desc.approve"));
      await checkA11y(a, testInfo, "approve-dialog");
      const approved = a.getByTestId("enroll-done").filter({ hasText: Tv(lng, "enroll.actions.done.approve", { label: ok }) });
      await clickUntil(a, lng, dlg.getByRole("button", { name: T(lng, "enroll.actions.approve"), exact: true }), approved);
      const reject = row(queue, no).getByRole("button", { name: Tv(lng, "enroll.actions.rejectFor", { label: no }) });
      await checkDestructiveConfirm(a, testInfo, {
        label: "enroll-reject",
        open: () => reject.click(),
        title: Tv(lng, "enroll.actions.title.reject", { label: no }),
        mentions: [T(lng, "enroll.actions.desc.reject")],
        confirm: T(lng, "enroll.actions.reject"),
      });
      await reject.click();
      const rejected = a.getByTestId("enroll-done").filter({ hasText: Tv(lng, "enroll.actions.done.reject", { label: no }) });
      await clickUntil(a, lng, dlg.getByRole("button", { name: T(lng, "enroll.actions.reject"), exact: true }), rejected);

      // người yêu cầu: được duyệt ⇒ nhận lệnh (/start) MỘT lần; bị từ chối ⇒ kết thúc
      await m.reload();
      await settle(m, lng);
      await expect(row(mine, no)).toHaveAttribute("data-status", "rejected", { timeout: 60_000 });
      const start = row(mine, ok).getByRole("button", { name: Tv(lng, "enroll.actions.startWebFor", { label: ok }) });
      await clickUntil(m, lng, start, m.getByTestId("issued-web"));
      await issuedHostname(m, lng);
      await checkA11y(m, testInfo, "enroll-started");
      // dọn: Tenant Admin thu hồi yêu cầu đã phát (thiết bị không chạy lệnh)
      await a.reload();
      await settle(a, lng);
      const all = a.getByTestId("all-requests");
      const revoke = row(all, ok).getByRole("button", { name: Tv(lng, "enroll.actions.revokeFor", { label: ok }) });
      await expect(revoke).toBeVisible({ timeout: 60_000 });
      await revoke.click();
      const gone = a.getByTestId("enroll-done").filter({ hasText: Tv(lng, "enroll.actions.done.revoke", { label: ok }) });
      await clickUntil(a, lng, dlg.getByRole("button", { name: T(lng, "enroll.actions.revoke"), exact: true }), gone);
      await expect(row(all, ok)).toHaveAttribute("data-status", "revoked", { timeout: 60_000 });
      await checkNoSecrets(member.context, guard, "queue-member");
      await checkNoSecrets(admin.context, guard, "queue-admin");
    } finally {
      await closeAll([member, admin]);
    }
  });
});
