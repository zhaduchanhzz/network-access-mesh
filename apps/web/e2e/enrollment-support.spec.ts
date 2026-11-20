// C4 (Support Access Grant — migration 0028; G4b — P4-T14) trong trình duyệt thật: Super Admin xin grant support_operator
// cho tenant-a (step-up: auth_time của phiên mới bị đẩy về quá 15 phút ⇒ 401 ⇒ xác thực lại ⇒ gửi lại), Tenant Owner duyệt
// (step-up trong hộp xác nhận), nhân viên (admin., role hiệu lực của grant) thấy nút Duyệt/Từ chối theo rbac và duyệt yêu
// cầu enrollment của End User ⇒ hàng hiện "bởi nhân viên hỗ trợ của nền tảng" ở cả hai phía; Owner thu hồi grant (hộp xác
// nhận) ⇒ lần duyệt kế tiếp của nhân viên (trang chưa tải lại) ⇒ 403 + thông báo grant đã kết thúc, yêu cầu không đổi.
// Đăng nhập mới + step-up: mật khẩu nằm trong thao tác fill ⇒ không trace cho file này.
import { ADMIN, APP, cfg } from "./env";
import { closeAll, requestWebAuth, row } from "./enroll";
import {
  ageSession,
  checkA11y,
  checkDestructiveConfirm,
  checkI18n,
  checkNoSecrets,
  checkScreen,
  clickUntil,
  confirmDialog,
  ctl,
  expect,
  lngOf,
  login,
  newActor,
  settle,
  stepUp,
  T,
  test,
  Tv,
  uniq,
  type Actor,
} from "./support";

test.use({ trace: "off" });

const A = cfg.tenantA.id;

// ================================================================================================ C4 — Support Access Grant
test.describe("enrollment — C4: nhân viên nền tảng có Support Access Grant", () => {
  test("C4: Super Admin xin grant (step-up) ⇒ Owner duyệt (step-up) ⇒ nhân viên duyệt yêu cầu enrollment của End User từ admin. ⇒ 'bởi nhân viên hỗ trợ'; Owner thu hồi grant ⇒ lần duyệt kế tiếp ⇒ 403 + thông báo grant đã kết thúc", async ({ browser, guard }, testInfo) => {
    const lng = lngOf(testInfo);
    const ticket = `PW-${lng}-${uniq("t", lng).slice(-6)}`;
    const first = uniq("sa", lng);
    const second = uniq("sb", lng);
    const actors: (Actor | null)[] = [];
    try {
      // 1. Super Admin (phiên mới, auth_time đã cũ) xin grant support_operator cho tenant-a ⇒ 401 ⇒ step-up ⇒ gửi lại ⇒ pending
      const sa = await newActor(browser, testInfo, guard, null);
      actors.push(sa);
      await login(sa.page, "sa", lng);
      await sa.page.goto(`${ADMIN}/platform/support-access`);
      await settle(sa.page, lng);
      await ageSession(sa.page);
      const fill = async () => {
        await expect(sa.page.locator("#grant-tenant option", { hasText: cfg.tenantA.slug })).toHaveCount(1, { timeout: 30_000 });
        await sa.page.locator("#grant-tenant").selectOption(A);
        await sa.page.locator("#grant-role").selectOption("support_operator");
        await sa.page.locator("#grant-duration").selectOption("30");
        await sa.page.getByLabel(T(lng, "support.ticket")).fill(ticket);
        await sa.page.getByLabel(T(lng, "support.reason")).fill(`P4-T14 G4b C4 ${lng}`);
        await sa.page.getByRole("button", { name: T(lng, "support.request"), exact: true }).click();
      };
      await fill();
      const prompt = sa.page.getByRole("alertdialog").filter({ hasText: T(lng, "stepUp.title") });
      await expect(prompt).toContainText(T(lng, "stepUp.description"));
      await expect(sa.page.getByRole("alert").filter({ hasText: T(lng, "problem.reauth_required") })).toBeVisible();
      await checkA11y(sa.page, testInfo, "stepup-platform");
      await stepUp(sa.page, "sa", prompt.getByRole("button", { name: T(lng, "stepUp.action") }));
      await settle(sa.page, lng);
      await fill();
      await expect(sa.page.getByRole("status").filter({ hasText: T(lng, "support.requested") })).toBeVisible({ timeout: 30_000 });
      const saRow = sa.page.getByTestId("grant-row").filter({ hasText: ticket });
      await expect(saRow.getByTestId("grant-status")).toHaveText(T(lng, "support.status.pending"));
      await checkNoSecrets(sa.context, guard, "stepup-platform");

      // 2. Owner (phiên mới, auth_time đã cũ) duyệt ⇒ 401 trong hộp ⇒ "Xác thực lại" ⇒ duyệt lại ⇒ approved
      const owner = await newActor(browser, testInfo, guard, null);
      actors.push(owner);
      await login(owner.page, "owner", lng);
      await owner.page.goto(`${APP}/t/${A}/support-access`);
      await settle(owner.page, lng);
      await ageSession(owner.page);
      const grantRow = owner.page.getByTestId("grant-row").filter({ hasText: ticket });
      await grantRow.getByRole("button", { name: T(lng, "support.approve"), exact: true }).click();
      const odlg = confirmDialog(owner.page);
      await expect(odlg.getByRole("heading")).toHaveText(T(lng, "support.confirm.approveTitle"));
      await odlg.getByRole("button", { name: T(lng, "support.approve"), exact: true }).click();
      await expect(odlg.getByRole("alert")).toContainText(T(lng, "problem.reauth_required"));
      await checkA11y(owner.page, testInfo, "stepup-dialog");
      await stepUp(owner.page, "owner", odlg.getByRole("button", { name: T(lng, "stepUp.action") }));
      await settle(owner.page, lng);
      await grantRow.getByRole("button", { name: T(lng, "support.approve"), exact: true }).click();
      await odlg.getByRole("button", { name: T(lng, "support.approve"), exact: true }).click();
      await expect(odlg).toHaveCount(0, { timeout: 30_000 });
      await expect(grantRow.getByTestId("grant-status")).toHaveText(T(lng, "support.status.approved"));

      // 3. End User tạo hai yêu cầu (chờ duyệt)
      const member = await newActor(browser, testInfo, guard, "member");
      actors.push(member);
      await member.page.goto(`${APP}/t/${A}/enroll`);
      await settle(member.page, lng);
      await requestWebAuth(member.page, lng, first, row(member.page.getByTestId("my-requests"), first));
      await expect(member.page.getByTestId("pending-approval")).toContainText(T(lng, "enroll.pendingApproval.title"));

      // 4. nhân viên (admin., grant support_operator) thấy nút Duyệt/Từ chối theo rbac của role hiệu lực ⇒ duyệt
      await sa.page.goto(`${ADMIN}/t/${A}/enrollment-keys`);
      await checkScreen(sa.page, testInfo, "support-enrollment-keys");
      await expect(sa.page.getByRole("button", { name: T(lng, "enroll.key.create"), exact: true })).toHaveCount(0);
      const queue = sa.page.getByTestId("approval-queue");
      await expect(row(queue, first).getByRole("button", { name: Tv(lng, "enroll.actions.rejectFor", { label: first }) })).toBeVisible({ timeout: 60_000 });
      await row(queue, first).getByRole("button", { name: Tv(lng, "enroll.actions.approveFor", { label: first }) }).click();
      const sdlg = confirmDialog(sa.page);
      const approved = sa.page.getByTestId("enroll-done").filter({ hasText: Tv(lng, "enroll.actions.done.approve", { label: first }) });
      await clickUntil(sa.page, lng, sdlg.getByRole("button", { name: T(lng, "enroll.actions.approve"), exact: true }), approved);
      const decided = row(sa.page.getByTestId("all-requests"), first);
      await expect(decided).toHaveAttribute("data-status", "approved", { timeout: 60_000 });
      await expect(decided.getByTestId("decided-by-support")).toHaveText(T(lng, "enroll.decider.supportApproved"));
      // phía tenant: người yêu cầu thấy được duyệt bởi nhân viên hỗ trợ
      await member.page.reload();
      await settle(member.page, lng);
      const mineRow = row(member.page.getByTestId("my-requests"), first);
      await expect(mineRow).toHaveAttribute("data-status", "approved", { timeout: 60_000 });
      await expect(mineRow.getByTestId("decided-by-support")).toHaveText(T(lng, "enroll.decider.supportApproved"));
      await checkScreen(member.page, testInfo, "member-approved-by-support");

      // 5. yêu cầu thứ hai; Owner thu hồi grant (hộp xác nhận — Esc/Hủy không gửi); nhân viên (trang chưa tải lại) duyệt ⇒ 403
      await requestWebAuth(member.page, lng, second, row(member.page.getByTestId("my-requests"), second));
      await sa.page.reload();
      await settle(sa.page, lng);
      const approveSecond = row(queue, second).getByRole("button", { name: Tv(lng, "enroll.actions.approveFor", { label: second }) });
      await expect(approveSecond).toBeVisible({ timeout: 60_000 });
      const revoke = grantRow.getByRole("button", { name: T(lng, "support.revoke"), exact: true });
      await checkDestructiveConfirm(owner.page, testInfo, {
        label: "grant-revoke",
        open: () => revoke.click(),
        title: T(lng, "support.confirm.revokeTitle"),
        mentions: [ticket],
        confirm: T(lng, "support.revoke"),
      });
      await revoke.click();
      await odlg.getByRole("button", { name: T(lng, "support.revoke"), exact: true }).click();
      await expect(grantRow.getByTestId("grant-status")).toHaveText(T(lng, "support.status.revoked"), { timeout: 30_000 });
      await approveSecond.click();
      const refused = sdlg.getByRole("alert").filter({ hasText: T(lng, "problem.forbidden") });
      await clickUntil(sa.page, lng, sdlg.getByRole("button", { name: T(lng, "enroll.actions.approve"), exact: true }), refused);
      await expect(sdlg.getByTestId("support-grant-ended")).toContainText(T(lng, "support.grantEnded"));
      await checkA11y(sa.page, testInfo, "support-grant-ended");
      await checkI18n(sa.page, lng, "support-grant-ended");
      await sa.page.keyboard.press("Escape");
      await expect(sdlg).toHaveCount(0);
      await expect(sa.page.getByTestId("enroll-done").filter({ hasText: second })).toHaveCount(0);

      // 6. dọn: Owner từ chối yêu cầu thứ hai (vẫn chờ duyệt — quyết định của nhân viên không có hiệu lực)
      await owner.page.goto(`${APP}/t/${A}/enrollment-keys`);
      await settle(owner.page, lng);
      const oq = owner.page.getByTestId("approval-queue");
      await row(oq, second).getByRole("button", { name: Tv(lng, "enroll.actions.rejectFor", { label: second }) }).click({ timeout: 60_000 });
      const rejected = owner.page.getByTestId("enroll-done").filter({ hasText: Tv(lng, "enroll.actions.done.reject", { label: second }) });
      await clickUntil(owner.page, lng, confirmDialog(owner.page).getByRole("button", { name: T(lng, "enroll.actions.reject"), exact: true }), rejected);
      for (const a of actors) if (a) await checkNoSecrets(a.context, guard, "c4");
    } finally {
      await closeAll(actors);
      await ctl("grants_cleanup");
    }
  });
});

