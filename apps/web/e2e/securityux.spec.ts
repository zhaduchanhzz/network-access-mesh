// Rà soát UX bảo mật của G4b (§19 Phase 4 — Go/No-Go G4b) trong trình duyệt thật, hai ngôn ngữ:
//   (b) lời nhắc step-up: securityux-stepup.spec.ts (đổi role chạm Tenant Admin) và enrollment-support.spec.ts (xin + duyệt
//       Support Access Grant) — file riêng vì đăng nhập mới (không trace);
//   (c) cách diễn đạt trạng thái hai pha — offboard (pending ⇒ "CHƯA chắc", applied ⇒ đã xác minh), policy "đã áp dụng lên
//       Headscale" tách khỏi "client đã hội tụ" (không quan sát được); xóa thiết bị: enrollment.spec.ts;
//   (d) không secret trong DOM/URL/storage/console — checkNoSecrets sau mỗi luồng; client secret của IdP chỉ-ghi;
//   (e) xác nhận thao tác phá hủy — hộp nêu đối tượng + hậu quả, focus vào Hủy/ô gõ lại, Esc và Hủy không gửi gì:
//       thiết bị (expire, xóa), route (gỡ duyệt, duyệt), DNS record, tài nguyên, tag, group (gõ lại tên), lời mời, khóa /
//       thu hồi session / offboard thành viên (gõ lại email), xóa (deprovision, 2P, gõ lại slug) / tạm ngưng tenant.
// Đối tượng của (e) do harness tạo trước (playwrightui.prepare_network) và KHÔNG bị xóa (chỉ mở hộp rồi Esc/Hủy); đối tượng
// của step-up/offboard là thành viên dùng-một-lần (pwcontrol new_member).
import type { Page } from "@playwright/test";
import { ADMIN, APP, cfg, storageFile } from "./env";
import {
  checkA11y,
  checkDestructiveConfirm,
  checkNoSecrets,
  checkScreen,
  confirmDialog,
  ctl,
  expect,
  lngOf,
  settle,
  T,
  test,
  Tv,
} from "./support";

const A = cfg.tenantA.id;
const B = cfg.tenantB.id;
const F = cfg.fixtures;

interface Member {
  id: string;
  name: string;
  email: string;
}

async function openUser(page: Page, testInfo: Parameters<typeof checkScreen>[1], m: Member, label: string): Promise<void> {
  await page.goto(`${APP}/t/${A}/users/${m.id}`);
  await checkScreen(page, testInfo, label);
  await expect(page.locator("h1")).toHaveText(m.name);
}

// ================================================================================================ (c)(e) Tenant Owner
test.describe("G4b — xác nhận thao tác phá hủy, trạng thái hai pha (Tenant Owner)", () => {
  test.use({ storageState: storageFile("owner") });

  test("Thành viên: khóa / thu hồi session / offboard — hộp nêu tên + hậu quả, offboard gõ lại email; Esc/Hủy không gửi; offboard hai pha: 'CHƯA chắc' khi pending, 'đã xác minh' khi applied", async ({ page, context, guard }, testInfo) => {
    const lng = lngOf(testInfo);
    const m = await ctl<Member>("new_member");
    await openUser(page, testInfo, m, "user-offboard");
    await checkDestructiveConfirm(page, testInfo, {
      label: "member-lock",
      open: () => page.getByRole("button", { name: T(lng, "people.access.lock"), exact: true }).click(),
      title: Tv(lng, "people.access.lockTitle", { name: m.name }),
      mentions: [T(lng, "people.access.lockDesc")],
      confirm: T(lng, "people.access.lock"),
    });
    await checkDestructiveConfirm(page, testInfo, {
      label: "member-sessions",
      open: () => page.getByRole("button", { name: T(lng, "people.access.revokeSessions"), exact: true }).click(),
      title: Tv(lng, "people.access.sessionsTitle", { name: m.name }),
      mentions: [T(lng, "people.access.sessionsDesc")],
      confirm: T(lng, "people.access.revokeSessions"),
    });
    const expected = m.email || m.name;
    const open = page.getByRole("button", { name: T(lng, "people.offboard.open"), exact: true });
    const effects = ["sessions", "groups", "nodes", "idp"].map((k) => T(lng, `people.offboard.effects.${k}`));
    await checkDestructiveConfirm(page, testInfo, {
      label: "member-offboard",
      open: () => open.click(),
      title: Tv(lng, "people.offboard.confirmTitle", { name: m.name }),
      mentions: [T(lng, "people.offboard.confirmDesc"), ...effects, T(lng, "people.offboard.final")],
      confirm: T(lng, "people.offboard.submit"),
      typed: expected,
    });
    await open.click();
    const dlg = confirmDialog(page);
    await dlg.getByRole("textbox").last().fill(expected);
    await dlg.getByRole("button", { name: T(lng, "people.offboard.submit"), exact: true }).click();
    const panel = page.getByTestId("offboard-panel");
    await expect(panel).toBeVisible({ timeout: 30_000 });
    const first = await panel.getAttribute("data-state");
    if (first === "pending") {
      // pha 2 đang chạy: không khẳng định node/key đã hết hạn
      await expect(panel).toContainText(T(lng, "people.offboard.explain.pending"));
      await expect(panel).toContainText(T(lng, "people.offboard.state.pending"));
      await checkA11y(page, testInfo, "offboard-pending");
    }
    testInfo.annotations.push({ type: "offboard-first-state", description: first ?? "?" });
    await expect(panel).toHaveAttribute("data-state", "applied", { timeout: 180_000 });
    await expect(panel).toContainText(T(lng, "people.offboard.explain.applied"));
    await expect(panel).toContainText(T(lng, "people.offboard.state.applied"));
    await checkScreen(page, testInfo, "offboard-applied");
    await checkNoSecrets(context, guard, "offboard");
  });

  test("Thiết bị: thu hồi (expire) và xóa — hộp nêu tên thiết bị, hậu quả và hai pha; Esc/Hủy không gửi", async ({ page, context, guard }, testInfo) => {
    const lng = lngOf(testInfo);
    await page.goto(`${APP}/t/${A}/devices/${F.routeDeviceId}`);
    await checkScreen(page, testInfo, "device-fixture");
    await expect(page.getByText(T(lng, "devices.revoke.description"))).toBeVisible();
    for (const kind of ["expire", "delete"] as const) {
      const name = T(lng, kind === "delete" ? "devices.revoke.delete" : "devices.revoke.expire");
      await checkDestructiveConfirm(page, testInfo, {
        label: `device-${kind}`,
        open: () => page.getByRole("button", { name, exact: true }).click(),
        title: Tv(lng, kind === "delete" ? "devices.revoke.confirmDeleteTitle" : "devices.revoke.confirmExpireTitle", { name: F.routeDevice }),
        mentions: [T(lng, kind === "delete" ? "devices.revoke.confirmDelete" : "devices.revoke.confirmExpire"), T(lng, "devices.revoke.twoPhase")],
        confirm: name,
      });
    }
    await expect(page.getByTestId("revocation-panel")).toHaveCount(0);
    await checkNoSecrets(context, guard, "device-dialogs");
  });

  test("Route: gỡ duyệt (route đã duyệt) và duyệt (route đang chờ) — hộp nêu thiết bị + hậu quả; Esc/Hủy không gửi", async ({ page, context, guard }, testInfo) => {
    const lng = lngOf(testInfo);
    await page.goto(`${APP}/t/${A}/routes`);
    await checkScreen(page, testInfo, "routes-fixture");
    await expect(page.locator("main")).toContainText(F.routeApproved);
    await expect(page.locator("main")).toContainText(F.routePending);
    await checkDestructiveConfirm(page, testInfo, {
      label: "route-revoke",
      open: () => page.getByRole("button", { name: Tv(lng, "network.routes.revokeFor", { name: F.routeDevice }), exact: true }).click(),
      title: Tv(lng, "network.routes.dialog.revokeTitle", { name: F.routeDevice }),
      mentions: [T(lng, "network.routes.dialog.revokeDesc"), F.routeApproved],
      confirm: T(lng, "network.routes.revoke"),
      mustChoose: true,
      prepare: () => confirmDialog(page).getByRole("checkbox", { name: F.routeApproved }).check(),
    });
    await checkDestructiveConfirm(page, testInfo, {
      label: "route-approve",
      open: () => page.getByRole("button", { name: Tv(lng, "network.routes.approveFor", { name: F.routeDevice }), exact: true }).click(),
      title: Tv(lng, "network.routes.dialog.approveTitle", { name: F.routeDevice }),
      mentions: [T(lng, "network.routes.dialog.approveDesc"), F.routePending],
      confirm: T(lng, "network.routes.approve"),
    });
    await checkNoSecrets(context, guard, "route-dialogs");
  });

  test("DNS record, tài nguyên mạng, tag, group (gõ lại tên), lời mời — hộp xóa/thu hồi nêu đối tượng + hậu quả; Esc/Hủy không gửi", async ({ page, context, guard }, testInfo) => {
    const lng = lngOf(testInfo);
    await page.goto(`${APP}/t/${A}/dns`);
    await checkScreen(page, testInfo, "dns-fixture");
    await checkDestructiveConfirm(page, testInfo, {
      label: "dns-delete",
      open: () => page.getByRole("button", { name: Tv(lng, "network.dns.deleteFor", { name: F.dnsName, type: "A" }), exact: true }).click(),
      title: Tv(lng, "network.dns.deleteTitle", { name: F.dnsName, type: "A" }),
      mentions: [Tv(lng, "network.dns.deleteDesc", { value: F.dnsValue })],
      confirm: T(lng, "network.dns.delete"),
    });
    await page.goto(`${APP}/t/${A}/resources`);
    await checkScreen(page, testInfo, "resources-fixture");
    await checkDestructiveConfirm(page, testInfo, {
      label: "resource-delete",
      open: () => page.getByRole("button", { name: Tv(lng, "network.resources.deleteFor", { name: F.resource }), exact: true }).click(),
      title: Tv(lng, "network.resources.deleteTitle", { name: F.resource }),
      mentions: [T(lng, "network.resources.deleteDesc")],
      confirm: T(lng, "network.resources.delete"),
    });
    await page.goto(`${APP}/t/${A}/tags`);
    await checkScreen(page, testInfo, "tags-fixture");
    await checkDestructiveConfirm(page, testInfo, {
      label: "tag-delete",
      open: () => page.getByRole("button", { name: Tv(lng, "tags.deleteOf", { name: F.tag }), exact: true }).click(),
      title: Tv(lng, "tags.deleteTitle", { name: F.tag }),
      mentions: [T(lng, "tags.deleteDescription")],
      confirm: T(lng, "tags.delete"),
    });
    await page.goto(`${APP}/t/${A}/invitations`);
    await checkScreen(page, testInfo, "invitations-fixture");
    const inv = page.locator("main tbody tr", { hasText: F.invitation });
    await checkDestructiveConfirm(page, testInfo, {
      label: "invitation-revoke",
      open: () => inv.getByRole("button", { name: T(lng, "people.invitations.revoke"), exact: true }).click(),
      title: Tv(lng, "people.invitations.revokeTitle", { email: F.invitation }),
      mentions: [T(lng, "people.invitations.revokeDesc")],
      confirm: T(lng, "people.invitations.revoke"),
    });
    await page.goto(`${APP}/t/${A}/groups`);
    await settle(page, lng);
    const group = page.locator("main tbody a", { hasText: /^pw-group-/ }).first();
    const groupName = ((await group.textContent()) ?? "").trim();
    await group.click();
    await checkScreen(page, testInfo, "group-fixture");
    await checkDestructiveConfirm(page, testInfo, {
      label: "group-delete",
      open: () => page.getByRole("button", { name: T(lng, "people.groups.delete"), exact: true }).click(),
      title: Tv(lng, "people.groups.deleteConfirmTitle", { name: groupName }),
      mentions: [T(lng, "people.groups.typeName")],
      confirm: T(lng, "people.groups.delete"),
      typed: groupName,
    });
    await checkNoSecrets(context, guard, "network-dialogs");
  });

  test("Policy: 'đã áp dụng lên Headscale' tách khỏi 'client đã hội tụ' (không quan sát được) — không khẳng định quá", async ({ page, context, guard }, testInfo) => {
    const lng = lngOf(testInfo);
    await page.goto(`${APP}/t/${A}/policies`);
    await checkScreen(page, testInfo, "policies-current");
    const current = page.getByTestId("policy-current");
    const applied = current.getByTestId("current-applied");
    await expect(applied).toHaveAttribute("data-state", "applied");
    await expect(applied).toContainText(T(lng, "policies.applied.states.applied"));
    await expect(applied).toContainText(T(lng, "policies.applied.at"));
    await expect(applied).toContainText(T(lng, "policies.applied.sha"));
    // "client đã hội tụ" là một mục riêng, luôn "không quan sát được" — không bao giờ suy ra từ lần áp dụng
    await expect(current).toContainText(T(lng, "policies.current.converged"));
    await expect(current).toContainText(T(lng, "policies.current.convergedUnknown"));
    await checkNoSecrets(context, guard, "policies");
  });

  test("Client secret của IdP (tenant) chỉ-ghi: chỉ hiện 'đã đặt/chưa đặt', ô nhập (nếu có) là password trống", async ({ page, context, guard }, testInfo) => {
    const lng = lngOf(testInfo);
    await page.goto(`${APP}/t/${A}/identity-provider`);
    await checkScreen(page, testInfo, "tenant-idp-secret");
    const main = page.locator("main");
    await expect(main.getByText(new RegExp(`^(${[T(lng, "idp.secretSet"), T(lng, "idp.secretUnset")].map((s) => s.replace(/[()]/g, "\\$&")).join("|")})$`))).toHaveCount(1);
    const input = page.locator("#idp-secret");
    if ((await input.count()) > 0) {
      await expect(input).toHaveAttribute("type", "password");
      await expect(input).toHaveAttribute("autocomplete", "new-password");
      await expect(input).toHaveValue("");
    }
    await checkNoSecrets(context, guard, "tenant-idp");
  });
});

// ================================================================================================ (e) Platform Super Admin
test.describe("G4b — xác nhận thao tác phá hủy (Super Admin)", () => {
  test.use({ storageState: storageFile("sa") });

  test("Tenant: xin xóa (deprovision, 2P — gõ lại slug + lý do) và tạm ngưng — hộp nêu slug + hậu quả; Esc/Hủy không gửi", async ({ page, context, guard }, testInfo) => {
    const lng = lngOf(testInfo);
    const slug = cfg.tenantB.slug;
    await page.goto(`${ADMIN}/platform/tenants/${B}`);
    await checkScreen(page, testInfo, "tenant-b-detail");
    await checkDestructiveConfirm(page, testInfo, {
      label: "tenant-delete",
      open: () => page.getByRole("button", { name: T(lng, "platform.tenantDetail.delete"), exact: true }).click(),
      prepare: () => confirmDialog(page).getByLabel(T(lng, "platform.tenantDetail.reason")).fill("P4-T14 G4b — không gửi"),
      title: Tv(lng, "platform.tenantDetail.deleteTitle", { slug }),
      mentions: [T(lng, "platform.tenantDetail.deleteDesc"), T(lng, "platform.tenantDetail.deleteTwoPerson")],
      confirm: T(lng, "platform.tenantDetail.deleteConfirm"),
      typed: slug,
    });
    await checkDestructiveConfirm(page, testInfo, {
      label: "tenant-suspend",
      open: () => page.getByRole("button", { name: T(lng, "platform.tenantDetail.suspend"), exact: true }).click(),
      title: Tv(lng, "platform.tenantDetail.suspendTitle", { slug }),
      mentions: [T(lng, "platform.tenantDetail.suspendDesc")],
      confirm: T(lng, "platform.tenantDetail.suspend"),
    });
    await checkNoSecrets(context, guard, "tenant-dialogs");
  });

  test("Client secret của IdP (nền tảng) chỉ-ghi: chỉ hiện 'đã đặt/chưa đặt'", async ({ page, context, guard }, testInfo) => {
    const lng = lngOf(testInfo);
    await page.goto(`${ADMIN}/platform/identity-providers`);
    await settle(page, lng);
    await page.locator('main tbody a[href^="/platform/identity-providers/"]').first().click();
    await checkScreen(page, testInfo, "platform-idp-secret");
    await expect(page.locator("main").getByText(new RegExp(`^(${[T(lng, "platform.idp.secretSet"), T(lng, "platform.idp.secretUnset")].map((s) => s.replace(/[()]/g, "\\$&")).join("|")})$`))).toHaveCount(1);
    await expect(page.locator('main input[type="text"][name*="secret" i], main input[id*="secret" i]:not([type="password"])')).toHaveCount(0);
    await checkNoSecrets(context, guard, "platform-idp");
  });
});
