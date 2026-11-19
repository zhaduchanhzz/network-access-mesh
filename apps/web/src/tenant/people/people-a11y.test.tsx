// a11y + i18n của Users / Groups / Invitations (P4-T09a): axe-core (WCAG 2.0/2.1 A + AA + best-practice; color-contrast
// kiểm trong trình duyệt thật ở P4-T14) trên danh sách, chi tiết + hộp xác nhận, hộp mời, trình sửa thành viên, bảng phê
// duyệt — vi và en; bàn phím: hộp offboard mở bằng Enter, focus vào ô gõ xác nhận, Esc đóng và trả focus; khóa i18n động.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { describe, expect, it } from "vitest";
import { i18n } from "../../i18n";
import en from "../../i18n/locales/en.json";
import vi from "../../i18n/locales/vi.json";
import { json, mockApi, renderApp, TENANT_A, tenantBody, tenantSession } from "../../test/helpers";
import { approval, APPROVAL_1, END_USER, group, GROUP_1, INV_1, invitation, INVITE_JOB, job, MEMBERS, OFFBOARD_JOB } from "../../test/people";
import { INVITATION_STATUSES, MEMBERSHIP_STATUSES, OFFBOARD_STATES, TENANT_ROLES } from "./model";

async function violations(): Promise<string[]> {
  const r = await axe.run(document.body, {
    runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"] },
    rules: { "color-contrast": { enabled: false } },
  });
  return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
}

const base = `/tenants/${TENANT_A}`;
const pendingOffboard = { ...MEMBERS.endUser, status: "offboarded", offboarding: { state: "pending" as const, job_id: OFFBOARD_JOB } };
const api = {
  "GET /auth/session": json(200, tenantSession([{ tenantId: TENANT_A, slug: "tenant-a", name: "Tenant A", role: "tenant_owner" }])),
  [`GET ${base}`]: json(200, tenantBody(TENANT_A, "tenant-a")),
  [`GET ${base}/notifications`]: json(200, { items: [], next_cursor: null }),
  [`GET ${base}/users`]: json(200, { items: [MEMBERS.me("tenant_owner"), MEMBERS.admin2, MEMBERS.offboarded, pendingOffboard], next_cursor: "c2" }),
  [`GET ${base}/users/${MEMBERS.operator.id}`]: json(200, MEMBERS.operator, { ETag: '"3"' }),
  [`GET ${base}/users/${END_USER}`]: json(200, pendingOffboard, { ETag: '"3"' }),
  [`GET ${base}/jobs/${OFFBOARD_JOB}`]: json(200, job(OFFBOARD_JOB, "member.offboard", "running")),
  [`GET ${base}/jobs`]: json(200, { items: [job(INVITE_JOB, "member.idp_invite", "succeeded", { type: "invitation", id: INV_1 })], next_cursor: null }),
  [`GET ${base}/invitations`]: json(200, { items: [invitation(INV_1, "end_user"), invitation("0190d300-0000-7000-8000-000000000003", "tenant_admin", { status: "expired" })], next_cursor: null }),
  [`GET ${base}/groups`]: json(200, { items: [group({ sensitive: true }), group({ id: "0190d200-0000-7000-8000-000000000002", name: "ops" })], next_cursor: null }),
  [`GET ${base}/groups/${GROUP_1}`]: json(200, group({ sensitive: true }), { ETag: '"4"' }),
  [`GET ${base}/approvals`]: json(200, { items: [approval()], next_cursor: null }),
  [`GET ${base}/approvals/${APPROVAL_1}`]: json(200, approval()),
};

describe.each(["vi", "en"] as const)("axe Users/Groups/Invitations (%s)", (lng) => {
  it.each([
    ["users", "users-table"],
    ["invitations", "invitations-table"],
    ["groups", "groups-table"],
  ])("%s", async (path, testId) => {
    await i18n.changeLanguage(lng);
    mockApi(api);
    renderApp({ path: `/t/${TENANT_A}/${path}` });
    await screen.findByTestId(testId);
    expect(await violations()).toEqual([]);
  });

  it("chi tiết thành viên (Owner xem Operator) + hộp offboard; bàn phím", async () => {
    await i18n.changeLanguage(lng);
    mockApi(api);
    renderApp({ path: `/t/${TENANT_A}/users/${MEMBERS.operator.id}` });
    const open = await screen.findByRole("button", { name: "Offboard…" });
    expect(await violations()).toEqual([]);
    open.focus();
    await userEvent.keyboard("{Enter}");
    const d = await screen.findByRole("alertdialog");
    expect(within(d).getByRole("textbox")).toHaveFocus();
    expect(await violations()).toEqual([]);
    await userEvent.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(open).toHaveFocus();
  });

  it("offboard đang chạy (pha 2)", async () => {
    await i18n.changeLanguage(lng);
    mockApi(api);
    renderApp({ path: `/t/${TENANT_A}/users/${END_USER}` });
    await screen.findByTestId("offboard-panel");
    expect(await violations()).toEqual([]);
  });

  it("hộp mời", async () => {
    await i18n.changeLanguage(lng);
    mockApi(api);
    renderApp({ path: `/t/${TENANT_A}/invitations` });
    await screen.findByTestId("invitations-table");
    await userEvent.click(screen.getAllByRole("button").find((b) => b.className.includes("btn-primary"))!);
    await screen.findByRole("dialog");
    expect(await violations()).toEqual([]);
  });

  it("chi tiết group sensitive + yêu cầu đang chờ + trình sửa thành viên", async () => {
    await i18n.changeLanguage(lng);
    mockApi(api);
    renderApp({ path: `/t/${TENANT_A}/groups/${GROUP_1}` });
    await screen.findByTestId("group-pending-approvals");
    expect(await violations()).toEqual([]);
    await userEvent.click(screen.getByRole("button", { name: lng === "vi" ? "Sửa thành viên" : "Edit members" }));
    await screen.findByTestId("members-editor");
    expect(await violations()).toEqual([]);
  });
});

type Tree = { [k: string]: string | Tree };
function has(tree: Tree, key: string): boolean {
  let node: string | Tree | undefined = tree;
  for (const part of key.split(".")) {
    if (typeof node !== "object") return false;
    node = node[part] ?? node[`${part}_other`];
  }
  return typeof node === "string";
}

describe("khóa i18n động của P4-T09a", () => {
  it("trạng thái, role, nguồn group, trạng thái phê duyệt có trong vi và en", () => {
    const keys = [
      ...MEMBERSHIP_STATUSES.map((s) => `people.status.${s}`),
      ...INVITATION_STATUSES.map((s) => `people.invitationStatus.${s}`),
      ...OFFBOARD_STATES.flatMap((s) => [`people.offboard.state.${s}`, `people.offboard.explain.${s}`]),
      ...TENANT_ROLES.map((r) => `roles.${r}`),
      ...["portal", "idp"].map((s) => `people.groups.sources.${s}`),
      ...["pending", "approved", "rejected", "expired", "executed"].flatMap((s) => [`people.approval.explain.${s}`, `status.approval.${s}`]),
    ];
    expect(keys.filter((k) => !has(vi as Tree, k) || !has(en as Tree, k))).toEqual([]);
  });
});
