// a11y + i18n của màn hình enrollment (P4-T08): axe-core (WCAG 2.0/2.1 A + AA + best-practice; color-contrast kiểm trong
// trình duyệt thật ở P4-T14) trên Thêm thiết bị (wizard, hướng dẫn Windows, lệnh web-auth vừa phát, ô dán link), hộp key
// một lần, trang claim (xác nhận + cảnh báo phishing + yêu cầu đã kết thúc), Enrollment key (hàng chờ duyệt + hộp tạo key đặc quyền) — vi và en,
// sáng và tối; khóa i18n động có trong cả hai catalog.
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { describe, expect, it } from "vitest";
import { i18n } from "../../i18n";
import en from "../../i18n/locales/en.json";
import vi from "../../i18n/locales/vi.json";
import { json, mockApi, problem, renderApp, TENANT_A, tenantBody, tenantSession } from "../../test/helpers";
import { tag } from "../../test/network";
import { setSystemDark } from "../../test/setup";
import { AUTH_ID, conflict, instructions, keyIssue, OTHER, REQ_1, REQ_3, request, webIssue } from "../../test/enrollment";
import { ENROLL_OS, ENROLLMENT_STATUSES } from "./model";

async function violations(): Promise<string[]> {
  const r = await axe.run(document.body, {
    runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"] },
    rules: { "color-contrast": { enabled: false } },
  });
  return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
}

const base = `/tenants/${TENANT_A}`;
const queue = [
  request(REQ_1, { status: "pending_approval", device_label: "phone-binh", requested_by_membership_id: OTHER, target_membership_id: OTHER, issued_at: null, credential_expires_at: null }),
  request(REQ_3, { status: "issued", method: "preauth_key", device_label: "ci-runner", tags: ["tag:ci"], reusable: true, target_membership_id: null }),
];
function apiFor(role: string) {
  return {
    "GET /auth/session": json(200, tenantSession([{ tenantId: TENANT_A, slug: "tenant-a", name: "Tenant A", role }])),
    [`GET ${base}`]: json(200, tenantBody(TENANT_A, "tenant-a")),
    [`GET ${base}/notifications`]: json(200, { items: [], next_cursor: null }),
    [`GET ${base}/enrollment/instructions`]: (r: Request) => json(200, instructions((new URL(r.url).searchParams.get("os") ?? "linux") as "linux")),
    [`GET ${base}/enrollment/requests`]: (r: Request) => {
      const s = new URL(r.url).searchParams.get("status");
      return json(200, { items: s ? queue.filter((x) => x.status === s) : queue, next_cursor: null });
    },
    [`GET ${base}/enrollment/requests/${REQ_1}`]: json(200, request(REQ_1)),
    [`GET ${base}/users`]: json(200, { items: [], next_cursor: null }),
    [`GET ${base}/tags`]: json(200, { items: [tag("tag:ci", 1)], next_cursor: null }),
    [`POST ${base}/enrollment/requests`]: json(201, webIssue()),
    [`POST ${base}/enrollment/keys`]: json(201, keyIssue()),
    [`POST ${base}/enrollment/web-auth/claim`]: conflict("no_pending_request"),
  };
}

describe.each([
  ["vi", false],
  ["en", true],
] as const)("axe màn hình enrollment (%s, tối=%s)", (lng, dark) => {
  const t = (k: string) => i18n.t(k);
  it("Thêm thiết bị: wizard + hướng dẫn Windows + lệnh vừa phát + ô dán link", async () => {
    await i18n.changeLanguage(lng);
    setSystemDark(dark);
    mockApi(apiFor("end_user"));
    renderApp({ path: `/t/${TENANT_A}/enroll` });
    const wizard = await screen.findByTestId("enroll-wizard");
    await within(wizard).findByTestId("login-server");
    expect(await violations()).toEqual([]);
    await userEvent.click(within(wizard).getByLabelText("Windows"));
    await within(wizard).findByTestId("windows-msi");
    expect(await violations()).toEqual([]);
    await userEvent.click(within(wizard).getByRole("button", { name: t("enroll.wizard.submitWeb") }));
    await screen.findByTestId("web-auth-command");
    const paste = screen.getByTestId("paste-claim");
    await userEvent.type(within(paste).getByLabelText(t("enroll.paste.label")), AUTH_ID);
    await userEvent.click(within(paste).getByRole("button", { name: t("enroll.paste.check") }));
    await within(paste).findByTestId("claim-confirm");
    expect(await violations()).toEqual([]);
  });

  it("hộp key một lần", async () => {
    await i18n.changeLanguage(lng);
    setSystemDark(dark);
    mockApi({ ...apiFor("tenant_admin"), [`POST ${base}/enrollment/requests`]: json(201, keyIssue()) });
    renderApp({ path: `/t/${TENANT_A}/enrollment-keys` });
    await userEvent.click(await screen.findByRole("button", { name: t("enroll.key.create") }));
    const dialog = screen.getByRole("dialog", { name: t("enroll.key.createTitle") });
    await within(dialog).findByLabelText("tag:ci");
    expect(await violations()).toEqual([]);
    await userEvent.click(within(dialog).getByRole("button", { name: t("enroll.key.submit") }));
    await screen.findByTestId("secret-value");
    expect(await violations()).toEqual([]);
  });

  it("Enrollment key: hàng chờ duyệt + hộp duyệt", async () => {
    await i18n.changeLanguage(lng);
    setSystemDark(dark);
    mockApi(apiFor("tenant_owner"));
    renderApp({ path: `/t/${TENANT_A}/enrollment-keys` });
    await screen.findByTestId("approval-queue");
    await screen.findByTestId("all-requests");
    expect(await violations()).toEqual([]);
    await userEvent.click(within(screen.getByTestId("approval-queue")).getByRole("button", { name: i18n.t("enroll.actions.approveFor", { label: "phone-binh" }) }));
    await screen.findByRole("alertdialog");
    expect(await violations()).toEqual([]);
  });

  it("trang claim: xác nhận, rồi cảnh báo phishing", async () => {
    await i18n.changeLanguage(lng);
    setSystemDark(dark);
    mockApi(apiFor("end_user"));
    renderApp({ path: `/enroll/claim?tenant=tenant-a&auth_id=${AUTH_ID}` });
    const panel = await screen.findByTestId("claim-confirm");
    await screen.findByTestId("no-pending-hint");
    expect(await violations()).toEqual([]);
    await userEvent.click(within(panel).getByRole("checkbox"));
    await userEvent.click(within(panel).getByRole("button", { name: t("enroll.claim.confirm") }));
    await screen.findByTestId("claim-phishing");
    expect(await violations()).toEqual([]);
  });

  it("trang claim: yêu cầu đã kết thúc (503 sau bước claim)", async () => {
    await i18n.changeLanguage(lng);
    setSystemDark(dark);
    mockApi({ ...apiFor("end_user"), [`POST ${base}/enrollment/web-auth/claim`]: problem(503, "instance_unavailable") });
    renderApp({ path: `/enroll/claim?tenant=tenant-a&auth_id=${AUTH_ID}` });
    const panel = await screen.findByTestId("claim-confirm");
    await userEvent.click(within(panel).getByRole("checkbox"));
    await userEvent.click(within(panel).getByRole("button", { name: t("enroll.claim.confirm") }));
    expect(await screen.findByTestId("claim-ended")).toHaveTextContent(t("enroll.claim.endedNext"));
    expect(await violations()).toEqual([]);
  });
});

describe("khóa i18n động của enrollment", () => {
  it("trạng thái, OS, phương thức, mã lỗi, thao tác — có trong vi và en", () => {
    type Tree = { [k: string]: string | Tree };
    const get = (tree: Tree, key: string) => key.split(".").reduce<string | Tree | undefined>((n, p) => (n && typeof n === "object" ? n[p] : undefined), tree);
    const keys = [
      ...ENROLLMENT_STATUSES.map((s) => `status.enrollment.${s}`),
      ...ENROLL_OS.flatMap((o) => ["name", "step1", "step2", "step3"].map((k) => `enroll.os.${o}.${k}`)),
      ...["web_auth", "preauth_key", "oidc"].map((m) => `enroll.method.${m}`),
      ...["node_mismatch", "foreign_node", "auth_id_not_pending", "claim_unfinished", "issue_unfinished", "key_missing", "node_gone", "record_failed"].map((c) => `enroll.failure.${c}`),
      ...["approve", "reject", "revoke"].flatMap((a) => [`enroll.actions.${a}`, `enroll.actions.done.${a}`, `enroll.actions.title.${a}`, `enroll.actions.desc.${a}`]),
      ...["already_started", "request_expired", "not_approved", "not_requester", "other"].map((c) => `enroll.startConflict.${c}`),
      ...["none", "several", "other_server"].map((c) => `enroll.paste.errors.${c}`),
      ...["self", "member", "tags"].map((o) => `enroll.key.owners.${o}`),
      ...["expired", "revoked"].map((s) => `enroll.issued.ended.${s}`),
      ...["endedNotPending", "endedUpstream"].map((k) => `enroll.claim.${k}`),
    ];
    const missing = keys.filter((k) => typeof get(vi as Tree, k) !== "string" || typeof get(en as Tree, k) !== "string");
    expect(missing).toEqual([]);
  });
});
