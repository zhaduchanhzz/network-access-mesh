// a11y của lỗi slug ở trang đăng nhập Tenant Portal (P4-T14-prep mục 6.3): lỗi phải được trình đọc màn hình đọc khi bấm
// "Tiếp tục" — vùng role="alert" có sẵn trong DOM từ đầu (rỗng), nhận nội dung khi slug sai, nội dung được thay ở mỗi
// lần bấm lặp lại; ô nhập trỏ tới lỗi (aria-describedby + aria-errormessage, aria-invalid) và nhận lại focus; sửa ô nhập
// ⇒ lỗi biến mất, gợi ý trở lại; axe sạch ở trạng thái lỗi, hai ngôn ngữ.
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { describe, expect, it, vi } from "vitest";
import { browser } from "../app/console";
import { i18n } from "../i18n";
import { mockApi, problem, renderApp } from "../test/helpers";

async function violations(): Promise<string[]> {
  const r = await axe.run(document.body, {
    runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"] },
    rules: { "color-contrast": { enabled: false } }, // jsdom không tính màu — độ tương phản kiểm bằng Playwright (P4-T14)
  });
  return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
}

describe.each(["vi", "en"] as const)("đăng nhập: lỗi slug được thông báo (%s)", (lng) => {
  it("vùng alert có sẵn, đọc lỗi khi bấm Tiếp tục, lặp lại thì thay nội dung, focus về ô nhập", async () => {
    await i18n.changeLanguage(lng);
    mockApi({ "GET /auth/session": problem(401, "unauthenticated") });
    const assign = vi.spyOn(browser, "assign").mockImplementation(() => undefined);
    renderApp({ path: "/login" });
    const input = await screen.findByLabelText(i18n.t("login.tenantLabel"));
    const submit = screen.getByRole("button", { name: i18n.t("login.submit") });

    // trước khi có lỗi: vùng alert đã có (rỗng) — trình đọc màn hình theo dõi nó từ đầu; ô nhập trỏ tới gợi ý
    const alert = screen.getByRole("alert");
    expect(alert).toBeEmptyDOMElement();
    expect(input).toHaveAttribute("aria-invalid", "false");
    expect(input).not.toHaveAttribute("aria-errormessage");
    expect(input).toHaveAccessibleDescription(i18n.t("login.tenantHint"));

    await userEvent.type(input, "Bad Slug");
    await userEvent.click(submit);
    expect(assign).not.toHaveBeenCalled();
    expect(alert).toHaveTextContent(i18n.t("login.tenantInvalid"));
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(input).toHaveAttribute("aria-errormessage", alert.id);
    expect(input).toHaveAccessibleDescription(i18n.t("login.tenantInvalid"));
    expect(input).toHaveFocus();
    expect(screen.queryByText(i18n.t("login.tenantHint"))).toBeNull();
    expect(await violations()).toEqual([]);

    // bấm lại với cùng slug sai: nội dung trong vùng alert được thay (một lỗi mới để đọc lại), vẫn một vùng alert
    const first = alert.firstElementChild;
    await userEvent.click(submit);
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    expect(alert.firstElementChild).not.toBe(first);
    expect(alert).toHaveTextContent(i18n.t("login.tenantInvalid"));

    // sửa ô nhập: lỗi rời vùng alert, gợi ý trở lại, rồi tiếp tục tới IdP
    await userEvent.clear(input);
    expect(alert).toBeEmptyDOMElement();
    expect(input).toHaveAttribute("aria-invalid", "false");
    expect(input).toHaveAccessibleDescription(i18n.t("login.tenantHint"));
    await userEvent.type(input, "tenant-a");
    await userEvent.click(submit);
    expect(assign).toHaveBeenCalledWith("/api/v1/auth/login?scope=tenant&tenant=tenant-a");
  });
});

// G4b-E2: slug không tồn tại / tenant không cho đăng nhập ⇒ server chuyển hướng điều hướng của trình duyệt về
// /login?error=tenant_not_found&tenant=<slug> (một mã cho mọi trường hợp). Trang hiện câu đã dịch trong vùng alert có sẵn,
// điền lại slug, focus ô nhập, cho thử lại; mã lạ ⇒ câu chung; không bao giờ in mã nguyên văn.
describe.each(["vi", "en"] as const)("đăng nhập: lỗi bắt đầu đăng nhập từ server (%s)", (lng) => {
  it("?error=tenant_not_found ⇒ thông báo đã dịch, slug điền lại, focus ô nhập, sửa rồi thử lại", async () => {
    await i18n.changeLanguage(lng);
    mockApi({ "GET /auth/session": problem(401, "unauthenticated") });
    const assign = vi.spyOn(browser, "assign").mockImplementation(() => undefined);
    renderApp({ path: "/login?error=tenant_not_found&tenant=khong-co" });
    const input = await screen.findByLabelText(i18n.t("login.tenantLabel"));
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent(i18n.t("login.errors.tenantNotFound"));
    expect(alert).not.toHaveTextContent("tenant_not_found");
    expect(input).toHaveValue("khong-co");
    await waitFor(() => expect(input).toHaveFocus());
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(input).toHaveAttribute("aria-errormessage", alert.id);
    expect(input).toHaveAccessibleDescription(i18n.t("login.errors.tenantNotFound"));
    expect(await violations()).toEqual([]);

    // sửa ô nhập ⇒ lỗi rời vùng alert; tiếp tục tới IdP với slug mới
    await userEvent.clear(input);
    expect(alert).toBeEmptyDOMElement();
    expect(input).toHaveAttribute("aria-invalid", "false");
    await userEvent.type(input, "tenant-a");
    await userEvent.click(screen.getByRole("button", { name: i18n.t("login.submit") }));
    expect(assign).toHaveBeenCalledWith("/api/v1/auth/login?scope=tenant&tenant=tenant-a");
  });

  it("mã lạ ⇒ câu chung, không in mã; thử lại cùng slug ⇒ lỗi biến mất và đi tiếp", async () => {
    await i18n.changeLanguage(lng);
    mockApi({ "GET /auth/session": problem(401, "unauthenticated") });
    const assign = vi.spyOn(browser, "assign").mockImplementation(() => undefined);
    renderApp({ path: "/login?error=<b>weird_code</b>&tenant=tenant-a" });
    await screen.findByLabelText(i18n.t("login.tenantLabel"));
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent(i18n.t("login.errors.startFailed"));
    expect(document.body).not.toHaveTextContent("weird_code");
    await userEvent.click(screen.getByRole("button", { name: i18n.t("login.submit") }));
    expect(alert).toBeEmptyDOMElement();
    expect(assign).toHaveBeenCalledWith("/api/v1/auth/login?scope=tenant&tenant=tenant-a");
  });
});
