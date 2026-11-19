// a11y (§12.4 — mục tiêu WCAG 2.1 AA): axe-core trên các màn hình của vỏ app, hai ngôn ngữ, hai giao diện.
// jsdom không tính được màu thật ⇒ tắt color-contrast ở đây; độ tương phản kiểm bằng axe trong trình duyệt ở P4-T14.
import { screen } from "@testing-library/react";
import axe from "axe-core";
import { describe, expect, it } from "vitest";
import { i18n } from "../i18n";
import { json, mockApi, platformSession, problem, renderApp, TENANT_A, tenantBody, tenantSession } from "../test/helpers";

async function violations(): Promise<string[]> {
  const r = await axe.run(document.body, {
    runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"] },
    rules: { "color-contrast": { enabled: false } },
  });
  return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
}

const owner = tenantSession([{ tenantId: TENANT_A, slug: "tenant-a", name: "Tenant A", role: "tenant_owner" }]);

describe.each(["vi", "en"] as const)("axe (%s)", (lng) => {
  it.each(["light", "dark"] as const)("đăng nhập Tenant Portal (%s)", async (theme) => {
    await i18n.changeLanguage(lng);
    localStorage.setItem("mg.pref.theme", theme);
    mockApi({ "GET /auth/session": problem(401, "unauthenticated") });
    renderApp({ path: "/login" });
    await screen.findByRole("heading", { level: 1 });
    expect(await violations()).toEqual([]);
  });

  it("đăng nhập Platform Console", async () => {
    await i18n.changeLanguage(lng);
    mockApi({ "GET /auth/session": problem(401, "unauthenticated") });
    renderApp({ path: "/login", console: "platform" });
    await screen.findByRole("heading", { level: 1 });
    expect(await violations()).toEqual([]);
  });

  it("Tenant Portal: layout + nav + trang chưa khả dụng + banner suspended", async () => {
    await i18n.changeLanguage(lng);
    mockApi({
      "GET /auth/session": json(200, owner),
      [`GET /tenants/${TENANT_A}`]: json(200, tenantBody(TENANT_A, "tenant-a", "suspended")),
    });
    renderApp({ path: `/t/${TENANT_A}/devices` });
    await screen.findByTestId("tenant-suspended");
    expect(await violations()).toEqual([]);
  });

  it("Platform Console: layout + nav + trang chưa khả dụng", async () => {
    await i18n.changeLanguage(lng);
    mockApi({ "GET /auth/session": json(200, platformSession("super_admin")) });
    renderApp({ path: "/platform/audit", console: "platform" });
    await screen.findByTestId("unavailable");
    expect(await violations()).toEqual([]);
  });

  it("404 thống nhất và trang chọn tenant", async () => {
    await i18n.changeLanguage(lng);
    mockApi({ "GET /auth/session": json(200, owner) });
    const { router } = renderApp({ path: "/khong-co" });
    await screen.findByRole("heading", { level: 1 });
    expect(await violations()).toEqual([]);
    await router.navigate("/tenants");
    await screen.findByRole("link", { name: /Tenant A/ });
    expect(await violations()).toEqual([]);
  });
});
