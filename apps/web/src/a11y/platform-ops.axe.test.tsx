// a11y của các màn hình P4-T03 (axe-core, hai ngôn ngữ): instances (danh sách, chi tiết, hộp đổi cấu hình đang mở),
// hosts, Platform Health (có thành phần "không khả dụng"), relay regions, thiết lập (hộp sửa có lỗi 412), nhân sự nền
// tảng (hộp gán SA), IdP (hộp sửa), gói dịch vụ (hộp tạo có lỗi). color-contrast kiểm trong trình duyệt thật ở P4-T14.
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { describe, expect, it, vi } from "vitest";
import { i18n } from "../i18n";
import { json, mockApi, platformSession, problem, renderApp } from "../test/helpers";
import { backup, configVersions, health, host, HOST2, idp, IDP_T, plan, platformUser, PU_ME, PU_OTHER, settings } from "../test/opsFixtures";
import { HOST1, INST1, instance, relayList, T1 } from "../test/platformFixtures";

vi.setConfig({ testTimeout: 30_000 });

async function violations(): Promise<string[]> {
  const r = await axe.run(document.body, {
    runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"] },
    rules: { "color-contrast": { enabled: false } },
  });
  return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
}

const routes = {
  "GET /auth/session": json(200, platformSession("super_admin")),
  "GET /platform/instances": json(200, { items: [instance(T1)], next_cursor: "n1" }),
  [`GET /platform/instances/${INST1}`]: json(200, instance(T1)),
  [`GET /platform/instances/${INST1}/config-versions`]: json(200, configVersions()),
  "GET /platform/backups": json(200, { items: [backup()], next_cursor: null }),
  "GET /platform/hosts": json(200, { items: [host(HOST1), host(HOST2, null)], next_cursor: null }),
  [`GET /platform/hosts/${HOST1}`]: json(200, host(HOST1)),
  "GET /platform/health": json(200, health()),
  "GET /platform/relay-regions": json(200, relayList(T1)),
  "GET /platform/settings": json(200, settings()),
  "PUT /platform/settings/approval.ttl_hours": problem(412, "precondition_failed"),
  "GET /platform/users": json(200, { items: [platformUser(PU_ME, { role: "super_admin" }), platformUser(PU_OTHER)], next_cursor: null }),
  "GET /platform/identity-providers": json(200, { items: [idp(), idp(IDP_T)], next_cursor: null }),
  [`GET /platform/identity-providers/${IDP_T}`]: json(200, idp(IDP_T), { ETag: '"5"' }),
  "GET /platform/plans": json(200, { items: [plan()] }),
};

describe.each(["vi", "en"] as const)("axe Platform Console P4-T03 (%s)", (lng) => {
  const L = (vi: string, en: string) => (lng === "vi" ? vi : en);

  it("instances: danh sách, chi tiết, hộp đổi cấu hình", async () => {
    await i18n.changeLanguage(lng);
    mockApi(routes);
    const { router } = renderApp({ path: "/platform/instances", console: "platform" });
    await screen.findByRole("link", { name: "acme.mesh.example.test" });
    expect(await violations()).toEqual([]);
    await router.navigate(`/platform/instances/${INST1}`);
    await screen.findByTestId("config-current");
    await screen.findByText("vacuum_into");
    expect(await violations()).toEqual([]);
    await userEvent.click(screen.getByRole("button", { name: L("Đổi cấu hình…", "Reconfigure…") }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText(L("Hạn node (ngày)", "Node expiry (days)")), "0");
    await userEvent.click(within(dialog).getByRole("button", { name: L("Áp dụng cấu hình", "Apply configuration") }));
    expect(await violations()).toEqual([]);
  });

  it("hosts (danh sách, chi tiết), health, relay regions", async () => {
    await i18n.changeLanguage(lng);
    mockApi(routes);
    const { router } = renderApp({ path: "/platform/hosts", console: "platform" });
    await screen.findAllByTestId("host-row");
    expect(await violations()).toEqual([]);
    await router.navigate(`/platform/hosts/${HOST1}`);
    await screen.findByRole("link", { name: "acme.mesh.example.test" });
    expect(await violations()).toEqual([]);
    await router.navigate("/platform/health");
    await screen.findByTestId("components-unavailable");
    expect(await violations()).toEqual([]);
    await router.navigate("/platform/relay-regions");
    await screen.findByTestId("relay-unavailable");
    expect(await violations()).toEqual([]);
  });

  it("thiết lập (hộp sửa với 412), nhân sự (hộp gán SA), IdP (hộp sửa), gói (hộp tạo có lỗi)", async () => {
    await i18n.changeLanguage(lng);
    mockApi(routes);
    const { router } = renderApp({ path: "/platform/settings", console: "platform" });
    await userEvent.click(await screen.findByRole("button", { name: L("Sửa approval.ttl_hours", "Edit approval.ttl_hours") }));
    let dialog = await screen.findByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: L("Lưu", "Save") }));
    await within(dialog).findByTestId("stale-setting");
    expect(await violations()).toEqual([]);
    await userEvent.keyboard("{Escape}");

    await router.navigate("/platform/users");
    const rows = await screen.findAllByTestId("platform-user");
    expect(await violations()).toEqual([]);
    await userEvent.click(within(rows[1]!).getByRole("button", { name: L("Gán Super Admin cho Second Admin", "Grant Super Admin to Second Admin") }));
    await screen.findByRole("dialog");
    expect(await violations()).toEqual([]);
    await userEvent.keyboard("{Escape}");

    await router.navigate(`/platform/identity-providers/${IDP_T}`);
    await userEvent.click(await screen.findByRole("button", { name: L("Sửa ràng buộc claim…", "Edit claim constraints…") }));
    await screen.findByRole("dialog");
    expect(await violations()).toEqual([]);
    await userEvent.keyboard("{Escape}");

    await router.navigate("/platform/plans");
    await userEvent.click(await screen.findByRole("button", { name: L("Tạo gói", "Create plan") }));
    dialog = await screen.findByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: L("Tạo gói", "Create plan") }));
    expect(await violations()).toEqual([]);
  });
});
