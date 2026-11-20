// G4b-E12: Platform Console hiện tên/slug của tenant và tên host (API trả `tenant_slug`/`tenant_name`/`host_name` cùng
// hàng) thay cho UUID — UUID ở tooltip và trong đích của link; thiếu nhãn ⇒ UUID như trước. Cột Gói của danh sách tenant
// có giá trị. vi + en, axe.
import { screen, within } from "@testing-library/react";
import axe from "axe-core";
import { describe, expect, it } from "vitest";
import { i18n } from "../i18n";
import { json, mockApi, platformSession, renderApp } from "../test/helpers";
import { HOST1, INST1, instance, JOB1, provisionJob, relayList, safeJob, T1, tenant } from "../test/platformFixtures";
import { idp, IDP_T } from "../test/opsFixtures";

async function violations(): Promise<string[]> {
  const r = await axe.run(document.body, {
    runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"] },
    rules: { "color-contrast": { enabled: false } },
  });
  return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
}

const labels = { tenant_slug: "acme", tenant_name: "Acme Corp" };
const session = { "GET /auth/session": json(200, platformSession("super_admin")) };

function expectTenantRef(scope: HTMLElement) {
  const link = within(scope).getByRole("link", { name: "Acme Corp" });
  expect(link).toHaveAttribute("href", `/platform/tenants/${T1}`);
  expect(link).toHaveAttribute("title", i18n.t("platform.idTooltip", { id: T1 }));
  expect(within(scope).getByText("acme")).toBeInTheDocument();
  expect(scope).not.toHaveTextContent(T1);
}

describe.each(["vi", "en"] as const)("tên thay UUID trong Platform Console (%s)", (lng) => {
  it("Instance: danh sách + chi tiết — tenant và host theo tên", async () => {
    await i18n.changeLanguage(lng);
    const inst = { ...instance(T1), ...labels, host_name: "host-1" };
    mockApi({
      ...session,
      "GET /platform/instances": json(200, { items: [inst], next_cursor: null }),
      [`GET /platform/instances/${INST1}`]: json(200, inst),
      [`GET /platform/instances/${INST1}/config-versions`]: json(200, { items: [], next_cursor: null }),
      "GET /platform/backups": json(200, { items: [], next_cursor: null }),
    });
    const { unmount } = renderApp({ path: "/platform/instances", console: "platform" });
    const row = (await screen.findByRole("link", { name: "acme.mesh.example.test" })).closest("tr")!;
    expectTenantRef(row);
    const hostLink = within(row).getByTestId("host-ref");
    expect(hostLink).toHaveTextContent("host-1");
    expect(hostLink).toHaveAttribute("href", `/platform/hosts/${HOST1}`);
    expect(hostLink).toHaveAttribute("title", i18n.t("platform.idTooltip", { id: HOST1 }));
    expect(row).not.toHaveTextContent(HOST1);
    expect(await violations()).toEqual([]);
    unmount();
    renderApp({ path: `/platform/instances/${INST1}`, console: "platform" });
    expect(await screen.findByTestId("host-ref")).toHaveTextContent("host-1");
    expect(screen.getByTestId("tenant-ref")).toHaveTextContent("Acme Corp");
  });

  it("Job, Relay Region, IdP: tenant theo tên; thiếu nhãn ⇒ UUID", async () => {
    await i18n.changeLanguage(lng);
    const withLabels = { ...safeJob(provisionJob(JOB1, T1)), ...labels };
    const relay = relayList(T1);
    relay.items[0] = { ...relay.items[0]!, ...labels, host_name: "host-1" };
    mockApi({
      ...session,
      "GET /platform/jobs": json(200, { items: [withLabels], next_cursor: null }),
      "GET /platform/relay-regions": json(200, relay),
      "GET /platform/identity-providers": json(200, { items: [idp(IDP_T, labels)], next_cursor: null }),
    });
    const { unmount } = renderApp({ path: "/platform/jobs", console: "platform" });
    const jobRow = (await screen.findByRole("link", { name: "tenant.provision" })).closest("tr")!;
    expectTenantRef(jobRow);
    expect(await violations()).toEqual([]);
    unmount();
    const r2 = renderApp({ path: "/platform/relay-regions", console: "platform" });
    expectTenantRef(await screen.findByTestId("relay-row"));
    r2.unmount();
    renderApp({ path: "/platform/identity-providers", console: "platform" });
    const issuer = await screen.findByRole("link", { name: "https://id.example.test/realms/tenant-acme" });
    expectTenantRef(issuer.closest("tr")!);
    expect(await violations()).toEqual([]);
  });

  it("thiếu nhãn (server cũ) ⇒ UUID như trước; danh sách tenant có cột Gói", async () => {
    await i18n.changeLanguage(lng);
    mockApi({
      ...session,
      "GET /platform/jobs": json(200, { items: [safeJob(provisionJob(JOB1, T1))], next_cursor: null }),
      "GET /platform/tenants": json(200, { items: [{ ...tenant(T1, "acme"), plan: "standard" }], next_cursor: null }),
    });
    const { unmount } = renderApp({ path: "/platform/jobs", console: "platform" });
    const jobRow = (await screen.findByRole("link", { name: "tenant.provision" })).closest("tr")!;
    expect(within(jobRow).getByRole("link", { name: T1 })).toHaveAttribute("href", `/platform/tenants/${T1}`);
    unmount();
    renderApp({ path: "/platform/tenants", console: "platform" });
    const row = (await screen.findByRole("link", { name: /acme/ })).closest("tr")!;
    expect(within(row).getByText("standard")).toBeInTheDocument();
  });
});
