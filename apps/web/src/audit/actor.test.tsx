// G4b-E13: một quy ước hiển thị actor ở Audit log — người dùng ⇒ tên hiển thị kèm e-mail nhỏ (ID danh tính ở tooltip;
// không tên ⇒ "Người dùng (chưa rõ tên)", không UUID trần); hệ thống ⇒ nhãn đã dịch theo `actor.kind` (ảnh chụp thô ở
// tooltip); server cũ không có `kind` ⇒ suy từ loại. vi + en, axe.
import { screen, within } from "@testing-library/react";
import axe from "axe-core";
import { describe, expect, it } from "vitest";
import type { components } from "../api/schema";
import { i18n } from "../i18n";
import { json, mockApi, renderApp, TENANT_A, tenantBody, tenantSession } from "../test/helpers";

async function violations(): Promise<string[]> {
  const r = await axe.run(document.body, {
    runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"] },
    rules: { "color-contrast": { enabled: false } },
  });
  return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`);
}

type Event = components["schemas"]["AuditEvent"];
const base = `/tenants/${TENANT_A}`;
const ALICE = "0190c000-0000-7000-8000-0000000000a1";
const GHOST = "0190c000-0000-7000-8000-0000000000a2";

function event(n: number, actor: Event["actor"], action: string): Event {
  return {
    id: `0190a700-0000-7000-8000-00000000000${String(n)}`,
    occurred_at: "2026-11-20T03:00:00Z",
    actor,
    action,
    resource: { type: "session", id: "" },
    outcome: "success",
    request_id: `req-${String(n)}`,
    details: {},
  };
}

const events: Event[] = [
  event(1, { type: "identity", kind: "user", identity_id: ALICE, display_name: "Alice Nguyễn", email: "alice@acme.test" }, "auth.login"),
  event(2, { type: "identity", kind: "user", identity_id: GHOST }, "auth.login"),
  event(3, { type: "system", kind: "idp_admin", display_name: "Keycloak administrator (master realm)" }, "idp.user.update"),
  event(4, { type: "system", kind: "job", display_name: "member.idp_invite" }, "idp.user.invite"),
  event(5, { type: "system", display_name: "IdP provisioning identity (platform)" }, "idp.user.create"),
];

describe.each(["vi", "en"] as const)("actor của Audit log (%s)", (lng) => {
  it("người ⇒ tên + e-mail; hệ thống ⇒ nhãn theo mã, mô tả thô ở tooltip", async () => {
    await i18n.changeLanguage(lng);
    mockApi({
      "GET /auth/session": json(200, tenantSession([{ tenantId: TENANT_A, slug: "tenant-a", name: "Tenant A", role: "tenant_owner" }])),
      [`GET ${base}`]: json(200, tenantBody(TENANT_A, "tenant-a")),
      [`GET ${base}/notifications`]: json(200, { items: [], next_cursor: null }),
      [`GET ${base}/audit`]: json(200, { items: events, next_cursor: null }),
    });
    renderApp({ path: `/t/${TENANT_A}/audit` });
    const rows = await screen.findAllByTestId("audit-row");
    expect(rows).toHaveLength(5);
    const name = (i: number) => within(rows[i]!).getByTestId("actor-name");

    expect(name(0)).toHaveTextContent("Alice Nguyễn");
    expect(name(0)).toHaveAttribute("title", i18n.t("audit.actorIdTooltip", { id: ALICE }));
    expect(within(rows[0]!).getByTestId("actor-email")).toHaveTextContent("alice@acme.test");

    expect(name(1)).toHaveTextContent(i18n.t("audit.unknownUser"));
    expect(rows[1]).not.toHaveTextContent(GHOST);

    expect(name(2)).toHaveTextContent(i18n.t("audit.actorKinds.idp_admin"));
    expect(name(2)).toHaveAttribute("title", i18n.t("audit.actorRaw", { raw: "Keycloak administrator (master realm)" }));
    expect(name(3)).toHaveTextContent(i18n.t("audit.actorKinds.job"));
    expect(rows[3]).not.toHaveTextContent("member.idp_invite");
    // server cũ không trả kind ⇒ nhãn chung "Hệ thống", mô tả tiếng Anh chỉ ở tooltip
    expect(name(4)).toHaveTextContent(i18n.t("audit.actorKinds.system"));
    expect(rows[4]).not.toHaveTextContent("IdP provisioning identity");
    expect(await violations()).toEqual([]);
  });
});
