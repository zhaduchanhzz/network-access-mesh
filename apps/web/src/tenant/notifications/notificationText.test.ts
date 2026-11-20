// G4b-E13: actor hệ thống của thông báo idp.admin_change hiện nhãn đã dịch theo mã (`actor_kind`, hoặc suy từ mô tả tiếng
// Anh của thông báo cũ) — cùng nhãn với Audit log; actor là người giữ nguyên tên.
import { describe, expect, it } from "vitest";
import { i18n } from "../../i18n";
import { notificationText, systemActorKind } from "./notificationText";

const at = "2026-11-20T03:00:00Z";

describe.each(["vi", "en"] as const)("actor của thông báo (%s)", (lng) => {
  it("actor_kind ⇒ nhãn đã dịch; thông báo cũ ⇒ suy từ mô tả; người ⇒ tên", async () => {
    await i18n.changeLanguage(lng);
    const t = i18n.t.bind(i18n);
    const withKind = notificationText(t, lng, "idp.admin_change", {
      event_id: "e1", action: "idp.user.credential_reset", actor: "Keycloak administrator (master realm)", actor_kind: "idp_admin", occurred_at: at,
    });
    expect(withKind).toContain(i18n.t("audit.actorKinds.idp_admin"));
    if (lng === "vi") expect(withKind).not.toContain("Keycloak administrator (master realm)");
    const legacy = notificationText(t, lng, "idp.admin_change", {
      event_id: "e2", action: "idp.user.update", actor: "IdP provisioning identity (platform)", occurred_at: at,
    });
    expect(legacy).toContain(i18n.t("audit.actorKinds.idp_provisioner"));
    if (lng === "vi") expect(legacy).not.toContain("IdP provisioning identity");
    const person = notificationText(t, lng, "idp.admin_change", { event_id: "e3", action: "idp.user.update", actor: "Nguyễn Văn A", occurred_at: at });
    expect(person).toContain("Nguyễn Văn A");
  });
});

describe("systemActorKind", () => {
  it("mã hợp lệ, mô tả cũ, đăng nhập console theo tên; người và mã lạ ⇒ null", () => {
    expect(systemActorKind({ actor_kind: "idp_driver" })).toBe("idp_driver");
    expect(systemActorKind({ actor: "Keycloak master: admin" })).toBe("idp_admin");
    expect(systemActorKind({ actor: "user of the realm" })).toBe("realm_user");
    expect(systemActorKind({ actor: "Alice" })).toBeNull();
    expect(systemActorKind({ actor_kind: "<b>x</b>", actor: "Alice" })).toBeNull();
  });
});
