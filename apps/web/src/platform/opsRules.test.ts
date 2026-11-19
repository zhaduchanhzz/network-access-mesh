// Quy tắc thuần của các form/thao tác P4-T03 — mirror của backend (chỉ hướng dẫn, server quyết định) và khóa i18n động.
import { describe, expect, it } from "vitest";
import en from "../i18n/locales/en.json";
import vi from "../i18n/locales/vi.json";
import { APPROVAL_ACTION_PERMISSION } from "./api";
import { idpUpdate, parseDomains, parseRequiredClaims, formOf } from "./idps/idpForm";
import { actionsFor, reconfigureRequest } from "./instances/InstanceActions";
import { HOST_STATUSES, IDP_STATUSES, INSTANCE_STATUSES, PLATFORM_ROLES, PLATFORM_USER_STATUSES } from "./opsApi";
import { checkPlanLimits, limitsFormOf, limitsOf, LIMIT_FIELDS } from "./plans/planForm";
import { parseSettingValue } from "./settings/SettingsPage";
import { userActions } from "./users/PlatformUsersPage";
import { idp, IDP_T, platformUser, PU_ME, PU_OTHER, PU_SA } from "../test/opsFixtures";
import { ME } from "../test/platformFixtures";

describe("checkPlanLimits = platform.CheckPlanLimits (vector của TestPlanLimitsParity, Go)", () => {
  const quota = `"max_devices":1,"max_users":2,"max_tagged_devices":0,"max_live_enrollment_credentials":3`;
  // [tài liệu, hợp lệ khi đầy đủ, hợp lệ khi từng phần] — kết quả của CHECK mg_plan_limits_valid (0012)
  const vectors: [string, boolean, boolean][] = [
    [`{${quota}}`, true, true],
    [`{${quota},"backup_interval_minutes":60,"instance":{"cpus":0.5,"memory_mb":512,"pids":64}}`, true, true],
    [`{"max_devices":1}`, false, true],
    [`{}`, false, true],
    [`[]`, false, false],
    [`1`, false, false],
    [`{${quota},"extra":1}`, false, false],
    [`{${quota},"max_devices":-1}`, false, false],
    [`{${quota},"max_devices":2147483648}`, false, false],
    [`{${quota},"max_devices":1.5}`, false, false],
    [`{${quota},"max_devices":"1"}`, false, false],
    [`{${quota},"backup_interval_minutes":0}`, false, false],
    [`{${quota},"instance":{"cpus":0}}`, false, false],
    [`{${quota},"instance":{"cpus":1025}}`, false, false],
    [`{${quota},"instance":{"pids":0}}`, false, false],
    [`{${quota},"instance":{"gpu":1}}`, false, false],
    [`{${quota},"instance":[]}`, false, false],
    [`{"max_users":0,"instance":{"memory_mb":1}}`, false, true],
    [`{${quota},"max_devices":null}`, false, false],
  ];
  it.each(vectors)("%s", (doc, full, partial) => {
    const v = JSON.parse(doc) as unknown;
    expect(checkPlanLimits(v, false) === "").toBe(full);
    expect(checkPlanLimits(v, true) === "").toBe(partial);
  });

  it("trường lỗi giống tên của 422 (limits.<khóa>, limits.instance.<khóa>); form ⇄ PlanLimits", () => {
    expect(checkPlanLimits({ max_devices: 1 }, false)).toBe("limits.max_users");
    expect(checkPlanLimits({ instance: { cpus: 0 } }, true)).toBe("limits.instance.cpus");
    const f = limitsFormOf({ max_devices: 5, instance: { cpus: 0.5 } });
    expect(limitsOf(f)).toEqual({ max_devices: 5, instance: { cpus: 0.5 } });
    expect(checkPlanLimits(limitsOf({ ...f, max_users: "abc" }), true)).toBe("limits.max_users");
    expect(LIMIT_FIELDS).toHaveLength(8);
  });
});

describe("reconfigure / thao tác instance", () => {
  it("chỉ trường đã điền; miền giá trị của InstanceReconfigure", () => {
    expect(reconfigureRequest({ logLevel: "", nodeExpiryDays: "", nameservers: "", derpRegionId: "" }).errors.form).toBeDefined();
    expect(reconfigureRequest({ logLevel: "error", nodeExpiryDays: "3650", nameservers: "1.1.1.1 8.8.8.8", derpRegionId: "900" })).toEqual({
      errors: {},
      body: { log_level: "error", node_expiry_days: 3650, nameservers: ["1.1.1.1", "8.8.8.8"], derp_region_id: 900 },
    });
    const bad = reconfigureRequest({ logLevel: "", nodeExpiryDays: "3651", nameservers: "1.1.1.1,1.1.1.1", derpRegionId: "1000" });
    expect(Object.keys(bad.errors).sort()).toEqual(["derpRegionId", "nameservers", "nodeExpiryDays"]);
    expect(reconfigureRequest({ logLevel: "", nodeExpiryDays: "", nameservers: "a b c d e f g h i", derpRegionId: "" }).errors.nameservers).toBeDefined();
  });

  it("nút theo quyền + trạng thái (§8.5)", () => {
    expect(actionsFor("super_admin", "running")).toEqual(["restart", "reconfigure", "backup", "upgrade", "restore", "quarantine"]);
    expect(actionsFor("platform_operator", "quarantined")).toEqual(["restore", "quarantine", "release"]);
    expect(actionsFor("platform_support", "running")).toEqual([]);
    expect(actionsFor("platform_viewer", "running")).toEqual([]);
    expect(actionsFor("super_admin", "removed")).toEqual([]);
  });
});

describe("thiết lập", () => {
  it("khóa đã biết: số nguyên trong miền; khóa khác: JSON", () => {
    expect(parseSettingValue("approval.ttl_hours", "168")).toEqual({ value: 168 });
    expect(parseSettingValue("approval.ttl_hours", "0")).toEqual({ error: "platform.settings.errors.range" });
    expect(parseSettingValue("approval.ttl_hours", "1.5")).toEqual({ error: "platform.settings.errors.integer" });
    expect(parseSettingValue("quota.max_tenants", "0")).toEqual({ value: 0 });
    expect(parseSettingValue("x.y", '{"a":1}')).toEqual({ value: { a: 1 } });
    expect(parseSettingValue("x.y", "{")).toEqual({ error: "platform.settings.errors.json" });
  });
});

describe("nhân sự nền tảng", () => {
  it("không tự sửa mình; SA chỉ gỡ qua 2P; role dưới SA mới sửa/khóa", () => {
    expect(userActions("super_admin", ME, platformUser(PU_ME))).toEqual([]);
    expect(userActions("super_admin", ME, platformUser(PU_SA, { role: "super_admin" }))).toEqual(["revokeSA"]);
    expect(userActions("super_admin", ME, platformUser(PU_OTHER))).toEqual(["edit", "disable", "grantSA"]);
    expect(userActions("super_admin", ME, platformUser(PU_OTHER, { status: "disabled" }))).toEqual(["edit"]);
    expect(userActions("platform_operator", ME, platformUser(PU_OTHER))).toEqual([]);
    expect(userActions("platform_operator", ME, platformUser(PU_SA, { role: "super_admin" }))).toEqual([]);
  });
});

describe("IdP", () => {
  it("không bao giờ gửi issuer/client_id/driver; chỉ trường đã đổi; kiểm như internal/config/idpclaims.go", () => {
    const row = idp(IDP_T);
    expect(idpUpdate(row, formOf(row))).toEqual({ errors: {}, body: {} });
    const f = { ...formOf(row), domains: "B.example\nexample.test, b.example" };
    const r = idpUpdate(row, f);
    expect(r.body).toEqual({ allowed_email_domains: ["b.example", "example.test"] });
    expect(Object.keys(r.body)).not.toContain("issuer");
    expect(parseRequiredClaims('{"sub":"x"}')).toBeNull();
    expect(parseRequiredClaims('{"groups":[]}')).toBeNull();
    expect(parseRequiredClaims('{"a":{"b":1}}')).toBeNull();
    expect(parseRequiredClaims('{"acr":"gold","n":2,"ok":true,"g":["a","b"]}')).not.toBeNull();
    expect(parseDomains("bad_domain")).toBeNull();
    expect(idpUpdate(row, { ...formOf(row), mapping: { email: "mail", email_verified: "", name: "bad name" } }).errors.mapping).toBeDefined();
  });
});

type Tree = { [k: string]: string | Tree };
function has(tree: Tree, key: string): boolean {
  let o: string | Tree | undefined = tree;
  for (const p of key.split(".")) {
    if (typeof o !== "object") return false;
    o = o[p] ?? o[`${p}_other`];
  }
  return o !== undefined;
}

describe("khóa i18n động của P4-T03", () => {
  it("trạng thái, role, thao tác, hạn mức, lý do health, thao tác 2P mới — có ở vi và en", () => {
    const keys = [
      ...INSTANCE_STATUSES.map((s) => `status.instance.${s}`),
      ...HOST_STATUSES.map((s) => `status.host.${s}`),
      ...PLATFORM_USER_STATUSES.map((s) => `status.platformUser.${s}`),
      ...IDP_STATUSES.map((s) => `status.idp.${s}`),
      ...["rendered", "pending", "applied", "superseded", "failed"].map((s) => `status.configVersion.${s}`),
      ...PLATFORM_ROLES.map((r) => `roles.${r}`),
      ...["restart", "reconfigure", "backup", "upgrade", "restore", "quarantine", "release"].map((a) => `platform.instance.act.${a}`),
      ...["quarantine", "release"].flatMap((a) => [`platform.instance.${a}Title`, `platform.instance.${a}Desc`]),
      ...["edit", "disable", "grantSA", "revokeSA"].flatMap((a) => [`platform.users.act.${a}`, `platform.users.actLabel.${a}`]),
      ...LIMIT_FIELDS.map((k) => `platform.plans.limit.${k}`),
      ...["approval_ttl_hours", "quota_max_tenants", "maintenance"].map((k) => `platform.settings.desc.${k}`),
      ...["direct", "vps_gateway"].map((m) => `platform.host.entryModes.${m}`),
      ...["no_heartbeat", "heartbeat_stale", "heartbeat_failed", "no_probe", "not_deployed"].map((r) => `health.reason.${r}`),
      ...["platform", "tenant"].map((s) => `platform.idps.scopes.${s}`),
      ...Object.keys(APPROVAL_ACTION_PERMISSION).map((a) => `platform.approvalActions.${a.replaceAll(".", "_")}`),
    ];
    expect(keys.filter((k) => !has(vi as Tree, k) || !has(en as Tree, k))).toEqual([]);
  });
});
