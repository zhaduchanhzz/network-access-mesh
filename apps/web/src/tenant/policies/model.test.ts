// Hàm thuần của trang Policies (P4-T11): kiểm sơ bộ cấu trúc, thân request luôn có `grants` mảng, quy tắc hiện nút duyệt
// (4-eyes / self-review / chỉ Owner), stale base, rollback, tên principal; biểu thức ip/SSH user trùng với server Go.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { current, G_ENG, ME_IDENTITY, OTHER_IDENTITY, SOURCE, T_WEB, V1, V2, version } from "../../test/policies";
import {
  ackRulesInReport,
  baseCode,
  canRollbackTo,
  findingsAt,
  IP_PROTO_RE,
  isCidrRef,
  isEditable,
  isStaleBase,
  localProblems,
  namesFrom,
  principalLabel,
  reviewActions,
  sameSource,
  splitTokens,
  SSH_USER_RE,
  toSourceBody,
  type PolicyFinding,
} from "./model";

const GO = readFileSync(join(import.meta.dirname, "../../../../../internal/policies/model.go"), "utf8");

function goRegex(name: string): string {
  const m = new RegExp(`${name}\\s*=\\s*regexp\\.MustCompile\\(\`([^\`]+)\`\\)`).exec(GO);
  if (!m?.[1]) throw new Error(`${name} không có trong model.go`);
  return m[1];
}

describe("parity với internal/policies/model.go", () => {
  it("ipRE và sshUserRE trùng nguyên văn", () => {
    expect(IP_PROTO_RE.source).toBe(goRegex("ipRE"));
    expect(SSH_USER_RE.source).toBe(goRegex("sshUserRE"));
  });
  it("vị trí và kiểu principal trùng positionTypes", () => {
    expect(GO).toContain("posVia:      {PrincipalTag}");
    expect(GO).toContain("posApprover: {PrincipalUser, PrincipalGroup, PrincipalTag}");
  });
});

describe("kiểm sơ bộ", () => {
  it("cidr", () => {
    for (const ok of ["*", "10.0.0.0/8", "10.0.0.1", "fd7a:115c:a1e0::/48", "::1", "192.168.1.0/32"]) expect(isCidrRef(ok), ok).toBe(true);
    for (const bad of ["", "10.0.0.0/33", "300.0.0.1", "eng", "10.0.0.0/8/1", "fd7a::/129", "group:eng"]) expect(isCidrRef(bad), bad).toBe(false);
  });

  it("thân request luôn có grants là mảng; trường rỗng bị bỏ; xác nhận giữ nguyên", () => {
    const body = toSourceBody({
      grants: [{ src: [{ type: "autogroup", ref: "member" }], dst: [{ type: "cidr", ref: "*" }], ip: ["*"], via: [] }],
      ssh: [{ action: "accept", src: [], dst: [], users: [], check_period: "" }],
      auto_approvers: { routes: {}, exit_node: [] },
      acknowledgements: [{ rule: "L4", reason: "đã duyệt với khách" }],
    });
    expect(body).toEqual({
      grants: [{ src: [{ type: "autogroup", ref: "member" }], dst: [{ type: "cidr", ref: "*" }], ip: ["*"] }],
      ssh: [{ action: "accept", src: [], dst: [], users: [] }],
      acknowledgements: [{ rule: "L4", reason: "đã duyệt với khách" }],
    });
    // nội dung hỏng (thiếu grants) vẫn thành mảng rỗng — không bao giờ gửi body thiếu grants
    expect(toSourceBody({} as never).grants).toEqual([]);
    expect(sameSource({ grants: [], ssh: [] }, { grants: [] })).toBe(true);
  });

  it("localProblems: thiếu principal, ip sai, user SSH sai, lý do xác nhận ngắn", () => {
    const p = localProblems({
      grants: [{ src: [], dst: [{ type: "cidr", ref: "10.0.0.1/40" }], ip: ["tcp:99999999"] }],
      ssh: [{ action: "accept", src: [{ type: "autogroup", ref: "member" }], dst: [{ type: "autogroup", ref: "self" }], users: ["Root!"] }],
      acknowledgements: [{ rule: "L10", reason: "ok" }],
    });
    expect(p.map((x) => `${x.path}:${x.key.split(".").pop() ?? ""}`)).toEqual([
      "grants[0].src:principalsRequired",
      "grants[0].dst[0]:badCidr",
      "grants[0].ip[0]:badIp",
      "ssh[0].users[0]:badSshUser",
      "acknowledgements[0].reason:ackReason",
    ]);
    expect(localProblems(SOURCE)).toEqual([]);
    expect(localProblems({ grants: [{ src: [{ type: "autogroup", ref: "member" }], dst: [{ type: "autogroup", ref: "member" }] }] })[0]?.key).toBe(
      "policies.local.ipRequired",
    );
  });

  it("splitTokens", () => {
    expect(splitTokens(" tcp:443, udp:53  *,,")).toEqual(["tcp:443", "udp:53", "*"]);
  });
});

describe("vòng đời", () => {
  const opts = { identityId: ME_IDENTITY, canEdit: true, canApprove: true, role: "tenant_admin" };

  it("4-eyes: người soạn/gửi không có nút duyệt; người khác có; ai có quyền duyệt cũng từ chối được", () => {
    const pending = version(V2, { state: "pending_approval", submitted_by: ME_IDENTITY });
    expect(reviewActions(pending, { ...opts, fourEyes: true })).toEqual({ submit: false, approve: false, reject: true, blockedBy: "self" });
    expect(reviewActions(pending, { ...opts, fourEyes: true, identityId: OTHER_IDENTITY })).toEqual({ submit: false, approve: true, reject: true, blockedBy: null });
    // người gửi khác người soạn: cũng không tự duyệt
    const submittedByOther = version(V2, { state: "pending_approval", created_by: ME_IDENTITY, submitted_by: OTHER_IDENTITY });
    expect(reviewActions(submittedByOther, { ...opts, fourEyes: true, identityId: OTHER_IDENTITY }).blockedBy).toBe("self");
    // validated + 4-eyes: chỉ gửi duyệt
    expect(reviewActions(version(V2, { state: "validated" }), { ...opts, fourEyes: true })).toEqual({ submit: true, approve: false, reject: false, blockedBy: null });
  });

  it("self-review khi tắt 4-eyes; xác nhận L4/L12 ⇒ chỉ Tenant Owner", () => {
    const validated = version(V2, { state: "validated" });
    expect(reviewActions(validated, { ...opts, fourEyes: false })).toEqual({ submit: false, approve: true, reject: false, blockedBy: null });
    const ownerAck = version(V2, {
      state: "validated",
      validation_report: {
        engine: "p4-t10",
        result: "passed",
        errors: [],
        warnings: [{ rule: "L4", severity: "warning", code: "wildcard_destination", message: "m", requires_ack: true, owner_only: true, acknowledged: true }],
        info: [],
        tests: [],
      },
    });
    expect(reviewActions(ownerAck, { ...opts, fourEyes: false }).blockedBy).toBe("owner");
    expect(reviewActions(ownerAck, { ...opts, fourEyes: false, role: "tenant_owner" }).approve).toBe(true);
    expect(reviewActions(version(V2, { kind: "baseline" }), { ...opts, fourEyes: false }).approve).toBe(false);
    expect(reviewActions(validated, { ...opts, fourEyes: false, canApprove: false }).approve).toBe(false);
  });

  it("isEditable / isStaleBase / canRollbackTo", () => {
    expect(isEditable(version(V2))).toBe(true);
    expect(isEditable(version(V2, { desired: true }))).toBe(false);
    expect(isEditable(version(V2, { state: "superseded" }))).toBe(false);
    expect(isEditable(version(V2, { kind: "baseline", source: undefined, hujson: "{}" }))).toBe(false);
    const cur = current();
    expect(isStaleBase(version(V2, { parent_version_id: V1 }), cur)).toBe(false);
    expect(isStaleBase(version(V2, { parent_version_id: "0190f000-0000-7000-8000-0000000000ff" }), cur)).toBe(true);
    expect(isStaleBase(version(V2, { parent_version_id: undefined }), current({ desired: undefined }))).toBe(false);
    expect(canRollbackTo(version(V2, { state: "superseded", approved_at: "2026-11-19T00:00:00Z" }))).toBe(true);
    expect(canRollbackTo(version(V2, { state: "superseded" }))).toBe(false);
    expect(canRollbackTo(version(V2, { state: "approved", approved_at: "x", desired: true }))).toBe(false);
  });

  it("báo cáo: luật cần xác nhận, phát hiện theo đường dẫn, mã gốc", () => {
    const f = (rule: string, path: string, extra: Partial<PolicyFinding> = {}): PolicyFinding => ({ rule, severity: "error", code: "c", message: "m", path, ...extra });
    const report = {
      engine: "p4-t10",
      result: "failed" as const,
      errors: [f("L4", "grants[0].dst[0]", { requires_ack: true, code: "wildcard_destination_ack_required" }), f("L6", "grants[10].src[0].ref")],
      warnings: [f("L10", "ssh[0].action", { requires_ack: true, acknowledged: true, severity: "warning" })],
      info: [],
      tests: [],
    };
    expect(ackRulesInReport(report)).toEqual(["L4", "L10"]);
    expect(findingsAt(report.errors, "grants[0]").map((x) => x.rule)).toEqual(["L4"]);
    expect(findingsAt(report.errors, "grants[1]")).toEqual([]);
    expect(baseCode("wildcard_destination_ack_required")).toBe("wildcard_destination");
  });
});

describe("tên principal", () => {
  it("theo danh mục, rồi tên của server, rồi id", () => {
    const book = { users: new Map([["m1", "a@example.test"]]), groups: new Map([[G_ENG, "eng"]]), tags: new Map([[T_WEB, "tag:web"]]), resources: new Map<string, string>() };
    const extra = namesFrom([{ type: "resource", ref: "r1", name: "db" }]);
    expect(principalLabel({ type: "user", ref: "m1" }, book)).toBe("a@example.test");
    expect(principalLabel({ type: "user", ref: "m2" }, book)).toBe("mg-m2@");
    expect(principalLabel({ type: "group", ref: G_ENG }, book)).toBe("group:eng");
    expect(principalLabel({ type: "tag", ref: T_WEB }, book)).toBe("tag:web");
    expect(principalLabel({ type: "resource", ref: "r1" }, book, extra)).toBe("db");
    expect(principalLabel({ type: "resource", ref: "r2" }, book, extra)).toBe("r2");
    expect(principalLabel({ type: "autogroup", ref: "self" }, book)).toBe("autogroup:self");
    expect(principalLabel({ type: "cidr", ref: "*" }, book)).toBe("*");
  });
});
