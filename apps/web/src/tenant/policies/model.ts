// Mô hình phía trình duyệt của trang Policies (P4-T11) — hàm thuần, có test (model.test.ts). Nội dung soạn là đúng
// `PolicySource` của spec (§7.2, §13.3): principal là tham chiếu có kiểu {type, ref} (membership/group/tag/resource theo
// id; autogroup, cidr theo vị trí) — không bao giờ là chuỗi tự do. Mọi quyết định (render, lint L1–L13, CheckPolicy,
// 4-eyes, step-up, stale_base) là của server; ở đây chỉ kiểm sơ bộ để hướng dẫn và để không gửi nội dung chắc chắn hỏng.
import type { components } from "../../api/schema";

export type PolicySource = components["schemas"]["PolicySource"];
export type PolicyGrant = components["schemas"]["PolicyGrant"];
export type PolicySSHRule = components["schemas"]["PolicySSHRule"];
export type PolicyPrincipal = components["schemas"]["PolicyPrincipal"];
export type PrincipalType = PolicyPrincipal["type"];
export type PolicyAcknowledgement = components["schemas"]["PolicyAcknowledgement"];
export type AckRule = PolicyAcknowledgement["rule"];
export type PolicyVersion = components["schemas"]["PolicyVersion"];
export type PolicyVersionState = PolicyVersion["state"];
export type PolicyFinding = components["schemas"]["PolicyFinding"];
export type PolicyReport = components["schemas"]["PolicyValidationReport"];
export type PolicyCurrent = components["schemas"]["PolicyCurrent"];
export type PolicyApplication = components["schemas"]["PolicyApplication"];
export type PolicyDiff = components["schemas"]["PolicyDiff"];
export type PrincipalName = components["schemas"]["PolicyPrincipalName"];
export type Tag = components["schemas"]["Tag"];

/** Vị trí của một danh sách principal — mỗi vị trí nhận kiểu riêng (bảng positionTypes của internal/policies/model.go). */
export type Position = "grantSrc" | "grantDst" | "via" | "sshSrc" | "sshDst" | "approver";

export const POSITION_TYPES: Readonly<Record<Position, readonly PrincipalType[]>> = {
  grantSrc: ["user", "group", "tag", "resource", "autogroup", "cidr"],
  grantDst: ["user", "group", "tag", "resource", "autogroup", "cidr"],
  via: ["tag"],
  sshSrc: ["user", "group", "tag", "autogroup"],
  sshDst: ["user", "tag", "autogroup"],
  approver: ["user", "group", "tag"],
};

/** Autogroup chọn được ở mỗi vị trí (`danger-all` không có trong bộ chọn — L5 luôn chặn nó ở nguồn). */
export const POSITION_AUTOGROUPS: Readonly<Partial<Record<Position, readonly string[]>>> = {
  grantSrc: ["member", "tagged"],
  grantDst: ["member", "tagged", "self", "internet"],
  sshSrc: ["member", "tagged"],
  sshDst: ["self", "member", "tagged"],
};

export const PRINCIPAL_TYPES = ["user", "group", "tag", "resource", "autogroup", "cidr"] as const satisfies readonly PrincipalType[];
export const ACK_RULES = ["L4", "L7", "L10", "L12", "L13"] as const satisfies readonly AckRule[];
/** Xác nhận chỉ có hiệu lực khi Tenant Owner duyệt version (§7.2, P4-T10). */
export const OWNER_ACK_RULES: readonly AckRule[] = ["L4", "L12"];
export const VERSION_STATES = [
  "draft",
  "validated",
  "pending_approval",
  "approved",
  "rejected",
  "superseded",
] as const satisfies readonly PolicyVersionState[];
type MissingState = Exclude<PolicyVersionState, (typeof VERSION_STATES)[number]>;
type Assert<T extends true> = T;
/** Lỗi typecheck ở đây ⇒ spec thêm trạng thái version chưa có ở đây (và chưa có bản dịch). */
export type AllVersionStatesListed = Assert<[MissingState] extends [never] ? true : false>;

/** Cùng biểu thức của server (`ipRE` — proto:port của grants `ip`). */
export const IP_PROTO_RE =
  /^(?:(?:tcp|udp|sctp|icmp|ipv6-icmp|igmp|esp|ah|gre|[0-9]{1,3}):)?(?:\*|[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*)$/;
/** Cùng biểu thức của server (`sshUserRE`). */
export const SSH_USER_RE = /^(?:root|autogroup:nonroot|[a-z_][a-z0-9_.-]{0,31})$/;
const IPV4 = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6 = /^[0-9a-f:]+(?:\.[0-9.]+)?$/i;
export const TAG_NAME_RE = /^tag:[a-z][a-z0-9-]{0,49}$/;
export const MIN_ACK_REASON = 5;
export const MAX_ACK_REASON = 500;

/** Kiểm sơ bộ một principal `cidr`: `*`, địa chỉ IPv4/IPv6 hoặc prefix (server kiểm bit host và dạng chuẩn). */
export function isCidrRef(ref: string): boolean {
  if (ref === "*") return true;
  const [addr = "", bits, ...rest] = ref.split("/");
  if (rest.length > 0) return false;
  const v4 = IPV4.test(addr);
  const v6 = !v4 && addr.includes(":") && IPV6.test(addr);
  if (!v4 && !v6) return false;
  if (bits === undefined) return true;
  if (!/^\d{1,3}$/.test(bits)) return false;
  return Number(bits) <= (v4 ? 32 : 128);
}

export function emptySource(): PolicySource {
  return { grants: [], ssh: [] };
}

export function emptyGrant(): PolicyGrant {
  return { src: [], dst: [], ip: [] };
}

/** Bản sao sâu (nội dung chỉ là JSON). */
export function cloneSource(s: PolicySource): PolicySource {
  return JSON.parse(JSON.stringify(s)) as PolicySource;
}

/**
 * Thân request `source` luôn có `grants` là MẢNG (L1: thiếu `grants`/`grants: null` = allow-all upstream) và không có
 * danh sách rỗng ở trường tùy chọn (`via`, `ip` rỗng của grant có `app`, `auto_approvers` rỗng, `acknowledgements` rỗng).
 */
export function toSourceBody(s: PolicySource): PolicySource {
  const grants = (Array.isArray(s.grants) ? s.grants : []).map((g) => {
    const out: PolicyGrant = { src: g.src, dst: g.dst };
    if (g.ip && g.ip.length > 0) out.ip = g.ip;
    if (g.app && Object.keys(g.app).length > 0) out.app = g.app;
    if (g.via && g.via.length > 0) out.via = g.via;
    return out;
  });
  const body: PolicySource = { grants, ssh: (s.ssh ?? []).map((r) => (r.check_period ? r : { action: r.action, src: r.src, dst: r.dst, users: r.users })) };
  const aa = s.auto_approvers;
  const routes = aa?.routes && Object.keys(aa.routes).length > 0 ? aa.routes : undefined;
  const exit = aa?.exit_node && aa.exit_node.length > 0 ? aa.exit_node : undefined;
  if (routes || exit) body.auto_approvers = { ...(routes ? { routes } : {}), ...(exit ? { exit_node: exit } : {}) };
  if (s.acknowledgements && s.acknowledgements.length > 0) body.acknowledgements = s.acknowledgements;
  return body;
}

/** So sánh nội dung (bỏ khác biệt chỉ do trường rỗng). */
export function sameSource(a: PolicySource, b: PolicySource): boolean {
  return JSON.stringify(toSourceBody(a)) === JSON.stringify(toSourceBody(b));
}

export interface LocalProblem {
  path: string;
  key: string;
}

/** Kiểm sơ bộ trước khi lưu — cùng ràng buộc cấu trúc với `PolicySource.Check` của server (không thay nó). */
export function localProblems(s: PolicySource): LocalProblem[] {
  const out: LocalProblem[] = [];
  const principals = (path: string, ps: readonly PolicyPrincipal[] | undefined, required: boolean) => {
    if (!ps || ps.length === 0) {
      if (required) out.push({ path, key: "policies.local.principalsRequired" });
      return;
    }
    ps.forEach((p, i) => {
      if (p.type === "cidr" && !isCidrRef(p.ref)) out.push({ path: `${path}[${i}]`, key: "policies.local.badCidr" });
    });
  };
  const grants: readonly PolicyGrant[] | undefined = Array.isArray(s.grants) ? s.grants : undefined;
  if (!grants) out.push({ path: "grants", key: "policies.local.grantsRequired" });
  (grants ?? []).forEach((g, i) => {
    const p = `grants[${i}]`;
    principals(`${p}.src`, g.src, true);
    principals(`${p}.dst`, g.dst, true);
    if ((!g.ip || g.ip.length === 0) && (!g.app || Object.keys(g.app).length === 0)) out.push({ path: `${p}.ip`, key: "policies.local.ipRequired" });
    (g.ip ?? []).forEach((ip, j) => {
      if (!IP_PROTO_RE.test(ip)) out.push({ path: `${p}.ip[${j}]`, key: "policies.local.badIp" });
    });
  });
  (s.ssh ?? []).forEach((r, i) => {
    const p = `ssh[${i}]`;
    principals(`${p}.src`, r.src, true);
    principals(`${p}.dst`, r.dst, true);
    if (r.users.length === 0) out.push({ path: `${p}.users`, key: "policies.local.usersRequired" });
    r.users.forEach((u, j) => {
      if (!SSH_USER_RE.test(u)) out.push({ path: `${p}.users[${j}]`, key: "policies.local.badSshUser" });
    });
  });
  for (const [prefix, ps] of Object.entries(s.auto_approvers?.routes ?? {})) {
    if (!isCidrRef(prefix) || prefix === "*" || !prefix.includes("/")) out.push({ path: `auto_approvers.routes[${prefix}]`, key: "policies.local.badCidr" });
    principals(`auto_approvers.routes[${prefix}]`, ps, true);
  }
  (s.acknowledgements ?? []).forEach((a, i) => {
    const n = runeLength(a.reason.trim());
    if (n < MIN_ACK_REASON || n > MAX_ACK_REASON) out.push({ path: `acknowledgements[${i}].reason`, key: "policies.local.ackReason" });
  });
  return out;
}

/** Số ký tự (code point) — như utf8.RuneCountInString của server. */
export function runeLength(s: string): number {
  return Array.from(s).length;
}

/** Tách một ô nhập danh sách (dấu phẩy hoặc khoảng trắng) thành phần tử. */
export function splitTokens(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter((x) => x !== "");
}

// ---------------------------------------------------------------------------------------------------- vòng đời

/** Version sửa được qua PATCH (server: 409 với desired, version nền tảng/HuJSON, superseded/rejected). */
export function isEditable(v: PolicyVersion): boolean {
  return v.kind === "user" && v.source !== undefined && !v.desired && v.state !== "superseded" && v.state !== "rejected";
}

/** Người gọi là người soạn hoặc người gửi — khi 4-eyes bật thì không được duyệt (server trả 403 self_approval). */
export function isAuthorOrSubmitter(v: PolicyVersion, identityId: string | null | undefined): boolean {
  if (!identityId) return false;
  return v.created_by === identityId || v.submitted_by === identityId;
}

/** Báo cáo có xác nhận chỉ Owner được làm (L4/L12) ⇒ chỉ Tenant Owner duyệt được (server: 403). */
export function needsOwnerApproval(v: PolicyVersion): boolean {
  return (v.validation_report?.warnings ?? []).some((f) => f.acknowledged === true && f.owner_only === true);
}

export type ReviewAction = "submit" | "approve" | "reject" | "none";

/**
 * Nút duyệt nào hiện cho người gọi (UX — server quyết định): 4-eyes bật ⇒ gửi duyệt từ `validated`, duyệt/từ chối
 * từ `pending_approval` bởi người KHÁC người soạn/gửi; tắt ⇒ người soạn tự xác nhận (self-review) từ `validated`.
 */
export function reviewActions(
  v: PolicyVersion,
  opts: { fourEyes: boolean; identityId: string | null | undefined; canEdit: boolean; canApprove: boolean; role: string },
): { submit: boolean; approve: boolean; reject: boolean; blockedBy: "self" | "owner" | null } {
  const res = { submit: false, approve: false, reject: false, blockedBy: null as "self" | "owner" | null };
  if (v.kind !== "user") return res;
  res.submit = opts.fourEyes && opts.canEdit && v.state === "validated";
  const reviewable = v.state === "pending_approval" || (!opts.fourEyes && v.state === "validated");
  if (reviewable && opts.canApprove) {
    if (opts.fourEyes && isAuthorOrSubmitter(v, opts.identityId)) res.blockedBy = "self";
    else if (needsOwnerApproval(v) && opts.role !== "tenant_owner") res.blockedBy = "owner";
    else res.approve = true;
  }
  // từ chối: mọi người có quyền duyệt, kể cả người soạn (rút lại) — server cho phép
  res.reject = opts.canApprove && v.state === "pending_approval";
  return res;
}

/** Version đã duyệt có base đã cũ: cha của nó không còn là version mong muốn ⇒ apply sẽ nhận 409 stale_base. */
export function isStaleBase(v: PolicyVersion, current: PolicyCurrent | undefined): boolean {
  if (!current) return false;
  const desired = current.desired?.id;
  if (v.desired) return false;
  return (v.parent_version_id ?? null) !== (desired ?? null);
}

/** Rollback được về version này: nội dung có kiểu, đã từng được duyệt, không phải version đang mong muốn. */
export function canRollbackTo(v: PolicyVersion): boolean {
  return v.kind === "user" && v.source !== undefined && !v.desired && v.approved_at !== undefined && (v.state === "approved" || v.state === "superseded");
}

/** Luật mà báo cáo đòi xác nhận (lỗi `<code>_ack_required` hoặc cảnh báo đã xác nhận). */
export function ackRulesInReport(r: PolicyReport | undefined): AckRule[] {
  const set = new Set<AckRule>();
  for (const f of [...(r?.errors ?? []), ...(r?.warnings ?? [])]) {
    if (f.requires_ack === true && (ACK_RULES as readonly string[]).includes(f.rule)) set.add(f.rule as AckRule);
  }
  return ACK_RULES.filter((x) => set.has(x));
}

/** Phát hiện của một đường dẫn (và con của nó): `grants[0]` gồm `grants[0].dst[1].ref`. */
export function findingsAt(fs: readonly PolicyFinding[], path: string): PolicyFinding[] {
  return fs.filter((f) => f.path === path || (f.path ?? "").startsWith(`${path}.`) || (f.path ?? "").startsWith(`${path}[`));
}

/** Mã phát hiện không có hậu tố "_ack_required" (khóa dịch chung cho lỗi chưa xác nhận và cảnh báo đã xác nhận). */
export function baseCode(code: string): string {
  return code.endsWith("_ack_required") ? code.slice(0, -"_ack_required".length) : code;
}

/** sha256 rút gọn để hiển thị (đầy đủ ở title). */
export function shortSha(sha: string | null | undefined): string {
  return sha ? sha.slice(0, 12) : "";
}

// ---------------------------------------------------------------------------------------------------- tên principal

export interface NameBook {
  users: ReadonlyMap<string, string>;
  groups: ReadonlyMap<string, string>;
  tags: ReadonlyMap<string, string>;
  resources: ReadonlyMap<string, string>;
}

/** Tên hiển thị của một principal: theo danh mục đã tải, nếu không có thì tên HuJSON server trả, cuối cùng là id. */
export function principalLabel(p: PolicyPrincipal, book: NameBook, extra: ReadonlyMap<string, string> = new Map()): string {
  switch (p.type) {
    case "autogroup":
      return `autogroup:${p.ref}`;
    case "cidr":
      return p.ref;
    case "user":
      return book.users.get(p.ref) ?? extra.get(`user/${p.ref}`) ?? `mg-${p.ref}@`;
    case "group":
      return book.groups.has(p.ref) ? `group:${book.groups.get(p.ref) ?? ""}` : (extra.get(`group/${p.ref}`) ?? p.ref);
    case "tag":
      return book.tags.get(p.ref) ?? extra.get(`tag/${p.ref}`) ?? p.ref;
    case "resource":
      return book.resources.get(p.ref) ?? extra.get(`resource/${p.ref}`) ?? p.ref;
  }
}

/** Bảng tên phụ từ `principals` của import/export ("type/ref" → tên HuJSON). */
export function namesFrom(ps: readonly PrincipalName[] | undefined, into: Map<string, string> = new Map()): Map<string, string> {
  for (const p of ps ?? []) into.set(`${p.type}/${p.ref}`, p.name);
  return into;
}
