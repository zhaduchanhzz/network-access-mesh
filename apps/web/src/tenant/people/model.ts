// Mô hình của Users / Groups / Invitations (P4-T09a, §12.3) — quy tắc role của §8.4 (bất biến 3, 3a) phía UI.
// Mọi hàm ở đây chỉ quyết định cái gì ĐƯỢC HIỆN (UX); server mới là nơi quyết định (authz.GuardMembershipChange trong
// transaction ghi — P4-T09): một thao tác UI ẩn vẫn bị server từ chối (403), một thao tác UI hiện vẫn có thể bị 403/409/412.
import type { components } from "../../api/schema";
import type { Tone } from "../../ui/Status";

export type Membership = components["schemas"]["Membership"];
export type Offboarding = components["schemas"]["MembershipOffboarding"];
export type Group = components["schemas"]["Group"];
export type GroupMember = components["schemas"]["GroupMember"];
export type Invitation = components["schemas"]["Invitation"];
export type InvitationRole = components["schemas"]["InvitationRole"];
export type InvitationStatus = components["schemas"]["InvitationStatus"];
export type ApprovalRequest = components["schemas"]["ApprovalRequest"];
export type RoleBelowAdmin = components["schemas"]["MembershipRoleUpdate"]["role"];
export type AdminRoleTarget = components["schemas"]["MembershipAdminRoleUpdate"]["role"];

/** Thứ bậc role phạm vi tenant — trùng cột `rank` của database/seeds/rbac.sql (test model.test.ts đọc file seed). */
export const TENANT_ROLE_RANK: Readonly<Record<string, number>> = {
  tenant_owner: 5,
  tenant_admin: 4,
  tenant_operator: 3,
  tenant_viewer: 2,
  end_user: 1,
};

/** Role tenant theo thứ bậc giảm dần (bộ lọc, hộp chọn). */
export const TENANT_ROLES = ["tenant_owner", "tenant_admin", "tenant_operator", "tenant_viewer", "end_user"] as const;
/** Role dưới Tenant Admin — `PUT /users/{id}/role` chỉ đổi giữa các role này (MembershipRoleUpdate). */
export const ROLES_BELOW_ADMIN = ["tenant_operator", "tenant_viewer", "end_user"] as const satisfies readonly RoleBelowAdmin[];
/** Role ghi được vào lời mời (InvitationRole) — không bao giờ Owner. */
export const INVITATION_ROLES = ["tenant_admin", "tenant_operator", "tenant_viewer", "end_user"] as const satisfies readonly InvitationRole[];
export const MEMBERSHIP_STATUSES = ["active", "locked", "offboarded"] as const;
export const INVITATION_STATUSES = ["pending", "accepted", "revoked", "expired"] as const satisfies readonly InvitationStatus[];
export const OFFBOARD_STATES = ["pending", "applied", "failed"] as const satisfies readonly Offboarding["state"][];

type Assert<T extends true> = T;
/** Lỗi typecheck ⇒ spec đổi tập role/trạng thái mà danh sách ở đây (và bản dịch people.*) chưa theo. */
export type AllBelowAdminListed = Assert<[Exclude<RoleBelowAdmin, (typeof ROLES_BELOW_ADMIN)[number]>] extends [never] ? true : false>;
export type AllInvitationRolesListed = Assert<[Exclude<InvitationRole, (typeof INVITATION_ROLES)[number]>] extends [never] ? true : false>;
export type AllInvitationStatusesListed = Assert<
  [Exclude<InvitationStatus, (typeof INVITATION_STATUSES)[number]>] extends [never] ? true : false
>;

/** Tên group (GroupCreate.name của spec): render thành `group:<name>` của policy. */
export const GROUP_NAME_RE = /^[a-z][a-z0-9-]{0,49}$/;
export const GROUP_DESCRIPTION_MAX = 1000;
/** Một PUT …/members: tối đa 1000 (spec); group sensitive: một yêu cầu phê duyệt tối đa 200 thành viên. */
export const GROUP_MEMBERS_MAX = 1000;
export const SENSITIVE_MEMBERS_MAX = 200;
export const APPROVAL_ACTION_GROUP_MEMBERS = "tenant.group.set_members";
export const IDP_INVITE_JOB = "member.idp_invite";
export const PAGE_SIZE = 25;

const OWNER = "tenant_owner";
const ADMIN = "tenant_admin";

function rank(role: string | null | undefined): number {
  return role && Object.hasOwn(TENANT_ROLE_RANK, role) ? (TENANT_ROLE_RANK[role] ?? 0) : 0;
}

/** Quy tắc 3a: Owner không bị giới hạn; người khác chỉ tác động lên role thấp hơn hẳn role của mình. Role lạ ⇒ không. */
export function outranks(actor: string | null | undefined, target: string | null | undefined): boolean {
  if (rank(actor) === 0 || rank(target) === 0) return false;
  return actor === OWNER || rank(target) < rank(actor);
}

export function isBelowAdmin(role: string): role is RoleBelowAdmin {
  return (ROLES_BELOW_ADMIN as readonly string[]).includes(role);
}

/** Thao tác giữ nguyên role của đích (khóa/mở khóa, thu hồi session, offboard — CheckMembershipAction): không trên
 * chính mình (UX), không trên membership đã offboard (trạng thái cuối), và theo 3a. */
export function canActOnMember(actorRole: string, actorMembershipId: string | null, target: Membership): boolean {
  return target.id !== actorMembershipId && target.status !== "offboarded" && outranks(actorRole, target.role);
}

/** Thao tác đổi role nào dùng operation nào (§8.4 bất biến 4 — hai operation, mỗi operation một quyền):
 * chạm Tenant Admin hoặc đổi một Owner ⇒ `admin-role` (Owner, step-up); giữa các role dưới Admin ⇒ `role`. */
export function roleOperation(current: string, next: string): "role" | "admin-role" | null {
  if (current === next || !(next === ADMIN || isBelowAdmin(next))) return null;
  if (isBelowAdmin(current) && isBelowAdmin(next)) return "role";
  return current === ADMIN || current === OWNER || isBelowAdmin(current) ? "admin-role" : null;
}

/** Role mới người gọi được chọn cho đích (đã bỏ role hiện tại), theo quyền của role người gọi (`can`) và quy tắc 3, 3a:
 * không bao giờ Owner (chỉ qua chuyển quyền sở hữu); role hiện tại và role mới đều thấp hơn hẳn người gọi trừ Owner. */
export function assignableRoles(
  actorRole: string,
  can: (permission: string) => boolean,
  target: Membership,
  actorMembershipId: string | null,
): string[] {
  if (target.status === "offboarded" || target.id === actorMembershipId || !outranks(actorRole, target.role)) return [];
  return [ADMIN, ...ROLES_BELOW_ADMIN].filter((next) => {
    const op = roleOperation(target.role, next);
    if (op === null || !outranks(actorRole, next)) return false;
    return can(op === "role" ? "tenant.membership:assign" : "tenant.membership:assign_admin");
  });
}

/** Role người gọi được ghi vào lời mời (GuardInvitationRole: thấp hơn hẳn, trừ Owner). */
export function invitableRoles(actorRole: string): InvitationRole[] {
  return INVITATION_ROLES.filter((r) => outranks(actorRole, r));
}

/** Chuyển quyền sở hữu: chỉ Owner, đích `active` chưa là Owner, không phải chính mình. */
export function canTransferOwnership(actorRole: string, can: (permission: string) => boolean, target: Membership, actorMembershipId: string | null): boolean {
  return actorRole === OWNER && can("tenant.membership:assign_admin") && target.status === "active" && target.role !== OWNER && target.id !== actorMembershipId;
}

export function membershipTone(status: string): Tone {
  return status === "active" ? "ok" : status === "locked" ? "warn" : "neutral";
}

export function offboardTone(state: Offboarding["state"]): Tone {
  return state === "applied" ? "ok" : state === "failed" ? "danger" : "warn";
}

export function invitationTone(status: string): Tone {
  return status === "pending" ? "warn" : status === "accepted" ? "ok" : "neutral";
}

/** Giá trị người dùng phải gõ lại để xác nhận offboard: email nếu có, nếu không thì tên hiển thị. */
export function offboardConfirmValue(m: Membership): string {
  return m.email && m.email.trim() !== "" ? m.email : m.display_name;
}

/** Danh sách id thành viên đã sắp xếp, không trùng (so sánh tập thay đổi và gửi lên). */
export function memberSet(ids: Iterable<string>): string[] {
  return [...new Set(ids)].sort();
}

export function sameSet(a: readonly string[], b: readonly string[]): boolean {
  const x = memberSet(a);
  const y = memberSet(b);
  return x.length === y.length && x.every((v, i) => v === y[i]);
}

/** Số thành viên trong payload của yêu cầu phê duyệt `tenant.group.set_members` (null nếu payload lạ). */
export function approvalMemberCount(a: ApprovalRequest): number | null {
  const ids = (a.payload as { membership_ids?: unknown }).membership_ids;
  return Array.isArray(ids) ? ids.length : null;
}
