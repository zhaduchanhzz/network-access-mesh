// Mục điều hướng của hai console (§12.2, §12.3 — bảng "Truy vết màn hình → task"). Mỗi mục cần đúng một permission
// đọc của ma trận §8.5/§8.6 để hiện (UX — server vẫn quyết định). Mục chưa xây (`available: false`) hiện trang
// "chưa khả dụng" kèm task sẽ xây nó (§12.4: không mock, không số liệu giả); task UI thay `available` khi hoàn tất.
// Thứ tự trong mảng = thứ tự ưu tiên của trang chủ tenant (mục đầu tiên role được xem); sidebar nhóm theo NAV_GROUPS.
import { can } from "../auth/permissions";

export interface NavItem {
  /** segment đường dẫn dưới /t/:tenantId hoặc /platform */
  path: string;
  /** khóa i18n của nhãn */
  labelKey: string;
  group: NavGroup;
  permission: string;
  /** task ở §20 xây màn hình này */
  task: string;
  /** "mvp" hoặc "post_mvp" (Phase 6+, §12.3) */
  phase: "mvp" | "post_mvp";
  available: boolean;
}

export type NavGroup = "overview" | "devices" | "access" | "network" | "people" | "governance" | "operations";

export const TENANT_NAV: readonly NavItem[] = [
  { path: "overview", labelKey: "nav.tenant.overview", group: "overview", permission: "tenant.dashboard:read", task: "P4-T04", phase: "mvp", available: true },
  { path: "devices", labelKey: "nav.tenant.devices", group: "devices", permission: "tenant.device:read", task: "P4-T04", phase: "mvp", available: true },
  { path: "enroll", labelKey: "nav.tenant.enroll", group: "devices", permission: "tenant.enrollment:read", task: "P4-T08", phase: "mvp", available: false },
  { path: "enrollment-keys", labelKey: "nav.tenant.enrollmentKeys", group: "devices", permission: "tenant.enrollment:issue_privileged", task: "P4-T08", phase: "mvp", available: false },
  { path: "notifications", labelKey: "nav.tenant.notifications", group: "overview", permission: "tenant.notification:read", task: "P4-T04", phase: "mvp", available: true },
  { path: "relay", labelKey: "nav.tenant.relay", group: "network", permission: "tenant.relay:read", task: "P4-T04", phase: "mvp", available: true },
  { path: "policies", labelKey: "nav.tenant.policies", group: "access", permission: "tenant.policy:read", task: "P4-T11", phase: "mvp", available: true },
  { path: "tags", labelKey: "nav.tenant.tags", group: "access", permission: "tenant.tag:read", task: "P4-T11", phase: "mvp", available: true },
  { path: "routes", labelKey: "nav.tenant.routes", group: "network", permission: "tenant.route:read", task: "P4-T12", phase: "mvp", available: false },
  { path: "dns", labelKey: "nav.tenant.dns", group: "network", permission: "tenant.dns:read", task: "P4-T12", phase: "mvp", available: false },
  { path: "resources", labelKey: "nav.tenant.resources", group: "network", permission: "tenant.resource:read", task: "P4-T12", phase: "mvp", available: false },
  { path: "diagnostics", labelKey: "nav.tenant.diagnostics", group: "network", permission: "tenant.diagnostics:read", task: "P5-T08", phase: "mvp", available: false },
  { path: "users", labelKey: "nav.tenant.users", group: "people", permission: "tenant.user:read", task: "P4-T09a", phase: "mvp", available: true },
  { path: "groups", labelKey: "nav.tenant.groups", group: "people", permission: "tenant.group:read", task: "P4-T09a", phase: "mvp", available: true },
  { path: "invitations", labelKey: "nav.tenant.invitations", group: "people", permission: "tenant.invitation:manage", task: "P4-T09a", phase: "mvp", available: true },
  { path: "audit", labelKey: "nav.tenant.audit", group: "governance", permission: "tenant.audit:read", task: "P4-T13", phase: "mvp", available: false },
  { path: "approvals", labelKey: "nav.tenant.approvals", group: "governance", permission: "tenant.approval:read", task: "P4-T13", phase: "mvp", available: false },
  { path: "support-access", labelKey: "nav.tenant.supportAccess", group: "governance", permission: "tenant.support_grant:read", task: "P4-T13", phase: "mvp", available: false },
  { path: "settings", labelKey: "nav.tenant.settings", group: "governance", permission: "tenant.settings:read", task: "P4-T13", phase: "mvp", available: false },
  { path: "identity-provider", labelKey: "nav.tenant.identityProvider", group: "governance", permission: "tenant.idp:read", task: "P4-T13", phase: "mvp", available: false },
  { path: "usage", labelKey: "nav.tenant.usage", group: "operations", permission: "tenant.usage:read", task: "P6-T11", phase: "post_mvp", available: false },
  { path: "billing", labelKey: "nav.tenant.billing", group: "operations", permission: "tenant.billing:read", task: "P6-T11", phase: "post_mvp", available: false },
];

export const PLATFORM_NAV: readonly NavItem[] = [
  { path: "health", labelKey: "nav.platform.health", group: "overview", permission: "platform.health:read", task: "P4-T03", phase: "mvp", available: true },
  { path: "tenants", labelKey: "nav.platform.tenants", group: "overview", permission: "platform.tenant:read", task: "P4-T02", phase: "mvp", available: true },
  { path: "approvals", labelKey: "nav.platform.approvals", group: "governance", permission: "platform.approval:read", task: "P4-T02", phase: "mvp", available: true },
  { path: "jobs", labelKey: "nav.platform.jobs", group: "operations", permission: "platform.job:read", task: "P4-T02", phase: "mvp", available: true },
  { path: "instances", labelKey: "nav.platform.instances", group: "operations", permission: "platform.instance:read", task: "P4-T03", phase: "mvp", available: true },
  { path: "hosts", labelKey: "nav.platform.hosts", group: "operations", permission: "platform.host:read", task: "P4-T03", phase: "mvp", available: true },
  { path: "relay-regions", labelKey: "nav.platform.relayRegions", group: "network", permission: "platform.relay:read", task: "P4-T03", phase: "mvp", available: true },
  { path: "plans", labelKey: "nav.platform.plans", group: "operations", permission: "platform.plan:read", task: "P4-T03", phase: "mvp", available: true },
  { path: "settings", labelKey: "nav.platform.settings", group: "governance", permission: "platform.settings:read", task: "P4-T03", phase: "mvp", available: true },
  { path: "users", labelKey: "nav.platform.users", group: "people", permission: "platform.user:read", task: "P4-T03", phase: "mvp", available: true },
  { path: "identity-providers", labelKey: "nav.platform.identityProviders", group: "people", permission: "platform.idp:read", task: "P4-T03", phase: "mvp", available: true },
  { path: "support-access", labelKey: "nav.platform.supportAccess", group: "governance", permission: "platform.support_grant:read", task: "P4-T13", phase: "mvp", available: false },
  { path: "audit", labelKey: "nav.platform.audit", group: "governance", permission: "platform.audit:read", task: "P4-T13", phase: "mvp", available: false },
  { path: "security-events", labelKey: "nav.platform.securityEvents", group: "governance", permission: "platform.security_event:read", task: "P6-T02a", phase: "post_mvp", available: false },
  { path: "usage", labelKey: "nav.platform.usage", group: "operations", permission: "platform.usage:read", task: "P6-T11", phase: "post_mvp", available: false },
  { path: "backups", labelKey: "nav.platform.backups", group: "operations", permission: "platform.backup:read", task: "P6-T04", phase: "post_mvp", available: false },
];

export const NAV_GROUPS: readonly NavGroup[] = ["overview", "devices", "access", "network", "people", "governance", "operations"];

export function visibleItems(items: readonly NavItem[], role: string | null | undefined): NavItem[] {
  return items.filter((i) => can(role, i.permission));
}
