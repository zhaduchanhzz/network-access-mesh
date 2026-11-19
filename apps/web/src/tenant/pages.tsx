// Màn hình đã xây của Tenant Portal, theo `path` của mục điều hướng (TENANT_NAV có `available: true`) — TenantNavRoute
// kiểm quyền rồi render màn hình ở đây; mục chưa có ở đây vẫn là trang "chưa khả dụng". Route con ngoài nav (chi tiết)
// ở TENANT_EXTRA_ROUTES, cùng cổng quyền đọc của mục cha. Task UI sau thêm màn hình của mình vào hai bảng này.
import type { ComponentType } from "react";
import type { RouteObject } from "react-router";
import { can } from "../auth/permissions";
import { ForbiddenPage } from "../pages/StatusPages";
import { DashboardPage } from "./dashboard/DashboardPage";
import { DeviceDetailPage } from "./devices/DeviceDetailPage";
import { DevicesPage } from "./devices/DevicesPage";
import { NotificationsPage } from "./notifications/NotificationsPage";
import { GroupDetailPage } from "./people/GroupDetailPage";
import { GroupsPage } from "./people/GroupsPage";
import { InvitationsPage } from "./people/InvitationsPage";
import { UserDetailPage } from "./people/UserDetailPage";
import { UsersPage } from "./people/UsersPage";
import { PoliciesScreen, PolicyVersionScreen, TagsScreen } from "./policies/screens";
import { RelayPage } from "./relay/RelayPage";
import { useTenant } from "./TenantScope";

/** P4-T04: Tổng quan, Devices, Relay, hộp thông báo; P4-T09a: Users, Groups, Invitations. */
export const TENANT_PAGES: Readonly<Record<string, ComponentType>> = {
  overview: DashboardPage,
  devices: DevicesPage,
  relay: RelayPage,
  notifications: NotificationsPage,
  // P4-T09a: Users, Groups, Invitations
  users: UsersPage,
  groups: GroupsPage,
  invitations: InvitationsPage,
  // P4-T11 (tải theo route)
  policies: PoliciesScreen,
  tags: TagsScreen,
};

function Guarded({ permission, Screen }: { permission: string; Screen: ComponentType }) {
  const { role } = useTenant();
  return can(role, permission) ? <Screen /> : <ForbiddenPage />;
}

export const TENANT_EXTRA_ROUTES: RouteObject[] = [
  { path: "devices/:deviceId", element: <Guarded permission="tenant.device:read" Screen={DeviceDetailPage} /> },
  { path: "users/:membershipId", element: <Guarded permission="tenant.user:read" Screen={UserDetailPage} /> },
  { path: "groups/:groupId", element: <Guarded permission="tenant.group:read" Screen={GroupDetailPage} /> },
  { path: "policies/:versionId", element: <Guarded permission="tenant.policy:read" Screen={PolicyVersionScreen} /> },
];
