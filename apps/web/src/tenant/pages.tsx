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
import { RelayPage } from "./relay/RelayPage";
import { useTenant } from "./TenantScope";

/** P4-T04: Tổng quan, Devices, Relay, hộp thông báo. */
export const TENANT_PAGES: Readonly<Record<string, ComponentType>> = {
  overview: DashboardPage,
  devices: DevicesPage,
  relay: RelayPage,
  notifications: NotificationsPage,
};

function Guarded({ permission, Screen }: { permission: string; Screen: ComponentType }) {
  const { role } = useTenant();
  return can(role, permission) ? <Screen /> : <ForbiddenPage />;
}

export const TENANT_EXTRA_ROUTES: RouteObject[] = [
  { path: "devices/:deviceId", element: <Guarded permission="tenant.device:read" Screen={DeviceDetailPage} /> },
];
