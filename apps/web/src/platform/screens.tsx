// Màn hình đã xây của Platform Console, theo segment của mục điều hướng (nav/navModel.ts — `available: true`). Mỗi mục
// một cây con dưới /platform/<mục>; PlatformNavRoute kiểm quyền đọc của mục rồi render <Outlet/>.
// Tải theo route (`lazy` của React Router — chunk riêng, cùng origin): Tenant Portal không tải mã của Platform Console
// (và của react-aria, chỉ các màn hình này dùng).
import type { ComponentType } from "react";
import type { RouteObject } from "react-router";
import { NotFoundPage } from "../pages/StatusPages";

const page =
  <M extends Record<string, unknown>>(load: () => Promise<M>, name: keyof M & string): RouteObject["lazy"] =>
  async () => ({ Component: (await load())[name] as ComponentType });

export const PLATFORM_SCREENS: Readonly<Partial<Record<string, RouteObject[]>>> = {
  // P4-T02
  tenants: [
    { index: true, lazy: page(() => import("./tenants/TenantListPage"), "TenantListPage") },
    { path: "new", lazy: page(() => import("./tenants/TenantCreatePage"), "TenantCreatePage") },
    { path: ":tenantId", lazy: page(() => import("./tenants/TenantDetailPage"), "TenantDetailPage") },
    { path: "*", element: <NotFoundPage /> },
  ],
  jobs: [
    { index: true, lazy: page(() => import("./jobs/JobListPage"), "JobListPage") },
    { path: ":jobId", lazy: page(() => import("./jobs/JobDetailPage"), "JobDetailPage") },
    { path: "*", element: <NotFoundPage /> },
  ],
  approvals: [
    { index: true, lazy: page(() => import("./approvals/ApprovalListPage"), "ApprovalListPage") },
    { path: ":approvalId", lazy: page(() => import("./approvals/ApprovalDetailPage"), "ApprovalDetailPage") },
    { path: "*", element: <NotFoundPage /> },
  ],
  // P4-T03
  health: [{ index: true, lazy: page(() => import("./health/HealthPage"), "HealthPage") }, { path: "*", element: <NotFoundPage /> }],
  instances: [
    { index: true, lazy: page(() => import("./instances/InstanceListPage"), "InstanceListPage") },
    { path: ":instanceId", lazy: page(() => import("./instances/InstanceDetailPage"), "InstanceDetailPage") },
    { path: "*", element: <NotFoundPage /> },
  ],
  hosts: [
    { index: true, lazy: page(() => import("./hosts/HostPages"), "HostListPage") },
    { path: ":hostId", lazy: page(() => import("./hosts/HostPages"), "HostDetailPage") },
    { path: "*", element: <NotFoundPage /> },
  ],
  "relay-regions": [
    { index: true, lazy: page(() => import("./relay/RelayRegionListPage"), "RelayRegionListPage") },
    { path: "*", element: <NotFoundPage /> },
  ],
  plans: [{ index: true, lazy: page(() => import("./plans/PlansPage"), "PlansPage") }, { path: "*", element: <NotFoundPage /> }],
  settings: [{ index: true, lazy: page(() => import("./settings/SettingsPage"), "SettingsPage") }, { path: "*", element: <NotFoundPage /> }],
  users: [{ index: true, lazy: page(() => import("./users/PlatformUsersPage"), "PlatformUsersPage") }, { path: "*", element: <NotFoundPage /> }],
  "identity-providers": [
    { index: true, lazy: page(() => import("./idps/IdpPages"), "IdpListPage") },
    { path: ":idpId", lazy: page(() => import("./idps/IdpPages"), "IdpDetailPage") },
    { path: "*", element: <NotFoundPage /> },
  ],
};
