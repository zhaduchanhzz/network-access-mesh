// Cây route (React Router, data mode — SPA tĩnh). Mỗi đường dẫn lạ ⇒ NotFoundPage (404 thống nhất).
//   /login                         đăng nhập (công khai)
//   /                              chuyển theo console + session
//   /tenants                       chọn tenant (membership hoặc support grant)
//   /t/:tenantId/<mục>             Tenant Portal (TENANT_NAV; màn hình đã xây: tenant/pages.tsx)
//   /t/:tenantId/devices/:deviceId chi tiết thiết bị (P4-T04)
//   /enroll/claim?tenant=&auth_id= trang claim web-auth (P4-T08 — đích chuyển hướng của edge v10, P4-T07); tự đưa tới
//                                  /login?tenant=<slug> khi chưa đăng nhập
//   /platform/<mục>                Platform Console — chỉ trên admin. (PLATFORM_NAV)
import { Outlet, type RouteObject } from "react-router";
import { MaintenanceBanner, RateLimitNotice, StepUpPrompt } from "../components/Banners";
import { PLATFORM_NAV, TENANT_NAV } from "../nav/navModel";
import { LoginPage } from "../pages/LoginPage";
import { NotFoundPage, RouteErrorPage } from "../pages/StatusPages";
import { PlatformHome, PlatformNavRoute, PlatformScope } from "../platform/PlatformScope";
import { PLATFORM_SCREENS } from "../platform/screens";
import { TENANT_EXTRA_ROUTES } from "../tenant/pages";
import { TenantHome, TenantNavRoute, TenantScope } from "../tenant/TenantScope";
import { TenantSelectPage } from "../tenant/TenantSelectPage";
import { ClaimScreen } from "../tenant/enrollment/screens";
import { HomeRedirect, RequireSession } from "./guards";

function RootLayout() {
  return (
    <>
      <div className="fixed inset-x-0 top-0 z-50 space-y-2 p-2" aria-live="polite">
        <StepUpPrompt />
        <RateLimitNotice />
        <MaintenanceBanner />
      </div>
      <Outlet />
    </>
  );
}

function BareNotFound() {
  return (
    <main id="main" className="min-h-screen bg-bg p-6 text-fg">
      <NotFoundPage />
    </main>
  );
}

export const routes: RouteObject[] = [
  {
    element: <RootLayout />,
    errorElement: <RouteErrorPage />,
    children: [
      { index: true, element: <HomeRedirect /> },
      { path: "login", element: <LoginPage /> },
      { path: "enroll/claim", element: <ClaimScreen /> },
      {
        element: <RequireSession />,
        children: [
          { path: "tenants", element: <TenantSelectPage /> },
          {
            path: "t/:tenantId",
            element: <TenantScope />,
            children: [
              { index: true, element: <TenantHome /> },
              ...TENANT_NAV.map((item) => ({ path: item.path, element: <TenantNavRoute item={item} /> })),
              ...TENANT_EXTRA_ROUTES,
              { path: "*", element: <NotFoundPage /> },
            ],
          },
          {
            path: "platform",
            element: <PlatformScope />,
            children: [
              { index: true, element: <PlatformHome /> },
              ...PLATFORM_NAV.map((item) => ({
                path: item.path,
                element: <PlatformNavRoute item={item} />,
                children: item.available ? PLATFORM_SCREENS[item.path] : undefined,
              })),
              { path: "*", element: <NotFoundPage /> },
            ],
          },
        ],
      },
      { path: "*", element: <BareNotFound /> },
    ],
  },
];
