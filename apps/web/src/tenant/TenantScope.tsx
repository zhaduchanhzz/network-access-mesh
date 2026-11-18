// Ngữ cảnh tenant (§12.1 tenant-aware views): mọi view tenant nằm dưới /t/:tenantId; tenantId phải thuộc session —
// membership trên app., Support Access Grant còn hiệu lực trên admin. (§8.3 bước 8, §8.7). Không thuộc ⇒ 404 thống
// nhất (không lộ tenant có tồn tại hay không). Ngoài ra đọc GET /tenants/{tenantId} để biết trạng thái
// (suspended/deprovisioning ⇒ banner chỉ-đọc; §8.4 bất biến 5).
import { useQuery } from "@tanstack/react-query";
import { createContext, useContext } from "react";
import { useTranslation } from "react-i18next";
import { Navigate, Outlet, useParams } from "react-router";
import { api, call } from "../api/client";
import { ApiError } from "../api/problem";
import { isUuid, queryKeys } from "../api/queryClient";
import { useConsole } from "../app/console";
import { useNotices } from "../app/notices";
import { can } from "../auth/permissions";
import { tenantRole, useSession } from "../auth/session";
import { AppShell } from "../layout/AppShell";
import { TENANT_NAV, visibleItems, type NavItem } from "../nav/navModel";
import { ProblemAlert } from "../components/ProblemAlert";
import { ForbiddenPage, NotFoundPage, UnavailablePage } from "../pages/StatusPages";

export interface TenantContextValue {
  tenantId: string;
  role: string;
  /** slug + tên từ membership (app.) — trên admin. lấy từ GET /tenants/{tenantId} */
  slug: string | null;
  name: string | null;
}

const TenantContext = createContext<TenantContextValue | null>(null);

export function useTenant(): TenantContextValue {
  const v = useContext(TenantContext);
  if (!v) throw new Error("useTenant ngoài TenantScope");
  return v;
}

export function TenantScope() {
  const { t } = useTranslation();
  const { tenantId: raw = "" } = useParams();
  const kind = useConsole();
  const session = useSession().data;
  const notices = useNotices();
  const tenantId = raw.toLowerCase();
  const role = session && isUuid(tenantId) ? tenantRole(session, tenantId, kind) : null;

  const tenant = useQuery({
    queryKey: queryKeys.tenant(isUuid(tenantId) ? tenantId : "00000000-0000-0000-0000-000000000000", "tenant"),
    queryFn: () => call(api.GET("/tenants/{tenantId}", { params: { path: { tenantId } } })),
    enabled: role !== null,
  });

  if (!session || role === null || (tenant.error instanceof ApiError && tenant.error.status === 404)) {
    return (
      <AppShell base={null} nav={[]} context="">
        <NotFoundPage />
      </AppShell>
    );
  }
  if (raw !== tenantId) return <Navigate to={`/t/${tenantId}`} replace />;

  const membership = session.memberships.find((m) => m.tenant_id === tenantId);
  const value: TenantContextValue = {
    tenantId,
    role,
    slug: membership?.tenant_slug ?? tenant.data?.slug ?? null,
    name: membership?.tenant_name ?? tenant.data?.name ?? null,
  };
  const status = tenant.data?.status;
  const readOnly = status === "suspended" || status === "deprovisioning" || notices.suspendedTenants.has(tenantId);
  const banner = (
    <>
      {readOnly ? (
        <div role="status" className="banner banner-warn" data-testid="tenant-suspended">
          <p>{t("tenant.suspendedBanner")}</p>
        </div>
      ) : null}
      {tenant.isError ? (
        <div className="px-4 pt-3">
          <ProblemAlert error={tenant.error} onRetry={() => void tenant.refetch()} />
        </div>
      ) : null}
    </>
  );
  return (
    <TenantContext value={value}>
      <AppShell
        base={`/t/${tenantId}`}
        nav={visibleItems(TENANT_NAV, role)}
        context={value.name ?? value.slug ?? tenantId}
        banner={banner}
      >
        <Outlet />
      </AppShell>
    </TenantContext>
  );
}

/** /t/:tenantId ⇒ mục đầu tiên role được xem (Tổng quan; End User không có dashboard ⇒ Thiết bị). */
export function TenantHome() {
  const { tenantId, role } = useTenant();
  const first = visibleItems(TENANT_NAV, role)[0];
  return first ? <Navigate to={`/t/${tenantId}/${first.path}`} replace /> : <ForbiddenPage />;
}

export function TenantNavRoute({ item }: { item: NavItem }) {
  const { role } = useTenant();
  if (!can(role, item.permission)) return <ForbiddenPage />;
  return <UnavailablePage item={item} />;
}
