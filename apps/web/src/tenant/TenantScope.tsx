// Ngữ cảnh tenant (§12.1 tenant-aware views): mọi view tenant nằm dưới /t/:tenantId; tenantId phải thuộc session —
// membership trên app., Support Access Grant còn hiệu lực trên admin. (§8.3 bước 8, §8.7). Không thuộc ⇒ 404 thống
// nhất (không lộ tenant có tồn tại hay không). Ngoài ra đọc GET /tenants/{tenantId} để biết trạng thái
// (suspended/deprovisioning ⇒ banner chỉ-đọc; §8.4 bất biến 5).
import { useQuery } from "@tanstack/react-query";
import { createContext, useContext, type ReactNode } from "react";
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
import { navAllowed, TENANT_NAV, visibleItems, type NavItem } from "../nav/navModel";
import { ProblemAlert } from "../components/ProblemAlert";
import { ForbiddenPage, NotFoundPage, UnavailablePage } from "../pages/StatusPages";
import { TENANT_PAGES } from "./pages";
import { useUnreadCount } from "./notifications/useUnreadCount";
import { useInstructions } from "./enrollment/Instructions";
import { SELF_ENROLL_ROLE, selfEnrollClosed } from "./enrollment/model";

export interface TenantContextValue {
  tenantId: string;
  role: string;
  /** slug + tên từ membership (app.) — trên admin. lấy từ GET /tenants/{tenantId} */
  slug: string | null;
  name: string | null;
  /** membership của người gọi trong tenant (app.); null với support grant (admin.) — P4-T04 lọc "thiết bị của tôi" */
  membershipId: string | null;
  /** tenant suspended/deprovisioning (hoặc vừa nhận 403 tenant_suspended): mọi thao tác ghi bị khóa ở UI (P4-T04) */
  readOnly: boolean;
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

  const membership = kind === "tenant" ? session.memberships.find((m) => m.tenant_id === tenantId) : undefined;
  const status = tenant.data?.status;
  const readOnly = status === "suspended" || status === "deprovisioning" || notices.suspendedTenants.has(tenantId);
  const value: TenantContextValue = {
    tenantId,
    role,
    slug: membership?.tenant_slug ?? tenant.data?.slug ?? null,
    name: membership?.tenant_name ?? tenant.data?.name ?? null,
    membershipId: membership?.membership_id ?? null,
    readOnly,
  };
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
      <TenantShell value={value} banner={banner} />
    </TenantContext>
  );
}

/** Vỏ của tenant: nav theo role + badge số thông báo chưa đọc (P4-T04). */
function TenantShell({ value, banner }: { value: TenantContextValue; banner: ReactNode }) {
  const unread = useUnreadCount(value.tenantId, can(value.role, "tenant.notification:read"));
  return (
    <AppShell
      base={`/t/${value.tenantId}`}
      nav={useTenantNav(value)}
      context={value.name ?? value.slug ?? value.tenantId}
      banner={banner}
      badges={unread.data ? { notifications: unread.data } : undefined}
    >
      <Outlet />
    </AppShell>
  );
}

/**
 * Mục điều hướng của role. G4b-E3: End User của tenant tắt `enrollment.self_enroll` không thấy "Thêm thiết bị" — cờ
 * `self_enroll` của GET /enrollment/instructions (cùng query với trang Thêm thiết bị); gõ thẳng URL vẫn tới trang giải
 * thích. Chưa biết cờ (đang tải, lỗi, tenant chưa có instance) ⇒ giữ mục như cũ.
 */
function useTenantNav(value: TenantContextValue): NavItem[] {
  const items = visibleItems(TENANT_NAV, value.role);
  const watch = value.role === SELF_ENROLL_ROLE && items.some((i) => i.path === "enroll");
  const probe = useInstructions(value.tenantId, "linux", watch);
  return watch && selfEnrollClosed(value.role, probe.data) ? items.filter((i) => i.path !== "enroll") : items;
}

/** /t/:tenantId ⇒ mục đầu tiên role được xem (Tổng quan; End User không có dashboard ⇒ Thiết bị). */
export function TenantHome() {
  const { tenantId, role } = useTenant();
  const first = visibleItems(TENANT_NAV, role)[0];
  return first ? <Navigate to={`/t/${tenantId}/${first.path}`} replace /> : <ForbiddenPage />;
}

export function TenantNavRoute({ item }: { item: NavItem }) {
  const { role } = useTenant();
  if (!navAllowed(item, role)) return <ForbiddenPage />;
  const Screen = item.available ? TENANT_PAGES[item.path] : undefined;
  return Screen ? <Screen /> : <UnavailablePage item={item} />;
}
