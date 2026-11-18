// Platform Console (§12.1, §12.2): CHỈ trên origin admin.<domain> và chỉ cho principal phạm vi platform. Trên app. ⇒
// 404 thống nhất (console không tồn tại ở origin này). Quyền thật do server quyết định (§8.8).
import { useTranslation } from "react-i18next";
import { Navigate, Outlet } from "react-router";
import { useConsole } from "../app/console";
import { can } from "../auth/permissions";
import { useSession } from "../auth/session";
import { AppShell } from "../layout/AppShell";
import { PLATFORM_NAV, visibleItems, type NavItem } from "../nav/navModel";
import { ForbiddenPage, NotFoundPage, UnavailablePage } from "../pages/StatusPages";

export function usePlatformRole(): string | null {
  const session = useSession().data;
  return session?.principal.scope === "platform" ? (session.principal.platform_role ?? null) : null;
}

export function PlatformScope() {
  const { t } = useTranslation();
  const kind = useConsole();
  const role = usePlatformRole();
  if (kind !== "platform") {
    return (
      <AppShell base={null} nav={[]} context="">
        <NotFoundPage />
      </AppShell>
    );
  }
  return (
    <AppShell base="/platform" nav={visibleItems(PLATFORM_NAV, role)} context={t("shell.platformConsole")}>
      {role === null ? <ForbiddenPage /> : <Outlet />}
    </AppShell>
  );
}

export function PlatformHome() {
  const role = usePlatformRole();
  const first = visibleItems(PLATFORM_NAV, role)[0];
  return first ? <Navigate to={`/platform/${first.path}`} replace /> : <ForbiddenPage />;
}

/** Mục điều hướng: role không có quyền đọc ⇒ "không có quyền"; chưa xây ⇒ "chưa khả dụng"; đã xây ⇒ màn hình con
 * (platform/screens.tsx). */
export function PlatformNavRoute({ item }: { item: NavItem }) {
  const role = usePlatformRole();
  if (!can(role, item.permission)) return <ForbiddenPage />;
  if (!item.available) return <UnavailablePage item={item} />;
  return <Outlet />;
}
