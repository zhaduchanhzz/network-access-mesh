// Bố cục chung (§12.4 — desktop-first, dùng được trên tablet/mobile): skip link, header (console, ngữ cảnh tenant,
// người dùng, tùy chọn, đăng xuất), điều hướng theo role, vùng nội dung.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link, NavLink } from "react-router";
import { useConsole } from "../app/console";
import { logout, useSession } from "../auth/session";
import { NAV_GROUPS, type NavItem } from "../nav/navModel";
import { ProblemAlert } from "../components/ProblemAlert";
import { Preferences } from "./Preferences";

export interface AppShellProps {
  /** tiền tố của mục điều hướng: /t/<tenantId> hoặc /platform; null ⇒ không có điều hướng (trang chọn tenant) */
  base: string | null;
  nav: readonly NavItem[];
  /** tên ngữ cảnh hiển thị ở header (tên tenant, hoặc nhãn Platform Console) */
  context: string;
  banner?: ReactNode;
  /** số đếm cạnh mục điều hướng, theo `path` của mục (P4-T04: thông báo chưa đọc); 0 ⇒ không hiện */
  badges?: Readonly<Record<string, NavCount>>;
  children: ReactNode;
}

/** Số đếm của một mục: `more` ⇒ còn nhiều hơn `count` (hiện "99+"). */
export interface NavCount {
  count: number;
  more: boolean;
}

export function AppShell({ base, nav, context, banner, badges, children }: AppShellProps) {
  const { t } = useTranslation();
  const kind = useConsole();
  const session = useSession().data;
  const queryClient = useQueryClient();
  const signOut = useMutation({ mutationFn: () => logout(queryClient) });
  const multiTenant = kind === "tenant" ? (session?.memberships.length ?? 0) > 1 : (session?.support_grants.length ?? 0) > 0;

  return (
    <div className="flex min-h-screen flex-col bg-bg text-fg">
      <a href="#main" className="skip-link">
        {t("shell.skipToContent")}
      </a>
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-line bg-surface px-4 py-3">
        <div className="flex min-w-0 items-center gap-3">
          <Link to="/" className="font-semibold">
            {t("app.name")}
          </Link>
          <span className="rounded bg-accent/10 px-2 py-0.5 text-xs font-medium text-accent">
            {kind === "platform" ? t("shell.platformConsole") : t("shell.tenantPortal")}
          </span>
          <span className="truncate text-sm text-muted" data-testid="shell-context">
            {context}
          </span>
          {multiTenant && base !== "/platform" ? (
            <Link to="/tenants" className="link text-sm">
              {t("shell.switchTenant")}
            </Link>
          ) : null}
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <Preferences />
          {session ? (
            <span className="text-sm" data-testid="shell-user">
              {session.principal.display_name}
            </span>
          ) : null}
          <button
            type="button"
            className="btn-secondary"
            disabled={signOut.isPending}
            onClick={() => {
              signOut.mutate();
            }}
          >
            {t("shell.signOut")}
          </button>
        </div>
      </header>
      {signOut.isError ? (
        <div className="px-4 pt-3">
          <ProblemAlert error={signOut.error} />
        </div>
      ) : null}
      {banner}
      <div className="flex flex-1 flex-col md:flex-row">
        {base !== null && nav.length > 0 ? <SideNav base={base} items={nav} badges={badges} /> : null}
        <main id="main" tabIndex={-1} className="flex-1 p-4 md:p-8">
          {children}
        </main>
      </div>
    </div>
  );
}

function SideNav({ base, items, badges }: { base: string; items: readonly NavItem[]; badges?: AppShellProps["badges"] }) {
  const { t } = useTranslation();
  return (
    <nav
      aria-label={t("shell.navigation")}
      className="border-b border-line bg-surface md:w-64 md:shrink-0 md:border-r md:border-b-0"
    >
      <div className="flex gap-4 overflow-x-auto p-3 md:block md:space-y-4 md:overflow-visible md:p-4">
        {NAV_GROUPS.map((g) => {
          const group = items.filter((i) => i.group === g);
          if (group.length === 0) return null;
          return (
            <div key={g} className="shrink-0">
              <p className="px-2 text-xs font-semibold tracking-wide text-muted uppercase" id={`nav-${g}`}>
                {t(`nav.groups.${g}`)}
              </p>
              <ul aria-labelledby={`nav-${g}`} className="mt-1 flex gap-1 md:block md:space-y-0.5">
                {group.map((i) => (
                  <li key={i.path}>
                    <NavLink
                      to={`${base}/${i.path}`}
                      className={({ isActive }) => (isActive ? "nav-link nav-link-active" : "nav-link")}
                    >
                      <span>{t(i.labelKey)}</span>
                      {!i.available ? <span className="nav-badge">{t("nav.soon")}</span> : null}
                      <NavCountBadge value={badges?.[i.path]} />
                    </NavLink>
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
      </div>
    </nav>
  );
}

function NavCountBadge({ value }: { value: NavCount | undefined }) {
  const { t } = useTranslation();
  if (!value || value.count <= 0) return null;
  const text = value.more ? `${value.count}+` : `${value.count}`;
  return (
    <span className="nav-count" data-testid="nav-count">
      <span aria-hidden="true">{text}</span>
      <span className="sr-only">{t("ui.navCount", { count: value.count, more: value.more ? "+" : "" })}</span>
    </span>
  );
}
