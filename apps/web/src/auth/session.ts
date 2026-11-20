// Luồng đăng nhập BFF (§8.3): SPA không bao giờ thấy token của IdP. Đăng nhập và đăng xuất là điều hướng top-level
// (không fetch) tới /api/v1/auth/login và tới `redirect_to` của POST /auth/logout; trạng thái đăng nhập đọc từ
// GET /auth/session (401 ⇒ chưa đăng nhập).
import { useQuery, type QueryClient } from "@tanstack/react-query";
import type { components } from "../api/schema";
import { api, API_PREFIX, call, setCsrfToken } from "../api/client";
import { ApiError } from "../api/problem";
import { queryKeys } from "../api/queryClient";
import { browser, type ConsoleKind } from "../app/console";
import { i18n, isLanguage, type Language } from "../i18n";

export type Session = components["schemas"]["Session"];
export type SessionMembership = components["schemas"]["SessionMembership"];
export type SupportGrant = components["schemas"]["SupportGrantSummary"];

/** Cùng pattern với `return_to` của GET /auth/login trong spec: đường dẫn tương đối, không `//`, không `/\`. */
export const RETURN_TO_RE = /^\/([^/\\\s][^\s]*)?$/;
const RETURN_TO_MAX = 512;
export const SLUG_RE = /^[a-z][a-z0-9-]{1,30}[a-z0-9]$/;

export function safeReturnTo(value: string | null | undefined): string | null {
  if (!value || value.length > RETURN_TO_MAX || !RETURN_TO_RE.test(value)) return null;
  if (value.startsWith("/login")) return null;
  return value;
}

export async function fetchSession(): Promise<Session | null> {
  try {
    const session = await call(api.GET("/auth/session"), { notify: false });
    setCsrfToken(session.csrf_token);
    return session;
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      setCsrfToken(null);
      return null;
    }
    throw e;
  }
}

export function useSession() {
  return useQuery({ queryKey: queryKeys.session(), queryFn: fetchSession, staleTime: 60_000 });
}

export interface LoginOptions {
  console: ConsoleKind;
  tenantSlug?: string | null;
  returnTo?: string | null;
  reauth?: boolean;
  /** ngôn ngữ của SPA ⇒ `ui_locales` (G4b-E14: trang đăng nhập của IdP cùng ngôn ngữ) */
  uiLocale?: Language | null;
}

/** URL của GET /api/v1/auth/login — `scope=platform` chỉ trên admin., `scope=tenant&tenant=<slug>` trên app. */
export function loginUrl(opts: LoginOptions): string {
  const q = new URLSearchParams();
  if (opts.console === "platform") {
    q.set("scope", "platform");
  } else {
    q.set("scope", "tenant");
    if (opts.tenantSlug) {
      if (!SLUG_RE.test(opts.tenantSlug)) throw new Error("tenant slug không hợp lệ");
      q.set("tenant", opts.tenantSlug);
    }
  }
  const back = safeReturnTo(opts.returnTo);
  if (back) q.set("return_to", back);
  if (opts.reauth) q.set("reauth", "true");
  if (opts.uiLocale && isLanguage(opts.uiLocale)) q.set("ui_locales", opts.uiLocale);
  return `${API_PREFIX}/auth/login?${q.toString()}`;
}

/** Bắt đầu đăng nhập (hoặc step-up khi `reauth`): điều hướng top-level — không dùng <form> vì `form-action 'self'`
 * của CSP áp cả lên chuyển hướng sau khi submit (tới auth.<domain>). */
export function startLogin(opts: LoginOptions): void {
  const lang = i18n.language;
  browser.assign(loginUrl({ ...opts, uiLocale: opts.uiLocale ?? (isLanguage(lang) ? lang : null) }));
}

/** POST /auth/logout (CSRF) rồi điều hướng tới `redirect_to` (end_session_endpoint của IdP) — chỉ URL https. */
export async function logout(queryClient: QueryClient): Promise<void> {
  const result = await call(api.POST("/auth/logout"));
  setCsrfToken(null);
  queryClient.clear();
  let target = "/";
  try {
    const u = new URL(result.redirect_to);
    if (u.protocol === "https:") target = u.href;
  } catch {
    /* giá trị lạ ⇒ về trang chủ */
  }
  browser.assign(target);
}

/** Role của người gọi trong một tenant: membership (app.) hoặc support grant còn hiệu lực (admin., §8.7). */
export function tenantRole(session: Session, tenantId: string, kind: ConsoleKind): string | null {
  if (kind === "tenant") {
    return session.memberships.find((m) => m.tenant_id === tenantId)?.role ?? null;
  }
  const now = Date.now();
  const grant = session.support_grants.find((g) => g.tenant_id === tenantId && Date.parse(g.expires_at) > now);
  return grant?.effective_role ?? null;
}
