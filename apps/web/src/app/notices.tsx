// Phản ứng chung với lỗi API (§8.3, §13.1) — nhận mọi ApiError qua onApiError:
// - 401 unauthenticated: session hết hạn/bị thu hồi ⇒ xóa session khỏi cache, RequireSession chuyển về /login.
// - 401 reauth_required: cần step-up (auth_time ≤ 15 phút) ⇒ lời nhắc xác thực lại (prompt=login qua reauth=true).
// - 403 tenant_suspended: tenant bị tạm ngưng ⇒ banner chỉ-đọc cho tenant đó.
// - 429 rate_limited: thông báo kèm thời gian chờ theo Retry-After.
// - 503 maintenance: nền tảng đang bảo trì (P3-T17) ⇒ banner.
import { useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { onApiError } from "../api/client";
import type { ApiError } from "../api/problem";
import { queryKeys } from "../api/queryClient";

const TENANT_PATH_RE = /\/tenants\/([0-9a-f-]{36})(?:\/|$)/i;

export interface Notices {
  stepUp: boolean;
  /** session vừa bị server từ chối (401 unauthenticated) — trang đăng nhập báo phiên đã hết hạn */
  sessionExpired: boolean;
  /** thời điểm (ms) hết thời gian chờ của 429 gần nhất */
  rateLimitedUntil: number | null;
  maintenance: boolean;
  suspendedTenants: ReadonlySet<string>;
  dismissStepUp: () => void;
  dismissRateLimit: () => void;
  dismissMaintenance: () => void;
  markSuspended: (tenantId: string) => void;
}

const NoticesContext = createContext<Notices | null>(null);

export function tenantOfProblem(error: ApiError): string | null {
  const m = TENANT_PATH_RE.exec(error.problem?.instance ?? "");
  return m?.[1]?.toLowerCase() ?? null;
}

export function NoticesProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [stepUp, setStepUp] = useState(false);
  const [sessionExpired, setSessionExpired] = useState(false);
  const [rateLimitedUntil, setRateLimitedUntil] = useState<number | null>(null);
  const [maintenance, setMaintenance] = useState(false);
  const [suspendedTenants, setSuspended] = useState<ReadonlySet<string>>(new Set());

  const markSuspended = useCallback((tenantId: string) => {
    setSuspended((s) => (s.has(tenantId) ? s : new Set([...s, tenantId])));
  }, []);

  useEffect(
    () =>
      onApiError((e) => {
        switch (e.code) {
          case "unauthenticated":
            setSessionExpired(true);
            queryClient.setQueryData(queryKeys.session(), null);
            break;
          case "reauth_required":
            setStepUp(true);
            break;
          case "tenant_suspended": {
            const t = tenantOfProblem(e);
            if (t) markSuspended(t);
            break;
          }
          case "rate_limited":
            setRateLimitedUntil(Date.now() + (e.retryAfter ?? 1) * 1000);
            break;
          case "maintenance":
            setMaintenance(true);
            break;
          default:
            break;
        }
      }),
    [queryClient, markSuspended],
  );

  const value = useMemo<Notices>(
    () => ({
      stepUp,
      sessionExpired,
      rateLimitedUntil,
      maintenance,
      suspendedTenants,
      dismissStepUp: () => {
        setStepUp(false);
      },
      dismissRateLimit: () => {
        setRateLimitedUntil(null);
      },
      dismissMaintenance: () => {
        setMaintenance(false);
      },
      markSuspended,
    }),
    [stepUp, sessionExpired, rateLimitedUntil, maintenance, suspendedTenants, markSuspended],
  );
  return <NoticesContext value={value}>{children}</NoticesContext>;
}

export function useNotices(): Notices {
  const v = useContext(NoticesContext);
  if (!v) throw new Error("useNotices ngoài NoticesProvider");
  return v;
}
