// TanStack Query (§12.4): MỌI query key bắt đầu bằng tenantId (UUID) để cache của hai tenant không bao giờ lẫn nhau;
// dữ liệu không thuộc tenant nào dùng một trong hai tiền tố cố định GLOBAL / PLATFORM. queryKeyHashFn từ chối mọi key
// khác — một query viết sai key là lỗi lập trình, hỏng ngay ở test thay vì lẫn dữ liệu ở runtime.
import { hashKey, QueryClient, type QueryKey } from "@tanstack/react-query";
import { ApiError } from "./problem";

export const GLOBAL = "_global";
export const PLATFORM = "_platform";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value: string): boolean {
  return UUID_RE.test(value);
}

export const queryKeys = {
  /** GET /auth/session — principal, memberships, support grants, CSRF token */
  session: () => [GLOBAL, "auth", "session"] as const,
  /** dữ liệu trong ngữ cảnh một tenant: [tenantId, …] */
  tenant: (tenantId: string, ...rest: readonly (string | number | Record<string, unknown>)[]) => {
    if (!isUuid(tenantId)) throw new Error("queryKeys.tenant: tenantId phải là UUID");
    return [tenantId, ...rest] as const;
  },
  /** dữ liệu của Platform Console: [PLATFORM, …] */
  platform: (...rest: readonly (string | number | Record<string, unknown>)[]) => [PLATFORM, ...rest] as const,
};

export function assertQueryKey(key: QueryKey): void {
  const head = key[0];
  if (typeof head !== "string" || !(head === GLOBAL || head === PLATFORM || isUuid(head))) {
    throw new Error(`query key không bắt đầu bằng tenantId/${GLOBAL}/${PLATFORM}: ${JSON.stringify(key)}`);
  }
}

const MAX_RETRY_AFTER_S = 60;

function retryable(error: unknown): error is ApiError {
  return (
    error instanceof ApiError &&
    (error.code === "network_error" || error.status === 429 || error.status === 503 || error.status === 502)
  );
}

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        queryKeyHashFn: (key) => {
          assertQueryKey(key);
          return hashKey(key);
        },
        staleTime: 15_000,
        // 401/403/404/422… không thử lại; 429/502/503/lỗi mạng thử lại tối đa 2 lần, tôn trọng Retry-After
        retry: (failureCount, error) => retryable(error) && failureCount < 2,
        retryDelay: (attempt, error) =>
          error instanceof ApiError && error.retryAfter !== null
            ? Math.min(error.retryAfter, MAX_RETRY_AFTER_S) * 1000
            : Math.min(1000 * 2 ** attempt, 10_000),
      },
      mutations: { retry: false },
    },
  });
}
