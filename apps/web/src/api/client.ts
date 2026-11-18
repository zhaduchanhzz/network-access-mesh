// Client type-safe của SaaS API (§12.4): openapi-fetch trên type sinh từ api/openapi.yaml (src/api/schema.d.ts).
// - Chỉ một đích: /api/v1 cùng origin (app.<domain> hoặc admin.<domain>). Trình duyệt không bao giờ gọi Headscale.
// - Xác thực bằng cookie __Host-mg_session do server đặt (HttpOnly — JavaScript không đọc được); không token nào
//   trong Web Storage. CSRF token (GET /auth/session) chỉ nằm trong bộ nhớ của trang (§8.3 bước 5).
import createClient, { type Middleware } from "openapi-fetch";
import type { paths } from "./schema";
import { ApiError } from "./problem";

export const API_PREFIX = "/api/v1";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

let csrfToken: string | null = null;

/** CSRF token của session hiện tại — chỉ giữ trong biến của module (mất khi tải lại trang, lấy lại từ /auth/session). */
export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

export function hasCsrfToken(): boolean {
  return csrfToken !== null;
}

const csrfMiddleware: Middleware = {
  onRequest({ request }) {
    if (!SAFE_METHODS.has(request.method.toUpperCase()) && csrfToken !== null) {
      request.headers.set("X-CSRF-Token", csrfToken);
    }
    return request;
  },
};

// baseUrl tuyệt đối nhưng luôn là origin của chính trang (Request cần URL tuyệt đối ngoài trình duyệt, ví dụ test).
export const api = createClient<paths>({
  baseUrl: `${window.location.origin}${API_PREFIX}`,
  credentials: "same-origin",
  headers: { Accept: "application/json, application/problem+json" },
  // đọc globalThis.fetch ở mỗi lần gọi (không giữ tham chiếu lúc khởi tạo)
  fetch: (request: Request) => globalThis.fetch(request),
});
api.use(csrfMiddleware);

type Listener = (error: ApiError) => void;
const listeners = new Set<Listener>();

/** Đăng ký nhận mọi ApiError của lời gọi qua `call` (phiên hết hạn, step-up, bảo trì, rate limit…). */
export function onApiError(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

interface FetchResult<T> {
  data?: T;
  error?: unknown;
  response: Response;
}

/**
 * Chờ một lời gọi openapi-fetch: 2xx ⇒ data; lỗi ⇒ ném ApiError (problem+json đã phân tích, Retry-After, request id)
 * và báo cho các listener (trừ khi `notify: false`).
 */
export async function call<T>(pending: Promise<FetchResult<T>>, opts: { notify?: boolean } = {}): Promise<T> {
  let result: FetchResult<T>;
  try {
    result = await pending;
  } catch {
    throw ApiError.network();
  }
  if (result.response.ok) {
    return result.data as T;
  }
  const error = ApiError.fromResponse(result.response, result.error);
  if (opts.notify !== false) {
    for (const l of listeners) l(error);
  }
  throw error;
}
