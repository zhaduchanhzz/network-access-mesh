// Lỗi của SaaS API (RFC 9457 application/problem+json, §13.1): client dựa vào `code` ổn định, không dựa vào
// `title`/`detail`. Mọi lỗi của lời gọi API — kể cả lỗi mạng và phản hồi không phải problem+json — đều thành ApiError.
import type { components } from "./schema";

export type Problem = components["schemas"]["Problem"];
export type ProblemCode = components["schemas"]["ProblemCode"];
/** `code` của Problem, cộng hai mã phía client: không tới được server, hoặc server trả lỗi không theo problem+json. */
export type ApiErrorCode = ProblemCode | "network_error" | "unexpected_response";

// Danh sách đầy đủ của enum ProblemCode — `satisfies` + kiểm ngược ở dưới làm typecheck fail khi spec thêm/bớt mã.
const PROBLEM_CODES = [
  "unauthenticated",
  "reauth_required",
  "forbidden",
  "tenant_suspended",
  "quota_exceeded",
  "not_found",
  "conflict",
  "precondition_failed",
  "precondition_required",
  "validation_failed",
  "idempotency_key_reuse",
  "rate_limited",
  "upstream_rejected",
  "instance_unavailable",
  "maintenance",
  "internal_error",
  "not_implemented",
] as const satisfies readonly ProblemCode[];
type MissingCode = Exclude<ProblemCode, (typeof PROBLEM_CODES)[number]>;
type Assert<T extends true> = T;
/** Lỗi typecheck ở đây ⇒ spec có mã mới chưa nằm trong PROBLEM_CODES (và chưa có bản dịch problem.<code>). */
export type AllProblemCodesListed = Assert<[MissingCode] extends [never] ? true : false>;

export const KNOWN_CODES: ReadonlySet<string> = new Set<string>(PROBLEM_CODES);

export function isProblem(x: unknown): x is Problem {
  if (typeof x !== "object" || x === null) return false;
  const p = x as Record<string, unknown>;
  return typeof p.status === "number" && typeof p.code === "string" && typeof p.title === "string";
}

/** Retry-After (RFC 9110): delta-seconds hoặc HTTP-date ⇒ số giây còn lại (≥ 0); giá trị lạ ⇒ null. */
export function parseRetryAfter(value: string | null, now: number = Date.now()): number | null {
  if (value === null) return null;
  const v = value.trim();
  if (/^\d{1,9}$/.test(v)) return Number(v);
  const at = Date.parse(v);
  if (Number.isNaN(at) || !/[a-z]/i.test(v)) return null;
  return Math.max(0, Math.ceil((at - now) / 1000));
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: ApiErrorCode;
  readonly problem: Problem | null;
  readonly retryAfter: number | null;
  readonly requestId: string | null;

  constructor(init: {
    status: number;
    code: ApiErrorCode;
    problem?: Problem | null;
    retryAfter?: number | null;
    requestId?: string | null;
  }) {
    super(`API ${init.status} ${init.code}`);
    this.name = "ApiError";
    this.status = init.status;
    this.code = init.code;
    this.problem = init.problem ?? null;
    this.retryAfter = init.retryAfter ?? null;
    this.requestId = init.requestId ?? init.problem?.request_id ?? null;
  }

  /** Phản hồi lỗi + body đã đọc (openapi-fetch: JSON nếu parse được, nếu không là text). */
  static fromResponse(response: Response, body: unknown): ApiError {
    const retryAfter = parseRetryAfter(response.headers.get("Retry-After"));
    const requestId = response.headers.get("X-Request-Id");
    const type = response.headers.get("Content-Type") ?? "";
    if (type.startsWith("application/problem+json") && isProblem(body)) {
      const code: ApiErrorCode = KNOWN_CODES.has(body.code) ? body.code : "unexpected_response";
      return new ApiError({ status: response.status, code, problem: body, retryAfter, requestId });
    }
    return new ApiError({ status: response.status, code: "unexpected_response", retryAfter, requestId });
  }

  static network(): ApiError {
    return new ApiError({ status: 0, code: "network_error" });
  }
}

export function isApiError(e: unknown): e is ApiError {
  return e instanceof ApiError;
}
