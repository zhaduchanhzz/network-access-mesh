// Hạ tầng UI dùng chung (P4-T04 — để người điều phối hợp nhất với P4-T02): lời gọi API cần đọc header của phản hồi
// (`Location` của 202 — §13.1 "Thao tác dài") và đọc ID job từ `Location`.
import { call } from "../api/client";
import { isUuid } from "../api/queryClient";

interface FetchResult<T> {
  data?: T;
  error?: unknown;
  response: Response;
}

/** Như `call` (lỗi ⇒ ApiError + listener chung) nhưng trả cả `Response` để đọc header (`Location`, `ETag`). */
export async function callWithResponse<T>(pending: Promise<FetchResult<T>>): Promise<{ data: T; response: Response }> {
  let response: Response | undefined;
  const data = await call(
    pending.then((r) => {
      response = r.response;
      return r;
    }),
  );
  if (response === undefined) throw new Error("callWithResponse: không có Response");
  return { data, response };
}

const TENANT_JOB_RE = /^\/api\/v1\/tenants\/([0-9a-f-]{36})\/jobs\/([0-9a-f-]{36})$/i;

/**
 * ID job trong `Location` của 202 phạm vi tenant (`/api/v1/tenants/{tenantId}/jobs/{jobId}` — §13.1). Chỉ nhận đường
 * dẫn tương đối cùng origin và đúng tenant đang xem; giá trị khác ⇒ null (không bao giờ theo một URL do server trả mà
 * chưa kiểm).
 */
export function tenantJobFromLocation(location: string | null, tenantId: string): string | null {
  if (!location) return null;
  const m = TENANT_JOB_RE.exec(location.trim());
  if (!m?.[1] || !m[2]) return null;
  if (m[1].toLowerCase() !== tenantId.toLowerCase() || !isUuid(m[2])) return null;
  return m[2].toLowerCase();
}
