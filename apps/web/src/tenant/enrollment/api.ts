// Truy vấn và lệnh của enrollment (P4-T08 trên API P4-T06): mọi key bắt đầu bằng tenantId (§12.4). Response phát
// credential (`EnrollmentIssue`) KHÔNG BAO GIỜ vào cache của TanStack Query: mutationFn chuyển credential cho người gọi
// (state của một màn hình) rồi chỉ trả `request` (không secret) — cache của mutation không giữ key/mã; `gcTime: 0` bỏ
// mutation khỏi cache khi màn hình đóng.
import { useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";
import { api, call } from "../../api/client";
import { useIdempotentMutation } from "../../api/idempotency";
import { useUsers } from "../people/api";
import { enrollmentKeys, isWaiting, ENROLL_POLL_MS, LIST_POLL_MS, type EnrollmentIssue, type EnrollmentRequest, type EnrollmentStatus } from "./model";

export const LIST_LIMIT = 100;

/** Sau một thao tác ghi: làm mới danh sách + yêu cầu (không hướng dẫn — không đổi, và mỗi GET tốn token rate limit). */
export async function invalidateEnrollment(queryClient: QueryClient, tenantId: string): Promise<void> {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: [...enrollmentKeys.all(tenantId), "list"] }),
    queryClient.invalidateQueries({ queryKey: [...enrollmentKeys.all(tenantId), "request"] }),
  ]);
}

/** Một trang yêu cầu (mới nhất trước); còn yêu cầu đang chờ thiết bị ⇒ poll (trạng thái do server/job reconcile đổi). */
export function useEnrollmentList(
  tenantId: string,
  f: { status?: EnrollmentStatus; cursor?: string; limit?: number } = {},
  enabled = true,
  poll = true,
) {
  const limit = f.limit ?? LIST_LIMIT;
  return useQuery({
    queryKey: enrollmentKeys.list(tenantId, { status: f.status ?? "", cursor: f.cursor ?? "", limit }),
    queryFn: () =>
      call(
        api.GET("/tenants/{tenantId}/enrollment/requests", {
          params: { path: { tenantId }, query: { limit, ...(f.status ? { status: f.status } : {}), ...(f.cursor ? { cursor: f.cursor } : {}) } },
        }),
      ),
    enabled,
    placeholderData: (prev) => prev,
    refetchInterval: (q) => (poll && q.state.data?.items.some((r) => isWaiting(r.status) || r.status === "requested") ? LIST_POLL_MS : false),
  });
}

/** Một yêu cầu — poll trong lúc chờ thiết bị (claim ở tab khác, client dùng key, job reconcile). */
export function useEnrollmentRequest(tenantId: string, id: string, initial: EnrollmentRequest) {
  return useQuery({
    queryKey: enrollmentKeys.one(tenantId, id),
    queryFn: () =>
      call(api.GET("/tenants/{tenantId}/enrollment/requests/{enrollmentRequestId}", { params: { path: { tenantId, enrollmentRequestId: id } } })),
    // response của lệnh tạo là bản đọc mới nhất — không GET lại ngay (tiết kiệm token rate limit)
    initialData: initial,
    initialDataUpdatedAt: () => Date.now(),
    refetchInterval: (q) => (q.state.data && isWaiting(q.state.data.status) ? ENROLL_POLL_MS : false),
  });
}

/** Lệnh phát credential (tạo yêu cầu, key đặc quyền) với Idempotency-Key theo nội dung; `onIssued` nhận credential. */
export function useIssueMutation<TVars>(
  tenantId: string,
  fn: (vars: TVars, idempotencyKey: string) => Promise<EnrollmentIssue>,
  onIssued: (issue: EnrollmentIssue) => void,
) {
  const queryClient = useQueryClient();
  return useIdempotentMutation<EnrollmentRequest, TVars>({
    gcTime: 0,
    mutationFn: async (vars, key) => {
      const issue = await fn(vars, key);
      onIssued(issue);
      return issue.request;
    },
    onSuccess: () => invalidateEnrollment(queryClient, tenantId),
  });
}

export type NewRequestBody = { method: "web_auth" | "preauth_key"; device_label?: string; ttl_minutes?: number };
export type NewKeyBody = {
  target_membership_id: string | null;
  tags: string[];
  reusable: boolean;
  ephemeral: boolean;
  device_label?: string;
  ttl_minutes?: number;
};

export function createRequest(tenantId: string, body: NewRequestBody, key: string): Promise<EnrollmentIssue> {
  return call(api.POST("/tenants/{tenantId}/enrollment/requests", { params: { path: { tenantId }, header: { "Idempotency-Key": key } }, body }));
}

export function createKey(tenantId: string, body: NewKeyBody, key: string): Promise<EnrollmentIssue> {
  return call(api.POST("/tenants/{tenantId}/enrollment/keys", { params: { path: { tenantId }, header: { "Idempotency-Key": key } }, body }));
}

/** membership id ⇒ tên hiển thị (chỉ khi người gọi đọc được /users — End User thấy "Bạn" cho chính mình). */
export function useMemberNames(tenantId: string, enabled: boolean): ReadonlyMap<string, string> {
  const users = useUsers(tenantId, {}, { enabled, limit: 200 });
  return new Map((users.data?.items ?? []).map((m) => [m.id, m.display_name]));
}
