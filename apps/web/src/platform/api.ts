// Truy vấn của Platform Console (P4-T02): mọi key bắt đầu bằng PLATFORM ("_platform" — queryKeys.platform, §12.4);
// dữ liệu chỉ là metadata registry (§8.4 bất biến 2) — không đọc dữ liệu nội bộ của tenant.
import { useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";
import type { components } from "../api/schema";
import { api, call } from "../api/client";
import { callWithETag } from "../api/etag";
import { isSettled, jobPollInterval, type JobStatus } from "../api/jobs";
import { PLATFORM, queryKeys } from "../api/queryClient";

export type Tenant = components["schemas"]["Tenant"];
export type TenantStatus = components["schemas"]["TenantStatus"];
export type TenantCreate = components["schemas"]["TenantCreate"];
export type Instance = components["schemas"]["Instance"];
export type PlatformRelayRegion = components["schemas"]["PlatformRelayRegion"];
export type RelayUnavailable = components["schemas"]["RelayUnavailable"];
export type ApprovalRequest = components["schemas"]["ApprovalRequest"];
export type ApprovalStatus = components["schemas"]["ApprovalStatus"];

export const TENANT_STATUSES = [
  "pending",
  "provisioning",
  "active",
  "suspended",
  "deprovisioning",
  "deleted",
  "failed",
] as const satisfies readonly TenantStatus[];
export const APPROVAL_STATUSES = ["pending", "approved", "rejected", "expired", "executed"] as const satisfies readonly ApprovalStatus[];
type Assert<T extends true> = T;
/** Lỗi typecheck ⇒ spec thêm trạng thái chưa có trong danh sách (và chưa có bản dịch status.*). */
export type AllTenantStatusesListed = Assert<[Exclude<TenantStatus, (typeof TENANT_STATUSES)[number]>] extends [never] ? true : false>;
export type AllApprovalStatusesListed = Assert<
  [Exclude<ApprovalStatus, (typeof APPROVAL_STATUSES)[number]>] extends [never] ? true : false
>;

/** Thao tác 2P phạm vi platform đã biết ⇒ permission của chính thao tác mà người duyệt phải giữ (§8.5; Go: Spec.Permission). */
export const APPROVAL_ACTION_PERMISSION: Readonly<Record<string, string>> = {
  "platform.tenant.delete": "platform.tenant:delete",
  "platform.instance.restore": "platform.instance:restore",
  "platform.instance.release": "platform.instance:release",
  "platform.idp.console_session": "platform.idp:console",
  // P4-T03a (màn hình: P4-T03)
  "platform.user.super_admin": "platform.user:assign_super_admin",
  "platform.idp.update_tenant": "platform.idp:manage",
};

export const PAGE_SIZE = 25;

export const platformKeys = {
  tenants: (f: { status?: string; q?: string; cursor?: string }) => queryKeys.platform("tenants", f),
  tenant: (id: string) => queryKeys.platform("tenant", id),
  tenantJobs: (id: string, cursor?: string) => queryKeys.platform("tenant", id, "jobs", { cursor }),
  tenantInstances: (id: string) => queryKeys.platform("tenant", id, "instances"),
  tenantRelay: (id: string) => queryKeys.platform("tenant", id, "relay"),
  jobs: (f: { status?: string; kind?: string; cursor?: string }) => queryKeys.platform("jobs", f),
  job: (id: string) => queryKeys.platform("job", id),
  approvals: (f: { status?: string; action?: string; cursor?: string }) => queryKeys.platform("approvals", f),
  approval: (id: string) => queryKeys.platform("approval", id),
  approvalHash: (id: string, serverHash: string) => queryKeys.platform("approval", id, "hash", serverHash),
};

/** Sau một thao tác ghi: làm mới mọi thứ có thể đã đổi (danh sách, chi tiết tenant, job, phê duyệt). */
export function invalidatePlatform(queryClient: QueryClient, ...parts: string[]): Promise<void> {
  return queryClient.invalidateQueries({ queryKey: [PLATFORM, ...parts] });
}

export function useTenantList(f: { status?: TenantStatus; q?: string; cursor?: string }) {
  return useQuery({
    queryKey: platformKeys.tenants(f),
    queryFn: () =>
      call(api.GET("/platform/tenants", { params: { query: { limit: PAGE_SIZE, status: f.status, q: f.q, cursor: f.cursor } } })),
    placeholderData: (prev) => prev,
  });
}

/** Chi tiết tenant + ETag (khóa lạc quan cho PATCH ở P4-T03a). */
export function useTenant(tenantId: string) {
  return useQuery({
    queryKey: platformKeys.tenant(tenantId),
    queryFn: () => callWithETag(api.GET("/platform/tenants/{tenantId}", { params: { path: { tenantId } } })),
  });
}

export function useTenantInstances(tenantId: string, enabled: boolean) {
  return useQuery({
    queryKey: platformKeys.tenantInstances(tenantId),
    queryFn: () =>
      call(api.GET("/platform/tenants/{tenantId}/instances", { params: { path: { tenantId }, query: { limit: 20 } } })),
    enabled,
  });
}

export function useTenantRelay(tenantId: string, enabled: boolean) {
  return useQuery({
    queryKey: platformKeys.tenantRelay(tenantId),
    queryFn: () =>
      call(api.GET("/platform/tenants/{tenantId}/relay-regions", { params: { path: { tenantId }, query: { limit: 20 } } })),
    enabled,
  });
}

/** Job gần đây của tenant; còn job chưa xong ⇒ làm mới mỗi 5 s. */
export function useTenantJobs(tenantId: string, cursor: string | undefined, enabled: boolean) {
  return useQuery({
    queryKey: platformKeys.tenantJobs(tenantId, cursor),
    queryFn: () =>
      call(
        api.GET("/platform/tenants/{tenantId}/jobs", { params: { path: { tenantId }, query: { limit: 10, cursor } } }),
      ),
    enabled,
    placeholderData: (prev) => prev,
    refetchInterval: (q) => (q.state.data?.items.some((j) => !isSettled(j.status)) ? 5_000 : false),
  });
}

export function useJobList(f: { status?: JobStatus; kind?: string; cursor?: string }) {
  return useQuery({
    queryKey: platformKeys.jobs(f),
    queryFn: () =>
      call(api.GET("/platform/jobs", { params: { query: { limit: PAGE_SIZE, status: f.status, kind: f.kind, cursor: f.cursor } } })),
    placeholderData: (prev) => prev,
    refetchInterval: (q) => (q.state.data?.items.some((j) => !isSettled(j.status)) ? 5_000 : false),
  });
}

/**
 * Job + poll tới trạng thái cuối (2 s phút đầu, rồi 5 s — src/api/jobs.ts). `since` = lúc mở trang. Job đã ở trạng thái
 * cuối ⇒ dữ liệu của tenant đó có thể đã đổi (suspend/resume/provision…) ⇒ làm mới chi tiết + danh sách tenant.
 */
export function useJob(jobId: string, since: number) {
  const queryClient = useQueryClient();
  return useQuery({
    queryKey: platformKeys.job(jobId),
    queryFn: async () => {
      const job = await call(api.GET("/platform/jobs/{jobId}", { params: { path: { jobId } } }));
      if (isSettled(job.status) && job.tenant_id) {
        void invalidatePlatform(queryClient, "tenant", job.tenant_id);
        void invalidatePlatform(queryClient, "tenants");
      }
      return job;
    },
    refetchInterval: (q) => (q.state.status === "error" ? false : jobPollInterval(q.state.data?.status, since)),
  });
}

export function useApprovalList(f: { status?: ApprovalStatus; action?: string; cursor?: string }) {
  return useQuery({
    queryKey: platformKeys.approvals(f),
    queryFn: () =>
      call(
        api.GET("/platform/approvals", { params: { query: { limit: PAGE_SIZE, status: f.status, action: f.action, cursor: f.cursor } } }),
      ),
    placeholderData: (prev) => prev,
  });
}

export function useApproval(approvalId: string) {
  return useQuery({
    queryKey: platformKeys.approval(approvalId),
    queryFn: () => call(api.GET("/platform/approvals/{approvalId}", { params: { path: { approvalId } } })),
  });
}
