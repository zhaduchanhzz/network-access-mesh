// Thao tác dài (§13.1, §13.5): 202 Accepted + `Location` của job (phạm vi platform: /api/v1/platform/jobs/{id}; phạm vi
// tenant: /api/v1/tenants/{t}/jobs/{id}); thao tác 2P trả `Location` của yêu cầu phê duyệt. Client poll job tới trạng
// thái cuối (MVP: polling qua TanStack Query — §12.4 "Realtime"). Bản duy nhất cho cả hai console (P4-T02 + P4-T04).
import { useQuery } from "@tanstack/react-query";
import { api, call } from "./client";
import { queryKeys } from "./queryClient";
import type { components } from "./schema";

export type Job = components["schemas"]["Job"];
export type PlatformJob = components["schemas"]["PlatformJob"];
export type JobStatus = components["schemas"]["JobStatus"];
export type JobStepStatus = components["schemas"]["JobStepStatus"];

export const JOB_STATUSES = [
  "queued",
  "running",
  "failed_resumable",
  "compensating",
  "rolled_back",
  "succeeded",
  "failed",
  "cancelled",
] as const satisfies readonly JobStatus[];
type MissingStatus = Exclude<JobStatus, (typeof JOB_STATUSES)[number]>;
type Assert<T extends true> = T;
/** Lỗi typecheck ở đây ⇒ spec thêm trạng thái job chưa có trong JOB_STATUSES (và chưa có bản dịch). */
export type AllJobStatusesListed = Assert<[MissingStatus] extends [never] ? true : false>;

/** Trạng thái không còn tự đổi (§11.3): không poll nữa. `failed_resumable` chỉ đổi khi người vận hành /retry hoặc
 * /rollback (job vòng đời của platform) — poll tiếp không mang lại gì. */
const SETTLED: ReadonlySet<JobStatus> = new Set(["succeeded", "failed", "cancelled", "rolled_back", "failed_resumable"]);

export function isSettled(status: JobStatus | undefined): boolean {
  return status !== undefined && SETTLED.has(status);
}

/**
 * Chu kỳ poll của một job: 2 s trong phút đầu (provisioning có bước nhanh), sau đó 5 s; dừng khi đã ở trạng thái cuối.
 * `since` là lúc bắt đầu theo dõi (ms).
 */
export function jobPollInterval(status: JobStatus | undefined, since: number, now: number = Date.now()): number | false {
  if (isSettled(status)) return false;
  return now - since < 60_000 ? 2_000 : 5_000;
}

const PLATFORM_JOB_RE = /^\/api\/v1\/platform\/jobs\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;
const TENANT_JOB_RE =
  /^\/api\/v1\/tenants\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/jobs\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;
const APPROVAL_RE =
  /^\/api\/v1\/(?:platform|tenants\/[0-9a-f-]{36})\/approvals\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

export type JobRef = { scope: "platform"; jobId: string } | { scope: "tenant"; tenantId: string; jobId: string };

/** Location của 202 ⇒ job (chỉ đường dẫn tương đối cùng origin dạng của spec; giá trị khác ⇒ null). */
export function jobFromLocation(location: string | null): JobRef | null {
  if (!location) return null;
  location = location.trim();
  const p = PLATFORM_JOB_RE.exec(location);
  if (p?.[1]) return { scope: "platform", jobId: p[1].toLowerCase() };
  const t = TENANT_JOB_RE.exec(location);
  if (t?.[1] && t[2]) return { scope: "tenant", tenantId: t[1].toLowerCase(), jobId: t[2].toLowerCase() };
  return null;
}

/** ID job trong `Location` phạm vi tenant — chỉ khi đúng tenant đang xem (không theo URL server trả mà chưa kiểm). */
export function tenantJobFromLocation(location: string | null, tenantId: string): string | null {
  const ref = jobFromLocation(location);
  return ref?.scope === "tenant" && ref.tenantId === tenantId.toLowerCase() ? ref.jobId : null;
}

/** Location của 202 thao tác 2P ⇒ id của yêu cầu phê duyệt. */
export function approvalFromLocation(location: string | null): string | null {
  const m = location ? APPROVAL_RE.exec(location) : null;
  return m?.[1]?.toLowerCase() ?? null;
}

/**
 * 19 bước của `tenant.provision` (§11.3) theo thứ tự — trùng `orchestrator.Steps` (Go; test src/api/jobs.test.ts đọc
 * internal/provisioning/orchestrator/model.go). Job chỉ ghi bước đã chạy; timeline hiện các bước còn lại là "chưa chạy".
 */
export const PROVISION_STEPS = [
  "validate",
  "registry.create",
  "placement.allocate",
  "dns.ensure",
  "secrets.generate",
  "idp.ensure",
  "storage.create",
  "config.render",
  "network.ensure",
  "instance.start",
  "instance.wait_healthy",
  "policy.bootstrap",
  "apikey.bootstrap",
  "edge.attach",
  "policy.verify",
  "tenant.configure",
  "relay.assign",
  "edge.verify",
  "activate",
] as const;

/** Bước dự kiến của một kind (chỉ tenant.provision có danh mục cố định ở §11.3; kind khác ⇒ chỉ bước đã ghi). */
export function plannedSteps(kind: string): readonly string[] {
  return kind === "tenant.provision" ? PROVISION_STEPS : [];
}

export const JOB_POLL_MS = 2000;

/** Job phạm vi tenant (GET /tenants/{t}/jobs/{id}), poll mỗi `intervalMs` tới trạng thái cuối; `jobId` null ⇒ không gọi. */
export function useTenantJob(tenantId: string, jobId: string | null, intervalMs: number = JOB_POLL_MS) {
  return useQuery({
    queryKey: queryKeys.tenant(tenantId, "jobs", jobId ?? "none"),
    queryFn: () => call(api.GET("/tenants/{tenantId}/jobs/{jobId}", { params: { path: { tenantId, jobId: jobId ?? "" } } })),
    enabled: jobId !== null,
    refetchInterval: (q) => (isSettled(q.state.data?.status) ? false : intervalMs),
    staleTime: 0,
  });
}
