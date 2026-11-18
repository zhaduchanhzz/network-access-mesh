// Hạ tầng UI dùng chung (P4-T04): poll job phạm vi tenant (§13.1 "Thao tác dài": 202 + Location ⇒ client poll
// `GET /tenants/{tenantId}/jobs/{jobId}` tới khi job kết thúc). MVP dùng polling của TanStack Query (§12.4 Realtime).
import { useQuery } from "@tanstack/react-query";
import { api, call } from "../api/client";
import { queryKeys } from "../api/queryClient";
import type { components } from "../api/schema";

export type Job = components["schemas"]["Job"];
export type JobStatus = components["schemas"]["JobStatus"];

/** Trạng thái kết thúc của job (§6.3 provisioning_jobs.status) — ngừng poll. */
const TERMINAL: ReadonlySet<JobStatus> = new Set<JobStatus>(["succeeded", "failed", "cancelled", "rolled_back"]);

export function isTerminalJob(status: JobStatus | undefined): boolean {
  return status !== undefined && TERMINAL.has(status);
}

export const JOB_POLL_MS = 2000;

/** Job của tenant, poll mỗi `intervalMs` tới khi kết thúc; `jobId` null ⇒ không gọi. */
export function useTenantJob(tenantId: string, jobId: string | null, intervalMs: number = JOB_POLL_MS) {
  return useQuery({
    queryKey: queryKeys.tenant(tenantId, "jobs", jobId ?? "none"),
    queryFn: () => call(api.GET("/tenants/{tenantId}/jobs/{jobId}", { params: { path: { tenantId, jobId: jobId ?? "" } } })),
    enabled: jobId !== null,
    refetchInterval: (q) => (isTerminalJob(q.state.data?.status) ? false : intervalMs),
    staleTime: 0,
  });
}
