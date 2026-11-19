// Truy vấn của Users / Groups / Invitations (P4-T09a): mọi key bắt đầu bằng tenantId (§12.4 — queryKeys.tenant), dữ liệu
// thật từ API của P4-T09 / P3-T05a / P3-T04a / P2-T12 — không số liệu cố định. Bản đọc có phiên bản (user, group) giữ
// `ETag` cho `If-Match` của lệnh sửa (src/api/etag.ts).
import { useQuery, type QueryClient } from "@tanstack/react-query";
import { api, call } from "../../api/client";
import { callWithETag, type Versioned } from "../../api/etag";
import { isSettled } from "../../api/jobs";
import { queryKeys } from "../../api/queryClient";
import { APPROVAL_ACTION_GROUP_MEMBERS, IDP_INVITE_JOB, PAGE_SIZE, type ApprovalRequest, type Group, type InvitationStatus, type Membership } from "./model";

export const OFFBOARD_POLL_MS = 2000;
export const APPROVAL_POLL_MS = 3000;
export const INVITE_JOB_POLL_MS = 2000;

export const peopleKeys = {
  users: (tenantId: string, f: Record<string, unknown> = {}) => queryKeys.tenant(tenantId, "people", "users", f),
  user: (tenantId: string, id: string) => queryKeys.tenant(tenantId, "people", "user", id),
  groups: (tenantId: string, f: Record<string, unknown> = {}) => queryKeys.tenant(tenantId, "people", "groups", f),
  group: (tenantId: string, id: string) => queryKeys.tenant(tenantId, "people", "group", id),
  invitations: (tenantId: string, f: Record<string, unknown> = {}) => queryKeys.tenant(tenantId, "people", "invitations", f),
  inviteJobs: (tenantId: string) => queryKeys.tenant(tenantId, "people", "invite-jobs"),
  approval: (tenantId: string, id: string) => queryKeys.tenant(tenantId, "people", "approval", id),
  groupApprovals: (tenantId: string, groupId: string) => queryKeys.tenant(tenantId, "people", "group-approvals", groupId),
};

/** Sau một thao tác ghi: làm mới danh sách/chi tiết của mục đó (key bắt đầu bằng [tenantId, "people", part]). */
export function invalidatePeople(queryClient: QueryClient, tenantId: string, ...parts: string[]): Promise<void> {
  return queryClient.invalidateQueries({ queryKey: queryKeys.tenant(tenantId, "people", ...parts) });
}

export interface UserFilters {
  q?: string;
  role?: string;
  status?: string;
  cursor?: string;
}

export function useUsers(tenantId: string, f: UserFilters, opts: { enabled?: boolean; limit?: number } = {}) {
  return useQuery({
    queryKey: peopleKeys.users(tenantId, { ...f, limit: opts.limit ?? PAGE_SIZE }),
    queryFn: () =>
      call(
        api.GET("/tenants/{tenantId}/users", {
          params: { path: { tenantId }, query: { limit: opts.limit ?? PAGE_SIZE, q: f.q || undefined, role: f.role || undefined, status: f.status || undefined, cursor: f.cursor } },
        }),
      ),
    enabled: opts.enabled ?? true,
    placeholderData: (prev) => prev,
    // còn thành viên đang offboard (pha 2 chưa xong) ⇒ làm mới tới khi job kết thúc
    refetchInterval: (q) => (q.state.data?.items.some((m) => m.offboarding?.state === "pending") ? OFFBOARD_POLL_MS * 2 : false),
  });
}

/** Một thành viên + ETag; offboard đang `pending` ⇒ poll tới `applied`/`failed` (T-17: chỉ báo xong khi job xác minh). */
export function useUser(tenantId: string, membershipId: string) {
  return useQuery<Versioned<Membership>>({
    queryKey: peopleKeys.user(tenantId, membershipId),
    queryFn: () => callWithETag(api.GET("/tenants/{tenantId}/users/{membershipId}", { params: { path: { tenantId, membershipId } } })),
    refetchInterval: (q) => (q.state.data?.data.offboarding?.state === "pending" && q.state.error === null ? OFFBOARD_POLL_MS : false),
    retry: false,
  });
}

export function useGroups(tenantId: string, f: { q?: string; cursor?: string }) {
  return useQuery({
    queryKey: peopleKeys.groups(tenantId, f),
    queryFn: () =>
      call(api.GET("/tenants/{tenantId}/groups", { params: { path: { tenantId }, query: { limit: PAGE_SIZE, q: f.q || undefined, cursor: f.cursor } } })),
    placeholderData: (prev) => prev,
  });
}

export function useGroup(tenantId: string, groupId: string) {
  return useQuery<Versioned<Group>>({
    queryKey: peopleKeys.group(tenantId, groupId),
    queryFn: () => callWithETag(api.GET("/tenants/{tenantId}/groups/{groupId}", { params: { path: { tenantId, groupId } } })),
    retry: false,
  });
}

export function useInvitations(tenantId: string, f: { status?: InvitationStatus; cursor?: string }) {
  return useQuery({
    queryKey: peopleKeys.invitations(tenantId, f),
    queryFn: () =>
      call(
        api.GET("/tenants/{tenantId}/invitations", {
          params: { path: { tenantId }, query: { limit: PAGE_SIZE, status: f.status, cursor: f.cursor } },
        }),
      ),
    placeholderData: (prev) => prev,
  });
}

/**
 * Job `member.idp_invite` mới nhất của mỗi lời mời (resource = invitation, P4-T09): GET /jobs?kind=member.idp_invite,
 * ghép theo `resource.id`. `watch` = id lời mời vừa tạo/gửi lại: poll tới khi job của nó có mặt và kết thúc.
 */
export function useInviteJobs(tenantId: string, enabled: boolean, watch: string | null) {
  return useQuery({
    queryKey: peopleKeys.inviteJobs(tenantId),
    queryFn: async () => {
      const page = await call(api.GET("/tenants/{tenantId}/jobs", { params: { path: { tenantId }, query: { kind: IDP_INVITE_JOB, limit: 100 } } }));
      const byInvitation = new Map<string, (typeof page.items)[number]>();
      // danh sách mới nhất trước ⇒ giữ job đầu tiên gặp cho mỗi lời mời
      for (const j of page.items) {
        if (j.resource?.type === "invitation" && !byInvitation.has(j.resource.id)) byInvitation.set(j.resource.id, j);
      }
      return byInvitation;
    },
    enabled,
    refetchInterval: (q) => {
      if (!watch || q.state.error) return false;
      const j = q.state.data?.get(watch);
      return j && isSettled(j.status) ? false : INVITE_JOB_POLL_MS;
    },
  });
}

/** Một yêu cầu phê duyệt trong tenant (P3-T04a) — poll khi còn chờ (`pending`/`approved` chưa thực thi). */
export function useTenantApproval(tenantId: string, approvalId: string | null, enabled: boolean) {
  return useQuery<ApprovalRequest>({
    queryKey: peopleKeys.approval(tenantId, approvalId ?? "none"),
    queryFn: () => call(api.GET("/tenants/{tenantId}/approvals/{approvalId}", { params: { path: { tenantId, approvalId: approvalId ?? "" } } })),
    enabled: enabled && approvalId !== null,
    refetchInterval: (q) => {
      const s = q.state.data?.status;
      return q.state.error === null && (s === undefined || s === "pending" || s === "approved") ? APPROVAL_POLL_MS : false;
    },
  });
}

/** Yêu cầu đổi thành viên đang chờ của MỘT group (`tenant.group.set_members`, resource_id = group). */
export function useGroupApprovals(tenantId: string, groupId: string, enabled: boolean) {
  return useQuery({
    queryKey: peopleKeys.groupApprovals(tenantId, groupId),
    queryFn: async () => {
      const page = await call(
        api.GET("/tenants/{tenantId}/approvals", {
          params: { path: { tenantId }, query: { status: "pending", action: APPROVAL_ACTION_GROUP_MEMBERS, limit: 100 } },
        }),
      );
      return page.items.filter((a) => a.resource_id === groupId);
    },
    enabled,
  });
}
