// Truy vấn của trang Policies + Tags (P4-T11) — mọi query key bắt đầu bằng tenantId (§12.4). Version đọc kèm ETag
// (= `"<revision>"`) để gửi lại trong If-Match; tên principal đọc từ các danh mục của tenant (users, groups, tags, tài
// nguyên mạng) —
// chỉ để hiển thị, tham chiếu luôn là id.
import { useQuery } from "@tanstack/react-query";
import { api, call } from "../../api/client";
import { callWithETag } from "../../api/etag";
import { queryKeys } from "../../api/queryClient";
import { can } from "../../auth/permissions";
import type { NameBook, PolicyVersion } from "./model";

export const policyKeys = {
  all: (t: string) => queryKeys.tenant(t, "policies"),
  current: (t: string) => queryKeys.tenant(t, "policies", "current"),
  list: (t: string, cursor: string) => queryKeys.tenant(t, "policies", "list", { cursor }),
  version: (t: string, id: string) => queryKeys.tenant(t, "policies", "version", id),
  diff: (t: string, id: string, revision: number, against: string) => queryKeys.tenant(t, "policies", "diff", id, revision, against),
  names: (t: string) => queryKeys.tenant(t, "policies", "names"),
  tags: (t: string, cursor: string) => queryKeys.tenant(t, "tags", { cursor }),
};

/** Lần poll trạng thái áp dụng khi lần áp gần nhất còn `pending`. */
export const APPLY_POLL_MS = 3000;

export function usePolicyCurrent(tenantId: string) {
  return useQuery({
    queryKey: policyKeys.current(tenantId),
    queryFn: () => call(api.GET("/tenants/{tenantId}/policies/current", { params: { path: { tenantId } } })),
    refetchInterval: (q) => (q.state.data?.latest?.state === "pending" ? APPLY_POLL_MS : false),
  });
}

export function usePolicyVersions(tenantId: string, cursor: string | undefined) {
  return useQuery({
    queryKey: policyKeys.list(tenantId, cursor ?? ""),
    queryFn: () =>
      call(api.GET("/tenants/{tenantId}/policies", { params: { path: { tenantId }, query: { limit: 25, ...(cursor ? { cursor } : {}) } } })),
  });
}

/** Một version + ETag của phản hồi (giá trị If-Match). */
export function usePolicyVersion(tenantId: string, versionId: string) {
  return useQuery({
    queryKey: policyKeys.version(tenantId, versionId),
    queryFn: () => callWithETag(api.GET("/tenants/{tenantId}/policies/{versionId}", { params: { path: { tenantId, versionId } } })),
    retry: false,
  });
}

export function usePolicyDiff(tenantId: string, v: PolicyVersion, against: string) {
  return useQuery({
    queryKey: policyKeys.diff(tenantId, v.id, v.revision, against),
    queryFn: () =>
      call(
        api.GET("/tenants/{tenantId}/policies/{versionId}/diff", {
          params: { path: { tenantId, versionId: v.id }, query: against ? { against } : {} },
        }),
      ),
  });
}

const MAX_PAGES = 5;

/** Đọc hết (tối đa MAX_PAGES trang × 200) một danh sách con trỏ. */
async function allPages<T>(page: (cursor: string | undefined) => Promise<{ items: T[]; next_cursor?: string | null }>): Promise<T[]> {
  const out: T[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const p = await page(cursor);
    out.push(...p.items);
    if (!p.next_cursor) break;
    cursor = p.next_cursor;
  }
  return out;
}

export interface Catalog {
  book: NameBook;
  users: { id: string; identityId: string; label: string; status: string }[];
  groups: { id: string; name: string }[];
  tags: { id: string; name: string; purpose: string; platformManaged: boolean }[];
  /** danh mục tài nguyên mạng (GET /resources — P4-T12); `null` ⇒ role không đọc được hoặc đọc lỗi */
  resources: { id: string; name: string; address: string }[] | null;
  /** identity id → tên hiển thị (người soạn/gửi/duyệt) */
  identities: ReadonlyMap<string, string>;
}

/** Danh mục tên của tenant cho bộ chọn principal và hiển thị — mỗi phần chỉ đọc khi role có quyền đọc của nó. */
export function usePolicyNames(tenantId: string, role: string) {
  return useQuery({
    queryKey: policyKeys.names(tenantId),
    staleTime: 30_000,
    queryFn: async (): Promise<Catalog> => {
      const path = { tenantId };
      const [users, groups, tags, resources] = await Promise.all([
        can(role, "tenant.user:read")
          ? allPages((cursor) => call(api.GET("/tenants/{tenantId}/users", { params: { path, query: { limit: 200, ...(cursor ? { cursor } : {}) } } })))
          : Promise.resolve([]),
        can(role, "tenant.group:read")
          ? allPages((cursor) => call(api.GET("/tenants/{tenantId}/groups", { params: { path, query: { limit: 200, ...(cursor ? { cursor } : {}) } } })))
          : Promise.resolve([]),
        can(role, "tenant.tag:read")
          ? allPages((cursor) => call(api.GET("/tenants/{tenantId}/tags", { params: { path, query: { limit: 200, ...(cursor ? { cursor } : {}) } } })))
          : Promise.resolve([]),
        // tài nguyên mạng (G4b-E4): đọc lỗi không làm hỏng cả danh mục — bộ chọn báo "không đọc được"
        can(role, "tenant.resource:read")
          ? allPages((cursor) => call(api.GET("/tenants/{tenantId}/resources", { params: { path, query: { limit: 200, ...(cursor ? { cursor } : {}) } } }), { notify: false })).catch(
              () => null,
            )
          : Promise.resolve(null),
      ]);
      const userLabel = (u: (typeof users)[number]) => (u.email ? `${u.display_name} <${u.email}>` : u.display_name);
      return {
        book: {
          users: new Map(users.map((u) => [u.id, u.email ?? u.display_name])),
          groups: new Map(groups.map((g) => [g.id, g.name])),
          tags: new Map(tags.map((t) => [t.id, t.name])),
          resources: new Map((resources ?? []).map((r) => [r.id, r.name])),
        },
        users: users.filter((u) => u.status !== "offboarded").map((u) => ({ id: u.id, identityId: u.identity_id, label: userLabel(u), status: u.status })),
        groups: groups.map((g) => ({ id: g.id, name: g.name })),
        tags: tags.map((t) => ({ id: t.id, name: t.name, purpose: t.purpose, platformManaged: t.platform_managed })),
        resources: resources?.map((r) => ({ id: r.id, name: r.name, address: r.address })) ?? null,
        identities: new Map(users.map((u) => [u.identity_id, u.display_name])),
      };
    },
  });
}
