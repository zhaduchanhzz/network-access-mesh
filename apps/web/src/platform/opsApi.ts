// Truy vấn của các màn hình P4-T03 (§12.2): instances, hosts, Platform Health, relay regions, thiết lập hệ thống,
// nhân sự nền tảng, identity provider, gói dịch vụ. Cùng quy tắc với src/platform/api.ts (P4-T02): key dưới PLATFORM
// ("_platform" — §12.4), dữ liệu thật của API (không số liệu giả), ETag giữ cho lệnh sửa (If-Match — src/api/etag.ts).
import { useQuery } from "@tanstack/react-query";
import type { components } from "../api/schema";
import { api, call } from "../api/client";
import { callWithETag } from "../api/etag";
import { queryKeys } from "../api/queryClient";
import { PAGE_SIZE } from "./api";

type S = components["schemas"];
export type Instance = S["Instance"];
export type InstanceStatus = S["InstanceStatus"];
export type InstanceConfigVersion = S["InstanceConfigVersion"];
export type Backup = S["Backup"];
export type Host = S["Host"];
export type HostStatus = S["HostStatus"];
export type PlatformHealth = S["PlatformHealth"];
export type SystemSetting = S["SystemSetting"];
export type PlatformUser = S["PlatformUser"];
export type PlatformRole = S["PlatformRole"];
export type PlatformAssignableRole = S["PlatformAssignableRole"];
export type PlatformUserStatus = S["PlatformUserStatus"];
export type IdentityProvider = S["IdentityProvider"];
export type IdentityProviderStatus = S["IdentityProviderStatus"];
export type Plan = S["Plan"];
export type PlanLimits = S["PlanLimits"];

export const INSTANCE_STATUSES = [
  "allocated",
  "starting",
  "running",
  "stopped",
  "failed",
  "removed",
  "quarantined",
] as const satisfies readonly InstanceStatus[];
export const HOST_STATUSES = ["active", "draining", "disabled"] as const satisfies readonly HostStatus[];
export const PLATFORM_ROLES = [
  "super_admin",
  "platform_operator",
  "platform_support",
  "platform_viewer",
] as const satisfies readonly PlatformRole[];
export const ASSIGNABLE_ROLES = ["platform_operator", "platform_support", "platform_viewer"] as const satisfies readonly PlatformAssignableRole[];
export const PLATFORM_USER_STATUSES = ["active", "disabled"] as const satisfies readonly PlatformUserStatus[];
export const IDP_STATUSES = ["pending", "active", "retiring", "disabled"] as const satisfies readonly IdentityProviderStatus[];

type Assert<T extends true> = T;
type Covers<All, Listed> = [Exclude<All, Listed>] extends [never] ? true : false;
/** Lỗi typecheck ⇒ spec thêm giá trị chưa có trong danh sách (và chưa có bản dịch). */
export type AllInstanceStatusesListed = Assert<Covers<InstanceStatus, (typeof INSTANCE_STATUSES)[number]>>;
export type AllHostStatusesListed = Assert<Covers<HostStatus, (typeof HOST_STATUSES)[number]>>;
export type AllPlatformRolesListed = Assert<Covers<PlatformRole, (typeof PLATFORM_ROLES)[number]>>;
export type AllAssignableRolesListed = Assert<Covers<PlatformAssignableRole, (typeof ASSIGNABLE_ROLES)[number]>>;
export type AllPlatformUserStatusesListed = Assert<Covers<PlatformUserStatus, (typeof PLATFORM_USER_STATUSES)[number]>>;
export type AllIdpStatusesListed = Assert<Covers<IdentityProviderStatus, (typeof IDP_STATUSES)[number]>>;

export function isOneOf<T extends string>(list: readonly T[], v: string): v is T {
  return (list as readonly string[]).includes(v);
}

export const opsKeys = {
  instances: (f: { status?: string; host?: string; cursor?: string }) => queryKeys.platform("instances", f),
  instance: (id: string) => queryKeys.platform("instance", id),
  configVersions: (id: string, cursor?: string) => queryKeys.platform("instance", id, "config-versions", { cursor }),
  backups: (instanceId: string) => queryKeys.platform("instance", instanceId, "backups"),
  hosts: (f: { status?: string; cursor?: string }) => queryKeys.platform("hosts", f),
  host: (id: string) => queryKeys.platform("host", id),
  health: () => queryKeys.platform("health"),
  relayRegions: (cursor?: string) => queryKeys.platform("relay-regions", { cursor }),
  settings: () => queryKeys.platform("settings"),
  users: (f: { status?: string; role?: string; cursor?: string }) => queryKeys.platform("users", f),
  idps: (f: { scope?: string; cursor?: string }) => queryKeys.platform("idps", f),
  idp: (id: string) => queryKeys.platform("idp", id),
  plans: () => queryKeys.platform("plans"),
};

export function useInstanceList(f: { status?: InstanceStatus; host?: string; cursor?: string }) {
  return useQuery({
    queryKey: opsKeys.instances(f),
    queryFn: () =>
      call(api.GET("/platform/instances", { params: { query: { limit: PAGE_SIZE, status: f.status, host: f.host, cursor: f.cursor } } })),
    placeholderData: (prev) => prev,
  });
}

/** Một instance; trạng thái chuyển tiếp (allocated/starting) ⇒ làm mới mỗi 10 s. */
export function useInstance(instanceId: string) {
  return useQuery({
    queryKey: opsKeys.instance(instanceId),
    queryFn: () => call(api.GET("/platform/instances/{instanceId}", { params: { path: { instanceId } } })),
    refetchInterval: (q) => (q.state.data?.status === "allocated" || q.state.data?.status === "starting" ? 10_000 : false),
  });
}

/** Version cấu hình của instance (P4-T03 — mới nhất trước, `current` = version đang hiệu lực). */
export function useInstanceConfigVersions(instanceId: string, cursor: string | undefined) {
  return useQuery({
    queryKey: opsKeys.configVersions(instanceId, cursor),
    queryFn: () =>
      call(
        api.GET("/platform/instances/{instanceId}/config-versions", {
          params: { path: { instanceId }, query: { limit: 10, cursor } },
        }),
      ),
    placeholderData: (prev) => prev,
  });
}

/** Bản backup `succeeded` của một instance (nguồn của yêu cầu restore — platform.backup:read). */
export function useInstanceBackups(instanceId: string, enabled: boolean) {
  return useQuery({
    queryKey: opsKeys.backups(instanceId),
    queryFn: () =>
      call(api.GET("/platform/backups", { params: { query: { instance: instanceId, status: "succeeded", limit: 20 } } })),
    enabled,
  });
}

export function useHostList(f: { status?: HostStatus; cursor?: string }) {
  return useQuery({
    queryKey: opsKeys.hosts(f),
    queryFn: () => call(api.GET("/platform/hosts", { params: { query: { limit: PAGE_SIZE, status: f.status, cursor: f.cursor } } })),
    placeholderData: (prev) => prev,
  });
}

export function useHost(hostId: string) {
  return useQuery({
    queryKey: opsKeys.host(hostId),
    queryFn: () => call(api.GET("/platform/hosts/{hostId}", { params: { path: { hostId } } })),
  });
}

/** Health tổng hợp — mỗi số kèm `checked_at`; tự làm mới mỗi 30 s. */
export function usePlatformHealth() {
  return useQuery({
    queryKey: opsKeys.health(),
    queryFn: () => call(api.GET("/platform/health")),
    refetchInterval: 30_000,
  });
}

export function usePlatformRelayRegions(cursor: string | undefined) {
  return useQuery({
    queryKey: opsKeys.relayRegions(cursor),
    queryFn: () => call(api.GET("/platform/relay-regions", { params: { query: { limit: PAGE_SIZE, cursor } } })),
    placeholderData: (prev) => prev,
  });
}

/** Tập khóa đóng của system_settings; mỗi khóa mang `etag` (If-Match của PUT). */
export function usePlatformSettings() {
  return useQuery({
    queryKey: opsKeys.settings(),
    queryFn: () => call(api.GET("/platform/settings")),
  });
}

export function usePlatformUsers(f: { status?: PlatformUserStatus; role?: PlatformRole; cursor?: string }) {
  return useQuery({
    queryKey: opsKeys.users(f),
    queryFn: () =>
      call(api.GET("/platform/users", { params: { query: { limit: PAGE_SIZE, status: f.status, role: f.role, cursor: f.cursor } } })),
    placeholderData: (prev) => prev,
  });
}

export function useIdentityProviders(f: { scope?: "platform" | "tenant"; cursor?: string }) {
  return useQuery({
    queryKey: opsKeys.idps(f),
    queryFn: () =>
      call(api.GET("/platform/identity-providers", { params: { query: { limit: PAGE_SIZE, scope: f.scope, cursor: f.cursor } } })),
    placeholderData: (prev) => prev,
  });
}

/** Một IdP + ETag (If-Match của PATCH). */
export function useIdentityProvider(idpId: string) {
  return useQuery({
    queryKey: opsKeys.idp(idpId),
    queryFn: () => callWithETag(api.GET("/platform/identity-providers/{idpId}", { params: { path: { idpId } } })),
  });
}

export function usePlans(enabled = true) {
  return useQuery({
    queryKey: opsKeys.plans(),
    queryFn: () => call(api.GET("/platform/plans")),
    enabled,
  });
}
