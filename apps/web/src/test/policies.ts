// Dữ liệu mẫu của trang Policies/Tags (P4-T11) — đúng schema của api/openapi.yaml (type sinh), chỉ dùng trong test.
import type { components } from "../api/schema";
import { json, TENANT_A, tenantSession } from "./helpers";

type S = components["schemas"];

export const ME_IDENTITY = "0190c000-0000-7000-8000-0000000000c1"; // principal của tenantSession
export const OTHER_IDENTITY = "0190c000-0000-7000-8000-0000000000c2";
export const M_ME = "0190d000-0000-7000-8000-000000000000";
export const M_OWNER = "0190d000-0000-7000-8000-0000000000b0";
export const G_ENG = "0190e100-0000-7000-8000-000000000001";
export const T_WEB = "0190e200-0000-7000-8000-000000000001";
export const T_ROUTER = "0190e200-0000-7000-8000-000000000002";
export const R_DB = "0190e300-0000-7000-8000-000000000001";
export const V1 = "0190f000-0000-7000-8000-000000000001";
export const V2 = "0190f000-0000-7000-8000-000000000002";
export const V3 = "0190f000-0000-7000-8000-000000000003";
export const JOB = "0190f100-0000-7000-8000-000000000001";
export const AT = "2026-11-19T02:00:00Z";
export const SHA_A = "a".repeat(64);
export const SHA_B = "b".repeat(64);
export const base = `/tenants/${TENANT_A}`;

export function session(role: string, identity: string = ME_IDENTITY) {
  const s = tenantSession([{ tenantId: TENANT_A, slug: "tenant-a", name: "Tenant A", role }]);
  s.principal.identity_id = identity;
  return s;
}

export const USERS: S["MembershipList"] = {
  items: [
    { id: M_ME, identity_id: ME_IDENTITY, display_name: "Nguyễn Văn A", email: "a@example.test", role: "tenant_admin", status: "active", headscale_username: `mg-${M_ME}`, version: 1 },
    { id: M_OWNER, identity_id: OTHER_IDENTITY, display_name: "Trần Thị B", email: "b@example.test", role: "tenant_owner", status: "active", headscale_username: `mg-${M_OWNER}`, version: 1 },
  ],
  next_cursor: null,
};

export const GROUPS: S["GroupList"] = {
  items: [{ id: G_ENG, name: "eng", source: "portal", sensitive: false, member_count: 1, version: 1, created_at: AT, updated_at: AT }],
  next_cursor: null,
};

export function tag(id: string, name: string, over: Partial<S["Tag"]> = {}): S["Tag"] {
  return { id, name, purpose: "server", platform_managed: false, version: 1, etag: '"1"', created_at: AT, updated_at: AT, ...over };
}

export const TAGS: S["TagList"] = {
  items: [tag(T_WEB, "tag:web", { description: "web servers" }), tag(T_ROUTER, "tag:router", { purpose: "router", platform_managed: true })],
  next_cursor: null,
};

export const SOURCE: S["PolicySource"] = {
  grants: [{ src: [{ type: "group", ref: G_ENG }], dst: [{ type: "tag", ref: T_WEB }], ip: ["tcp:443"] }],
  ssh: [],
};

export function version(id: string, over: Partial<S["PolicyVersion"]> = {}): S["PolicyVersion"] {
  const revision = over.revision ?? 1;
  return {
    id,
    version: id === V1 ? 1 : id === V2 ? 2 : 3,
    revision,
    etag: `"${String(revision)}"`,
    kind: "user",
    state: "draft",
    content_sha256: SHA_A,
    source: SOURCE,
    desired: false,
    parent_version_id: V1,
    created_by: ME_IDENTITY,
    created_at: AT,
    updated_at: AT,
    ...over,
  };
}

export function current(over: Partial<S["PolicyCurrent"]> = {}): S["PolicyCurrent"] {
  return {
    desired: version(V1, { state: "approved", desired: true, approved_by: ME_IDENTITY, approved_at: AT, review_mode: "self", parent_version_id: undefined }),
    applied: {
      id: "0190f200-0000-7000-8000-000000000001",
      policy_version_id: V1,
      trigger: "manual",
      state: "applied",
      applied_sha256: SHA_B,
      headscale_updated_at: AT,
      created_at: AT,
      finished_at: AT,
    },
    four_eyes: false,
    apply_step_up: false,
    ...over,
  };
}

export function job(status: S["JobStatus"]): S["Job"] {
  return {
    id: JOB,
    kind: "policy.apply",
    tenant_id: TENANT_A,
    status,
    current_step: null,
    steps: [{ name: "apply", status: status === "succeeded" ? "succeeded" : "running", attempt: 1, started_at: AT, finished_at: null, message: null }],
    created_at: AT,
  };
}

/** Các route chung: session, tenant, danh mục tên (users/groups/tags), current, danh sách version. */
export function common(role: string, identity: string = ME_IDENTITY, cur: S["PolicyCurrent"] = current()) {
  return {
    "GET /auth/session": json(200, session(role, identity)),
    [`GET ${base}`]: json(200, {
      id: TENANT_A,
      slug: "tenant-a",
      name: "Tenant A",
      status: "active",
      deployment_region: "lab",
      plan: "standard",
      limits: {},
      control_url: "https://tenant-a.mesh.example.test",
      created_at: AT,
      updated_at: AT,
      version: 1,
    }),
    [`GET ${base}/notifications`]: json(200, { items: [], next_cursor: null }),
    [`GET ${base}/users`]: json(200, USERS),
    [`GET ${base}/groups`]: json(200, GROUPS),
    [`GET ${base}/tags`]: json(200, TAGS),
    [`GET ${base}/policies/current`]: json(200, cur),
    [`GET ${base}/policies`]: json(200, { items: [version(V2), cur.desired ?? version(V1)], next_cursor: null }),
  };
}
