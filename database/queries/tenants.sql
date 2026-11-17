-- Tenant Registry (P2-T11, §5.4, §6.3, §13.2): đọc phạm vi tenant (pool tenant, store.WithTenantTx — RLS chỉ thấy tenant
-- đang đặt), đọc phạm vi platform cho nhân sự nền tảng (pool platform, store.WithPlatformTx — chỉ metadata registry, bảng
-- nội bộ tenant như tenant_memberships không có nhánh platform) và các lệnh ghi của `meshguard admin` (pool platform):
-- adopt-instance, register-platform-idp, set-idp-client-secret. Mẫu ILIKE được escape ở Go (ký tự `\` mặc định của LIKE).
-- Không truy vấn nào ở đây đọc hay ghi giá trị secret: api_key_secret_ref / client_secret_ref chỉ là reference mgsec://.

-- name: GetTenantView :one
-- GET /tenants/{t} (pool tenant) và GET /platform/tenants/{t} (pool platform): tenant + server_url của instance chưa
-- removed (control_url — §13.3). LEFT JOIN: tenant chưa có instance vẫn trả hàng.
SELECT sqlc.embed(t), i.server_url AS control_url
FROM tenants t
LEFT JOIN tenant_instances i ON i.tenant_id = t.id AND i.status <> 'removed'
WHERE t.id = sqlc.arg(id);

-- name: ListMemberTenantsPage :many
-- GET /tenants (pool tenant, WithTenantTx với tenant của chính identity — §8.2: identity thuộc đúng một tenant): tenant
-- mà identity là thành viên đang hoạt động; tenant đã xóa không xuất hiện. Thứ tự (created_at, id) tăng dần, con trỏ =
-- phần tử cuối của trang trước.
SELECT sqlc.embed(t), i.server_url AS control_url
FROM tenant_memberships m
JOIN tenants t ON t.id = m.tenant_id
LEFT JOIN tenant_instances i ON i.tenant_id = t.id AND i.status <> 'removed'
WHERE m.identity_id = sqlc.arg(identity_id) AND m.status = 'active' AND t.status <> 'deleted'
  AND (sqlc.narg(after_created_at)::timestamptz IS NULL
       OR (t.created_at, t.id) > (sqlc.narg(after_created_at)::timestamptz, sqlc.narg(after_id)::uuid))
ORDER BY t.created_at, t.id
LIMIT sqlc.arg(row_limit);

-- name: ListRegistryTenantsPage :many
-- GET /platform/tenants (pool platform): chỉ metadata registry; lọc theo trạng thái và slug/tên.
SELECT sqlc.embed(t), i.server_url AS control_url
FROM tenants t
LEFT JOIN tenant_instances i ON i.tenant_id = t.id AND i.status <> 'removed'
WHERE (sqlc.narg(status)::text IS NULL OR t.status = sqlc.narg(status)::text)
  AND (sqlc.narg(pattern)::text IS NULL OR t.slug::text ILIKE sqlc.narg(pattern)::text
       OR t.name ILIKE sqlc.narg(pattern)::text)
  AND (sqlc.narg(after_created_at)::timestamptz IS NULL
       OR (t.created_at, t.id) > (sqlc.narg(after_created_at)::timestamptz, sqlc.narg(after_id)::uuid))
ORDER BY t.created_at, t.id
LIMIT sqlc.arg(row_limit);

-- name: ListTenantMembersPage :many
-- GET /tenants/{t}/users (pool tenant): membership + danh tính + khóa role; tenant_id lọc ở truy vấn ngoài RLS (§8.8).
SELECT m.id, m.tenant_id, m.identity_id, m.status, m.headscale_username, m.version, m.created_at,
       r.key AS role_key, i.display_name, i.email, i.subject
FROM tenant_memberships m
JOIN identities i ON i.tenant_id = m.tenant_id AND i.id = m.identity_id
JOIN roles r ON r.id = m.role_id AND r.scope = m.role_scope
WHERE m.tenant_id = sqlc.arg(tenant_id)
  AND (sqlc.narg(role_key)::text IS NULL OR r.key = sqlc.narg(role_key)::text)
  AND (sqlc.narg(status)::text IS NULL OR m.status = sqlc.narg(status)::text)
  AND (sqlc.narg(pattern)::text IS NULL OR i.display_name ILIKE sqlc.narg(pattern)::text
       OR i.email::text ILIKE sqlc.narg(pattern)::text)
  AND (sqlc.narg(after_created_at)::timestamptz IS NULL
       OR (m.created_at, m.id) > (sqlc.narg(after_created_at)::timestamptz, sqlc.narg(after_id)::uuid))
ORDER BY m.created_at, m.id
LIMIT sqlc.arg(row_limit);

-- name: GetTenantMember :one
-- GET /tenants/{t}/users/{membershipId} (pool tenant): membership của tenant khác ⇒ không có hàng (404 — §8.4 bất biến 6).
SELECT m.id, m.tenant_id, m.identity_id, m.status, m.headscale_username, m.version, m.created_at,
       r.key AS role_key, i.display_name, i.email, i.subject
FROM tenant_memberships m
JOIN identities i ON i.tenant_id = m.tenant_id AND i.id = m.identity_id
JOIN roles r ON r.id = m.role_id AND r.scope = m.role_scope
WHERE m.tenant_id = sqlc.arg(tenant_id) AND m.id = sqlc.arg(id);

-- name: ListInstancesPage :many
-- GET /platform/instances (pool platform). api_key_secret_ref không bao giờ rời service (schema Instance không có nó).
SELECT * FROM tenant_instances
WHERE (sqlc.narg(status)::text IS NULL OR status = sqlc.narg(status)::text)
  AND (sqlc.narg(host_id)::uuid IS NULL OR host_id = sqlc.narg(host_id)::uuid)
  AND (sqlc.narg(after_created_at)::timestamptz IS NULL
       OR (created_at, id) > (sqlc.narg(after_created_at)::timestamptz, sqlc.narg(after_id)::uuid))
ORDER BY created_at, id
LIMIT sqlc.arg(row_limit);

-- name: GetLiveTenantBySlug :one
-- adopt-instance: slug đã thuộc tenant khác chưa (partial UNIQUE(slug) WHERE status <> 'deleted').
SELECT * FROM tenants
WHERE slug = sqlc.arg(slug) AND status <> 'deleted';

-- name: InsertAdoptedTenant :one
-- adopt-instance (pool platform): id lấy từ meta/instance.json của tenant dựng tay ở Phase 1.
INSERT INTO tenants (id, slug, name, status, deployment_region)
VALUES (sqlc.arg(id), sqlc.arg(slug), sqlc.arg(name), sqlc.arg(status), sqlc.narg(deployment_region))
RETURNING *;

-- name: TransitionTenantStatus :one
-- Chuyển trạng thái có điều kiện (không hàng ⇒ trạng thái hiện tại khác from_status).
UPDATE tenants
SET status = sqlc.arg(status), updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND status = sqlc.arg(from_status)
RETURNING *;

-- name: GetHostByName :one
-- Pool platform (bảng P).
SELECT * FROM hosts
WHERE name = sqlc.arg(name);

-- name: SetTenantInstanceAPIKey :one
-- Pool platform: chỉ reference mgsec:// của API key + prefix công khai + hạn (§6.3) — không bao giờ là key.
UPDATE tenant_instances
SET api_key_secret_ref = sqlc.narg(api_key_secret_ref), api_key_prefix = sqlc.narg(api_key_prefix),
    api_key_expires_at = sqlc.narg(api_key_expires_at), updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND tenant_id = sqlc.arg(tenant_id)
RETURNING *;

-- name: SetTenantInstanceRuntime :one
-- Pool platform: version Headscale đã kiểm qua GET /version và image digest đang chạy.
UPDATE tenant_instances
SET headscale_version = sqlc.arg(headscale_version), image_digest = sqlc.arg(image_digest), updated_at = now(),
    version = version + 1
WHERE id = sqlc.arg(id) AND tenant_id = sqlc.arg(tenant_id)
RETURNING *;

-- name: TransitionTenantInstanceStatus :one
-- Chuyển trạng thái có điều kiện của instance (TenantInstanceStatus — §13.3).
UPDATE tenant_instances
SET status = sqlc.arg(status), updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND tenant_id = sqlc.arg(tenant_id) AND status = sqlc.arg(from_status)
RETURNING *;

-- name: InsertIdentityProviderWithID :one
-- Pool platform. id cấp trước (MG_IDP_ID_* — P2-T05: redirect URI của realm chứa id này).
INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, driver, driver_ref, status)
VALUES (sqlc.arg(id), sqlc.arg(scope), sqlc.narg(tenant_id), sqlc.arg(issuer), sqlc.arg(client_id), sqlc.arg(driver),
        sqlc.narg(driver_ref), sqlc.arg(status))
RETURNING *;

-- name: GetActiveTenantIdentityProvider :one
-- Hàng active của tenant (partial UNIQUE(tenant_id) WHERE status = 'active').
SELECT * FROM identity_providers
WHERE tenant_id = sqlc.arg(tenant_id) AND status = 'active';

-- name: SetIdentityProviderClientSecretRef :one
-- Pool platform: chỉ reference mgsec:// của client secret (§8.2) — issuer/client_id bất biến không đổi ở đây.
UPDATE identity_providers
SET client_secret_ref = sqlc.arg(client_secret_ref), updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id)
RETURNING *;
