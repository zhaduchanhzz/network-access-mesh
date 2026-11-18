-- P4-T03a — thiết lập của tenant, IdP của tenant, yêu cầu xóa tenant (§8.2, §8.6, §13.3). Pool tenant
-- (store.WithTenantTx / WithTenantJobTx của tenant trong path): RLS chỉ cho thấy hàng của chính tenant, tenant_id còn
-- được lọc tường minh ở mọi truy vấn (§8.8 lớp 2–4). Quyền cột UPDATE của 0025.

-- name: LockTenantSettings :one
-- Khóa hàng tenant (FOR UPDATE — quyền UPDATE (settings…) của 0025) trước khi đọc-sửa-ghi tài liệu thiết lập.
SELECT id, slug, name, status, settings, version FROM tenants
WHERE id = sqlc.arg(id)
FOR UPDATE;

-- name: GetTenantSettingsRow :one
SELECT id, slug, name, status, settings, version FROM tenants
WHERE id = sqlc.arg(id);

-- name: UpdateTenantSettingsDoc :one
UPDATE tenants
SET settings = sqlc.arg(settings), updated_at = sqlc.arg(now)::timestamptz, version = version + 1
WHERE id = sqlc.arg(id)
RETURNING id, slug, name, status, settings, version;

-- name: TenantHasHeadscaleUsers :one
-- ID-08: identity_mode bất biến khi tenant đã có Headscale user đầu tiên — một membership đã gắn Headscale user, hoặc
-- một thiết bị bất kỳ trong sổ (kể cả đã gỡ).
SELECT EXISTS (SELECT 1 FROM tenant_memberships m WHERE m.tenant_id = sqlc.arg(tenant_id) AND m.headscale_user_id IS NOT NULL)
    OR EXISTS (SELECT 1 FROM device_inventory_cache d WHERE d.tenant_id = sqlc.arg(tenant_id)) AS has_users;

-- name: ListTenantGroupIDs :many
-- policy.sensitive_groups chỉ nhận group của chính tenant (bảng groups — 0021).
SELECT id FROM groups
WHERE tenant_id = sqlc.arg(tenant_id) AND id = ANY(sqlc.arg(ids)::uuid[]);

-- name: GetTenantActiveIdP :one
-- GET /tenants/{t}/identity-provider: hàng active của tenant (partial UNIQUE(tenant_id) WHERE status='active').
SELECT * FROM identity_providers
WHERE tenant_id = sqlc.arg(tenant_id) AND scope = 'tenant' AND status = 'active';

-- name: LockTenantActiveIdP :one
SELECT * FROM identity_providers
WHERE tenant_id = sqlc.arg(tenant_id) AND scope = 'tenant' AND status = 'active'
FOR UPDATE;

-- name: LockTenantIdP :one
-- Thực thi thay đổi do nền tảng khởi xướng đã được duyệt: đúng hàng IdP của tenant đó.
SELECT * FROM identity_providers
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id)
FOR UPDATE;
