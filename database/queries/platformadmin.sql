-- P4-T03a — quản trị nền tảng (§8.2, §8.4 bất biến 3, §8.5): platform users, system settings, identity providers,
-- plans, sửa tenant. Mọi truy vấn ở đây chạy trên pool platform (store.WithPlatformTx), trừ các truy vấn ghi chú
-- "pool tenant" (thực thi thay đổi IdP của tenant đã duyệt — audit của tenant cùng transaction, quyền cột của 0025).

-- ---------------------------------------------------------------- platform users

-- name: ListPlatformUsersPage :many
-- GET /platform/users: platform user + identity + khóa role, thứ tự ổn định (created_at, id), con trỏ là cặp giá trị
-- của phần tử cuối trang trước.
SELECT pu.id, pu.identity_id, pu.status, pu.created_at, pu.updated_at, pu.version, r.key AS role_key,
       i.subject, i.display_name, i.email, i.status AS identity_status, i.last_login_at
FROM platform_users pu
JOIN identities i ON i.id = pu.identity_id AND i.scope = pu.identity_scope
JOIN roles r ON r.id = pu.role_id AND r.scope = pu.role_scope
WHERE (sqlc.narg(status)::text IS NULL OR pu.status = sqlc.narg(status)::text)
  AND (sqlc.narg(role_key)::text IS NULL OR r.key = sqlc.narg(role_key)::text)
  AND (sqlc.narg(after_created_at)::timestamptz IS NULL
       OR (pu.created_at, pu.id) > (sqlc.narg(after_created_at)::timestamptz, sqlc.narg(after_id)::uuid))
ORDER BY pu.created_at, pu.id
LIMIT sqlc.arg(row_limit);

-- name: GetPlatformUserView :one
-- GET /platform/users/{id} và phép đọc lại sau mỗi lần ghi.
SELECT pu.id, pu.identity_id, pu.status, pu.created_at, pu.updated_at, pu.version, r.key AS role_key,
       i.subject, i.display_name, i.email, i.status AS identity_status, i.last_login_at
FROM platform_users pu
JOIN identities i ON i.id = pu.identity_id AND i.scope = pu.identity_scope
JOIN roles r ON r.id = pu.role_id AND r.scope = pu.role_scope
WHERE pu.id = sqlc.arg(id);

-- name: LockPlatformUserRole :one
-- Khóa hàng platform user (FOR UPDATE — quyền UPDATE cột của 0002) và trả role hiện tại.
SELECT pu.id, pu.identity_id, pu.status, pu.version, r.key AS role_key
FROM platform_users pu
JOIN roles r ON r.id = pu.role_id AND r.scope = pu.role_scope
WHERE pu.id = sqlc.arg(id)
FOR UPDATE OF pu;

-- name: UpdatePlatformUser :one
-- role_scope cố định 'platform' + FK ghép (role_id, role_scope) → roles: role tenant/support bị DB từ chối.
UPDATE platform_users
SET role_id = sqlc.arg(role_id), status = sqlc.arg(status), updated_at = sqlc.arg(now)::timestamptz, version = version + 1
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: InsertPlatformUserCreatedBy :one
-- POST /platform/users (§8.2): identity của IdP platform tạo sẵn (InsertSeededIdentity) + platform user; created_by =
-- identity của người gọi (tham chiếu, không FK).
INSERT INTO platform_users (identity_id, role_id, created_by)
VALUES (sqlc.arg(identity_id), sqlc.arg(role_id), sqlc.arg(created_by))
RETURNING *;

-- ---------------------------------------------------------------- system settings

-- name: ListServedSystemSettings :many
-- GET /platform/settings: hàng của các khóa được phục vụ (tập khóa đóng của internal/config).
SELECT * FROM system_settings
WHERE key = ANY(sqlc.arg(keys)::text[])
ORDER BY key;

-- name: LockSystemSetting :one
SELECT * FROM system_settings
WHERE key = sqlc.arg(key)
FOR UPDATE;

-- name: InsertSystemSettingIfAbsent :one
-- PUT của một khóa chưa có hàng (ETag "0"): một lần ghi đồng thời khác đã tạo hàng ⇒ không có hàng trả về (412).
INSERT INTO system_settings (key, value, updated_by, updated_at)
VALUES (sqlc.arg(key), sqlc.arg(value), sqlc.narg(updated_by), sqlc.arg(now)::timestamptz)
ON CONFLICT (key) DO NOTHING
RETURNING *;

-- name: UpdateSystemSettingValue :one
UPDATE system_settings
SET value = sqlc.arg(value), updated_by = sqlc.narg(updated_by), updated_at = sqlc.arg(now)::timestamptz,
    version = version + 1
WHERE key = sqlc.arg(key)
RETURNING *;

-- ---------------------------------------------------------------- identity providers

-- name: ListIdentityProvidersPage :many
-- GET /platform/identity-providers: mọi đăng ký IdP (platform và tenant), thứ tự (created_at, id).
SELECT * FROM identity_providers
WHERE (sqlc.narg(scope)::text IS NULL OR scope = sqlc.narg(scope)::text)
  AND (sqlc.narg(after_created_at)::timestamptz IS NULL
       OR (created_at, id) > (sqlc.narg(after_created_at)::timestamptz, sqlc.narg(after_id)::uuid))
ORDER BY created_at, id
LIMIT sqlc.arg(row_limit);

-- name: LockIdentityProvider :one
-- Pool platform hoặc tenant (RLS: pool tenant chỉ thấy hàng của chính tenant): khóa hàng IdP trước khi sửa.
SELECT * FROM identity_providers
WHERE id = sqlc.arg(id)
FOR UPDATE;

-- name: UpdateIdentityProviderClaims :one
-- §8.2 MVP: chỉ ràng buộc claim/domain (+ reference của client secret); issuer, client_id, driver, scope, tenant_id
-- không có trong lệnh (và không được cấp quyền UPDATE). Pool platform (hàng platform — 0002) hoặc pool tenant (hàng
-- của chính tenant — 0025); version lạc quan: hàng đã đổi ⇒ không có hàng trả về.
UPDATE identity_providers
SET required_claims = sqlc.arg(required_claims), allowed_email_domains = sqlc.arg(allowed_email_domains)::text[],
    claim_mapping = sqlc.arg(claim_mapping), client_secret_ref = sqlc.narg(client_secret_ref),
    updated_at = sqlc.arg(now)::timestamptz, version = version + 1
WHERE id = sqlc.arg(id) AND version = sqlc.arg(version)
RETURNING *;

-- ---------------------------------------------------------------- plans

-- name: ListPlansWithUsage :many
-- GET /platform/plans: mọi gói (cả gói đóng) + số subscription còn hiệu lực đang dùng.
SELECT sqlc.embed(p),
       (SELECT count(*) FROM subscriptions s
        WHERE s.plan_id = p.id AND s.status IN ('trialing', 'active', 'past_due'))::bigint AS tenant_count
FROM subscription_plans p
ORDER BY p.key;

-- name: GetPlanWithUsage :one
SELECT sqlc.embed(p),
       (SELECT count(*) FROM subscriptions s
        WHERE s.plan_id = p.id AND s.status IN ('trialing', 'active', 'past_due'))::bigint AS tenant_count
FROM subscription_plans p
WHERE p.id = sqlc.arg(id);

-- name: InsertPlan :one
-- CHECK mg_plan_limits_valid(limits, false) của 0012: đủ bốn khóa quota; key UNIQUE (23505 ⇒ 409).
INSERT INTO subscription_plans (key, name, limits, is_active)
VALUES (sqlc.arg(key), sqlc.arg(name), sqlc.arg(limits), sqlc.arg(is_active))
RETURNING *;

-- name: LockPlan :one
SELECT * FROM subscription_plans
WHERE id = sqlc.arg(id)
FOR UPDATE;

-- name: UpdatePlan :one
-- key không có trong lệnh (bất biến — TenantCreate.plan_key).
UPDATE subscription_plans
SET name = sqlc.arg(name), limits = sqlc.arg(limits), is_active = sqlc.arg(is_active),
    updated_at = sqlc.arg(now)::timestamptz, version = version + 1
WHERE id = sqlc.arg(id)
RETURNING *;

-- ---------------------------------------------------------------- sửa tenant (PATCH /platform/tenants/{id})

-- name: LockTenantRow :one
SELECT * FROM tenants
WHERE id = sqlc.arg(id)
FOR UPDATE;

-- name: UpdateTenantName :one
-- Mọi PATCH tăng version của tenant (nguồn ETag), kể cả khi chỉ gói/override đổi.
UPDATE tenants
SET name = sqlc.arg(name), updated_at = sqlc.arg(now)::timestamptz, version = version + 1
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: LockLiveSubscription :one
-- Subscription còn hiệu lực của tenant (tối đa một — partial UNIQUE của 0012) + khóa gói.
SELECT s.id, s.plan_id, s.overrides, p.key AS plan_key
FROM subscriptions s
JOIN subscription_plans p ON p.id = s.plan_id
WHERE s.tenant_id = sqlc.arg(tenant_id) AND s.status IN ('trialing', 'active', 'past_due')
FOR UPDATE OF s;

-- name: UpdateSubscriptionPlan :exec
-- CHECK mg_plan_limits_valid(overrides, true) của 0012.
UPDATE subscriptions
SET plan_id = sqlc.arg(plan_id), overrides = sqlc.arg(overrides), updated_at = sqlc.arg(now)::timestamptz,
    version = version + 1
WHERE id = sqlc.arg(id) AND tenant_id = sqlc.arg(tenant_id);

-- ---------------------------------------------------------------- nhãn của Platform Console (G4b-E12)

-- name: ListTenantLabels :many
-- Slug, tên và gói (subscription còn hiệu lực — trialing/active/past_due, tối đa một: partial UNIQUE của 0012) của các
-- tenant được nhắc tới trên một trang của Platform Console (instance, job, relay region, IdP, danh sách tenant) — tra
-- theo lô thay cho UUID. Tenant không có subscription còn hiệu lực ⇒ plan_key rỗng.
SELECT t.id, t.slug::text AS slug, t.name,
       COALESCE((SELECT p.key FROM subscriptions s JOIN subscription_plans p ON p.id = s.plan_id
                 WHERE s.tenant_id = t.id AND s.status IN ('trialing', 'active', 'past_due')
                 ORDER BY s.created_at DESC LIMIT 1), '')::text AS plan_key
FROM tenants t
WHERE t.id = ANY(sqlc.arg(ids)::uuid[]);

-- name: ListHostNames :many
-- Tên host (nhãn DNS, bất biến) của các host được nhắc tới trên một trang của Platform Console (G4b-E12).
SELECT id, name FROM hosts WHERE id = ANY(sqlc.arg(ids)::uuid[]);
