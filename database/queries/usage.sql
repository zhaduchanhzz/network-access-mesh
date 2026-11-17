-- QuotaChecker tối thiểu (P3-T06a, §11.3 bước 1, §7.4 bước 3): trần số tenant toàn nền tảng (system_settings
-- quota.max_tenants — pool platform; pool tenant không đọc được bảng P) và hạn mức thiết bị theo plan (pool tenant của
-- chính tenant). Bản "Lock" khóa hàng nguồn của hạn mức tới hết transaction của người gọi, để hai lần tạo đồng thời không
-- cùng vượt trần: registry.create (bước 2) khóa hàng quota.max_tenants, enrollment khóa hàng subscription (§7.4 bước 3).

-- name: GetTenantCap :one
SELECT value FROM system_settings
WHERE key = 'quota.max_tenants';

-- name: LockTenantCap :one
-- Cần UPDATE trên ≥ 1 cột của system_settings (role platform có — 0001).
SELECT value FROM system_settings
WHERE key = 'quota.max_tenants'
FOR UPDATE;

-- name: CountLiveTenants :one
-- quota.max_tenants = số tenant chưa `deleted` tối đa (0012).
SELECT count(*) FROM tenants
WHERE status <> 'deleted';

-- name: GetTenantSubscriptionLimits :one
-- Subscription còn hiệu lực (trialing/active/past_due — tối đa một, partial UNIQUE của 0012) + limits của plan.
SELECT s.id, p.key AS plan_key, p.limits, s.overrides
FROM subscriptions s
JOIN subscription_plans p ON p.id = s.plan_id
WHERE s.tenant_id = sqlc.arg(tenant_id) AND s.status IN ('trialing', 'active', 'past_due');

-- name: LockTenantSubscriptionLimits :one
-- Như trên, khóa hàng subscription (role tenant có UPDATE (updated_at) chỉ để chạy được mệnh đề này — 0012).
SELECT s.id, p.key AS plan_key, p.limits, s.overrides
FROM subscriptions s
JOIN subscription_plans p ON p.id = s.plan_id
WHERE s.tenant_id = sqlc.arg(tenant_id) AND s.status IN ('trialing', 'active', 'past_due')
FOR UPDATE OF s;

-- name: CountTenantDevices :one
-- Thiết bị đang có trong sổ (removed_at IS NULL) của instance chưa removed của tenant — hàng của instance đã bị thay thế
-- không còn tính. tenant_id lọc ở truy vấn ngoài RLS (§8.8).
SELECT count(*) FROM device_inventory_cache d
JOIN tenant_instances i ON i.tenant_id = d.tenant_id AND i.id = d.instance_id
WHERE d.tenant_id = sqlc.arg(tenant_id) AND d.removed_at IS NULL AND i.status <> 'removed';
