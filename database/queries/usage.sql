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
-- quota.max_tenants = số tenant tối đa đang chiếm chỗ (0012): không tính tenant `deleted` (đã deprovision) và `failed`
-- (provisioning đã rollback — không còn instance; P3-T09, ghi chú P3-T07 mục 7). Tenant `failed` quay lại `provisioning`
-- chỉ qua /retry (orchestrator.Control), lần đó kiểm lại trần dưới cùng khóa hàng (TenantCreationTx).
SELECT count(*) FROM tenants
WHERE status NOT IN ('deleted', 'failed');

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

-- name: CountOpenEnrollmentRequests :one
-- Yêu cầu enrollment chưa kết thúc của tenant (§7.4 bước 3: quota thiết bị = sổ thiết bị CỘNG yêu cầu còn có thể sinh
-- thiết bị) — đếm dưới khóa hàng subscription của người gọi (LockTenantSubscriptionLimits).
SELECT count(*) FROM enrollment_requests
WHERE tenant_id = sqlc.arg(tenant_id)
  AND status IN ('requested', 'pending_approval', 'approved', 'awaiting_device', 'claimed', 'registered',
                 'credential_issued');

-- name: CountTenantTaggedDevices :one
-- PlanLimits.max_tagged_devices (P4-T06): thiết bị gắn tag đang có trong sổ của instance chưa removed — tag và chủ sở
-- hữu loại trừ nhau (HS-10, PL-09) nên tags khác rỗng ⇔ tagged node. Đếm dưới khóa hàng subscription của người gọi.
SELECT count(*) FROM device_inventory_cache d
JOIN tenant_instances i ON i.tenant_id = d.tenant_id AND i.id = d.instance_id
WHERE d.tenant_id = sqlc.arg(tenant_id) AND d.removed_at IS NULL AND i.status <> 'removed'
  AND cardinality(d.tags) > 0;

-- name: CountOpenTaggedEnrollmentRequests :one
-- Yêu cầu enrollment chưa kết thúc mang tag (pre-auth key gắn tag — §7.4 phương thức B): còn có thể sinh một tagged
-- node, tính vào max_tagged_devices như CountOpenEnrollmentRequests tính vào max_devices.
SELECT count(*) FROM enrollment_requests
WHERE tenant_id = sqlc.arg(tenant_id) AND cardinality(requested_tags) > 0
  AND status IN ('requested', 'pending_approval', 'approved', 'awaiting_device', 'claimed', 'registered',
                 'credential_issued');

-- name: CountLiveEnrollmentCredentials :one
-- Credential enrollment còn hạn (PlanLimits.max_live_enrollment_credentials): mã/lệnh web-auth và pre-auth key đã phát
-- chưa dùng, cộng key reusable đã dùng nhưng còn hạn, cộng yêu cầu đang phát (requested — pre-auth key được tạo ở
-- Headscale SAU khi transaction quota commit: chưa có hạn nhưng sắp là một credential sống; dở dang quá 15 phút thì
-- enrollment.reconcile chuyển failed). /start đang phát key giữ khóa tenant `enrollment` tới khi ghi xong — lần tạo yêu
-- cầu chờ khóa đó trước khi đếm.
SELECT count(*) FROM enrollment_requests
WHERE tenant_id = sqlc.arg(tenant_id)
  AND (status = 'requested'
       OR (credential_expires_at > now()
           AND (status IN ('awaiting_device', 'claimed', 'credential_issued') OR (status = 'consumed' AND reusable))));
