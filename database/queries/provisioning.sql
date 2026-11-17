-- Truy vấn của state machine tenant.provision (P3-T05, §11.3) và của `POST /platform/tenants` (bước 1–2 ở API). Pool
-- platform trừ khi ghi khác; điều kiện tenant_id tường minh là lớp thứ hai sau RLS. Không truy vấn nào đọc hay ghi secret:
-- chỉ reference mgsec:// và prefix công khai.

-- ---------------------------------------------------------------- bước 1–2 (API)

-- name: GetActivePlanByKey :one
-- Gói của yêu cầu tạo tenant (§13.3 TenantCreate.plan_key): chỉ gói đang mở bán.
SELECT * FROM subscription_plans
WHERE key = sqlc.arg(key) AND is_active;

-- name: SlugHeldByDeletedTenant :one
-- §11.3 bước 1: slug của tenant đã `deleted` bị từ chối khi còn object của instance cũ trong registry — instance chưa
-- removed (thư mục, network, container), backup chưa purge, IdP chưa vô hiệu (issuer). Hostname của instance chưa
-- removed còn được placement kiểm lại dưới khóa (ErrHostnameInUse).
SELECT EXISTS (
    SELECT 1 FROM tenants t
    WHERE t.slug = sqlc.arg(slug) AND t.status = 'deleted'
      AND (EXISTS (SELECT 1 FROM tenant_instances ti WHERE ti.tenant_id = t.id AND ti.status <> 'removed')
           OR EXISTS (SELECT 1 FROM backups b WHERE b.tenant_id = t.id AND b.status <> 'purged')
           OR EXISTS (SELECT 1 FROM identity_providers i WHERE i.tenant_id = t.id AND i.status <> 'disabled'))
)::boolean AS held;

-- name: InsertSubscription :one
-- §11.3 bước 2: subscription của tenant mới (gói đã chọn, không override).
INSERT INTO subscriptions (tenant_id, plan_id, status)
VALUES (sqlc.arg(tenant_id), sqlc.arg(plan_id), 'active')
RETURNING *;

-- ---------------------------------------------------------------- state machine (worker)

-- name: GetProvisionTenant :one
-- Tenant của job + hạn mức gói hiệu lực (limits ⊕ overrides của subscription còn hiệu lực; NULL khi không có).
SELECT sqlc.embed(t), p.key AS plan_key, p.limits AS plan_limits, s.overrides AS plan_overrides
FROM tenants t
LEFT JOIN subscriptions s ON s.tenant_id = t.id AND s.status IN ('trialing', 'active', 'past_due')
LEFT JOIN subscription_plans p ON p.id = s.plan_id
WHERE t.id = sqlc.arg(id);

-- name: GetProvisionInstance :one
-- Instance mà placement.allocate đã cấp (id lấy từ created_resources của bước 3) + điểm vào công khai của host.
SELECT sqlc.embed(ti), h.name AS host_name, h.public_entry AS host_public_entry
FROM tenant_instances ti
JOIN hosts h ON h.id = ti.host_id
WHERE ti.id = sqlc.arg(id) AND ti.tenant_id = sqlc.arg(tenant_id);

-- name: SetInstanceNoiseFingerprint :exec
-- Bước 11: fingerprint Noise key (khóa công khai X25519, 64 hex — do container trợ giúp của Agent tính, P3-T03).
UPDATE tenant_instances
SET noise_key_fingerprint = sqlc.arg(fingerprint)::text, updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND tenant_id = sqlc.arg(tenant_id);

-- name: GetInstanceConfigVersionBySHA :one
-- Bước 8 idempotent: version cấu hình đã ghi cho đúng nội dung này.
SELECT * FROM instance_config_versions
WHERE tenant_id = sqlc.arg(tenant_id) AND instance_id = sqlc.arg(instance_id) AND config_sha256 = sqlc.arg(config_sha256)::text
ORDER BY version DESC
LIMIT 1;

-- name: InsertInstanceConfigVersion :one
-- Bước 8: version cấu hình đã render (Agent render từ tham số có kiểu; rendered_config là bản mô tả không secret — nội
-- dung thật nằm trên host, đối chiếu bằng config_sha256).
INSERT INTO instance_config_versions (tenant_id, instance_id, version, template_version, params, rendered_config,
                                      config_sha256, status, created_by)
VALUES (sqlc.arg(tenant_id), sqlc.arg(instance_id),
        (SELECT COALESCE(max(v.version), 0) + 1 FROM instance_config_versions v WHERE v.instance_id = sqlc.arg(instance_id)),
        sqlc.arg(template_version), sqlc.arg(params), sqlc.arg(rendered_config), sqlc.arg(config_sha256)::text,
        'applied', NULL)
RETURNING *;

-- name: SetInstanceConfigVersion :exec
-- Bước 8: version cấu hình hiện hành + derp_region_id đã render (placement để NULL — mỗi tailnet có DERP map riêng).
UPDATE tenant_instances
SET config_version_id = sqlc.arg(config_version_id)::uuid,
    derp_region_id = COALESCE(sqlc.narg(derp_region_id)::integer, derp_region_id), updated_at = now(),
    version = version + 1
WHERE id = sqlc.arg(id) AND tenant_id = sqlc.arg(tenant_id);

-- name: InsertProvisionIdP :one
-- Bước 6: IdP của tenant ở trạng thái pending (bước 16 chuyển active). id do API cấp trước (redirect URI chứa id).
INSERT INTO identity_providers (id, scope, tenant_id, issuer, client_id, client_secret_ref, required_claims,
                                allowed_email_domains, driver, driver_ref, status)
VALUES (sqlc.arg(id), 'tenant', sqlc.arg(tenant_id), sqlc.arg(issuer), sqlc.arg(client_id), sqlc.narg(client_secret_ref),
        sqlc.arg(required_claims), sqlc.arg(allowed_email_domains)::text[], sqlc.arg(driver), sqlc.narg(driver_ref),
        'pending')
RETURNING *;

-- name: UpdateProvisionIdP :one
-- Bước 6 chạy lại: driver_ref / client secret mới nhất (issuer, client_id, driver bất biến).
UPDATE identity_providers
SET driver_ref = sqlc.narg(driver_ref), client_secret_ref = sqlc.narg(client_secret_ref), updated_at = now(),
    version = version + 1
WHERE id = sqlc.arg(id) AND tenant_id = sqlc.arg(tenant_id)
RETURNING *;

-- name: TransitionIdentityProviderStatus :one
-- pending → active (bước 16), → disabled (compensation bước 6): có điều kiện theo trạng thái hiện tại.
UPDATE identity_providers
SET status = sqlc.arg(status)::text, updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND tenant_id = sqlc.arg(tenant_id) AND status = sqlc.arg(from_status)::text
RETURNING *;

-- name: SetTenantSettings :exec
-- Bước 16: tenants.settings (TenantSettings — §13.3) của yêu cầu tạo.
UPDATE tenants
SET settings = sqlc.arg(settings), updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND status = 'provisioning';

-- name: UpsertEmbeddedRelayRegion :one
-- Bước 17: region DERP nhúng của tenant (kind embedded ⇒ verify in_process — CHECK của 0010).
INSERT INTO relay_regions (tenant_id, code, name, kind, derp_region_id, hostname, ipv4, stun_port, derp_port, verify_mode,
                           host_id, status)
VALUES (sqlc.arg(tenant_id), sqlc.arg(code), sqlc.arg(name), 'embedded', sqlc.arg(derp_region_id), sqlc.arg(hostname),
        sqlc.narg(ipv4)::inet, sqlc.narg(stun_port), 443, 'in_process', sqlc.arg(host_id), 'active')
ON CONFLICT (tenant_id, code) DO UPDATE
SET hostname = EXCLUDED.hostname, ipv4 = EXCLUDED.ipv4, stun_port = EXCLUDED.stun_port, status = 'active',
    updated_at = now(), version = relay_regions.version + 1
RETURNING *;

-- name: UpsertRelayAssignment :one
INSERT INTO relay_assignments (tenant_id, instance_id, relay_region_id, priority, status)
VALUES (sqlc.arg(tenant_id), sqlc.arg(instance_id), sqlc.arg(relay_region_id), 0, 'active')
ON CONFLICT (instance_id, relay_region_id) DO UPDATE
SET status = 'active', updated_at = now()
RETURNING *;

-- name: GetTenantRelayRegionByCode :one
SELECT * FROM relay_regions
WHERE tenant_id = sqlc.arg(tenant_id)::uuid AND code = sqlc.arg(code);

-- name: DeleteRelayAssignment :execrows
-- Compensation bước 17: xóa hàng do job tạo.
DELETE FROM relay_assignments
WHERE tenant_id = sqlc.arg(tenant_id) AND instance_id = sqlc.arg(instance_id) AND relay_region_id = sqlc.arg(relay_region_id);

-- name: DeleteRelayRegion :execrows
DELETE FROM relay_regions r
WHERE r.tenant_id = sqlc.arg(tenant_id)::uuid AND r.id = sqlc.arg(id)::uuid AND r.kind = 'embedded'
  AND NOT EXISTS (SELECT 1 FROM relay_assignments a WHERE a.relay_region_id = r.id);
