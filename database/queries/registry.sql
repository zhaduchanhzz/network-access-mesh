-- name: CreateTenant :one
-- Pool platform.
INSERT INTO tenants (slug, name, status, deployment_region, settings)
VALUES (sqlc.arg(slug), sqlc.arg(name), sqlc.arg(status), sqlc.narg(deployment_region), sqlc.arg(settings))
RETURNING *;

-- name: GetTenant :one
SELECT * FROM tenants
WHERE id = sqlc.arg(id);

-- name: ListTenants :many
-- Thứ tự ổn định (created_at, id) cho phân trang (§13.1).
SELECT * FROM tenants
ORDER BY created_at, id
LIMIT sqlc.arg(row_limit);

-- name: UpdateTenantStatus :one
-- Khóa lạc quan: trả 0 hàng (pgx.ErrNoRows) khi version lệch.
UPDATE tenants
SET status = sqlc.arg(status), updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND version = sqlc.arg(version)
RETURNING *;

-- name: CreateHost :one
-- Pool platform (bảng P). capacity và public_entry lấy DEFAULT của bảng (0014: max_instances 100; điểm vào công khai
-- khai báo sau — placement không chọn host chưa có ipv4).
INSERT INTO hosts (name, region, run_uid_range, tenant_net_pool)
VALUES (sqlc.arg(name), sqlc.arg(region), sqlc.arg(run_uid_range), sqlc.arg(tenant_net_pool))
RETURNING *;

-- name: GetHost :one
SELECT * FROM hosts
WHERE id = sqlc.arg(id);

-- name: CreateTenantInstance :one
-- Pool platform. id do caller cấp (adopt-instance lấy từ meta/instance.json — P2-T11).
INSERT INTO tenant_instances (id, tenant_id, host_id, status, headscale_version, image_digest, control_hostname,
                              server_url, base_domain, internal_address, stun_port, derp_region_id, run_uid, net_cidr,
                              data_path)
VALUES (sqlc.arg(id), sqlc.arg(tenant_id), sqlc.arg(host_id), sqlc.arg(status), sqlc.arg(headscale_version),
        sqlc.arg(image_digest), sqlc.arg(control_hostname), sqlc.arg(server_url), sqlc.arg(base_domain),
        sqlc.arg(internal_address), sqlc.narg(stun_port), sqlc.narg(derp_region_id), sqlc.arg(run_uid),
        sqlc.arg(net_cidr), sqlc.arg(data_path))
RETURNING *;

-- name: GetTenantInstance :one
SELECT * FROM tenant_instances
WHERE id = sqlc.arg(id);

-- name: GetLiveInstanceForTenant :one
-- Registry.ForTenant (§5.4): instance chưa removed của tenant (MVP: tối đa một).
SELECT * FROM tenant_instances
WHERE tenant_id = sqlc.arg(tenant_id) AND status <> 'removed';

-- name: GetSystemSetting :one
-- Pool platform (bảng P).
SELECT * FROM system_settings
WHERE key = sqlc.arg(key);

-- name: UpsertSystemSetting :one
INSERT INTO system_settings (key, value, updated_by)
VALUES (sqlc.arg(key), sqlc.arg(value), sqlc.narg(updated_by))
ON CONFLICT (key) DO UPDATE
SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now(), version = system_settings.version + 1
RETURNING *;
