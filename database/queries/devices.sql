-- Truy vấn của module devices (P2-T13): sổ thiết bị (device_inventory_cache), trạng thái đồng bộ theo instance
-- (device_inventory_sync_state), thu hồi hai pha. Mọi truy vấn chạy trên pool tenant (bảng T) trừ khi ghi khác;
-- điều kiện tenant_id tường minh là lớp thứ hai sau RLS.

-- name: DevicesSnapshotTime :one
-- Đồng hồ DB ngay trước ListNodes: mốc của snapshot (so với device_inventory_sync_state.synced_at).
SELECT clock_timestamp()::timestamptz AS snapshot_at;

-- name: GetDevicesNodeExpiry :one
-- Nguồn giới hạn node_expiry của quy tắc kẹp hạn (§7.4, §13.4): TenantSettings.node_expiry (tenants.settings), rồi
-- node.expiry của cấu hình đã render của instance (instance_config_versions.params qua config_version_id — §14.5).
SELECT COALESCE(t.settings ->> 'node_expiry', '')::text AS tenant_node_expiry,
       COALESCE(c.params ->> 'node_expiry', '')::text  AS instance_node_expiry
FROM tenants t
JOIN tenant_instances i ON i.tenant_id = t.id AND i.id = sqlc.arg(instance_id)
LEFT JOIN instance_config_versions c ON c.tenant_id = i.tenant_id AND c.id = i.config_version_id
WHERE t.id = sqlc.arg(tenant_id);

-- name: ListDeviceOwnerNames :many
-- Ánh xạ Headscale user (mg-<membership_uuid>) → membership của tenant (owner của node thuộc user).
SELECT id, headscale_username FROM tenant_memberships
WHERE tenant_id = sqlc.arg(tenant_id);

-- name: EnsureDeviceSyncState :exec
INSERT INTO device_inventory_sync_state (instance_id, tenant_id)
VALUES (sqlc.arg(instance_id), sqlc.arg(tenant_id))
ON CONFLICT (instance_id) DO NOTHING;

-- name: LockDeviceSyncState :one
-- Tuần tự hóa các lần áp dụng sync của một instance; caller bỏ qua snapshot không mới hơn synced_at.
SELECT * FROM device_inventory_sync_state
WHERE tenant_id = sqlc.arg(tenant_id) AND instance_id = sqlc.arg(instance_id)
FOR UPDATE;

-- name: RecordDeviceSync :exec
UPDATE device_inventory_sync_state
SET generation = sqlc.arg(generation), synced_at = sqlc.arg(synced_at), node_count = sqlc.arg(node_count)
WHERE tenant_id = sqlc.arg(tenant_id) AND instance_id = sqlc.arg(instance_id);

-- name: GetDeviceSyncState :one
SELECT * FROM device_inventory_sync_state
WHERE tenant_id = sqlc.arg(tenant_id) AND instance_id = sqlc.arg(instance_id);

-- name: LockLiveDevicesOfInstance :many
SELECT * FROM device_inventory_cache
WHERE tenant_id = sqlc.arg(tenant_id) AND instance_id = sqlc.arg(instance_id) AND removed_at IS NULL
ORDER BY headscale_node_id
FOR UPDATE;

-- name: LatestDeviceOfNode :one
-- Hàng gần nhất của đúng node (instance, node id, machine key) — kể cả đã removed: snapshot cũ hơn lần gỡ thì không
-- dựng lại thiết bị đã gỡ.
SELECT * FROM device_inventory_cache
WHERE tenant_id = sqlc.arg(tenant_id) AND instance_id = sqlc.arg(instance_id)
  AND headscale_node_id = sqlc.arg(headscale_node_id) AND machine_key = sqlc.arg(machine_key)
ORDER BY first_seen_at DESC, id DESC
LIMIT 1;

-- name: InsertSyncedDevice :one
INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, node_key, name, given_name,
                                    ip_addresses, headscale_user_id, owner_membership_id, tags, register_method, online,
                                    last_seen, expiry, approved_routes, available_routes, subnet_routes, hs_created_at,
                                    first_seen_at, last_synced_at, sync_generation)
VALUES (sqlc.arg(tenant_id), sqlc.arg(instance_id), sqlc.arg(headscale_node_id), sqlc.arg(machine_key),
        sqlc.narg(node_key), sqlc.narg(name), sqlc.narg(given_name), sqlc.arg(ip_addresses), sqlc.narg(headscale_user_id),
        sqlc.narg(owner_membership_id), sqlc.arg(tags), sqlc.narg(register_method), sqlc.arg(online), sqlc.narg(last_seen),
        sqlc.narg(expiry), sqlc.arg(approved_routes), sqlc.arg(available_routes), sqlc.arg(subnet_routes),
        sqlc.narg(hs_created_at), sqlc.arg(synced_at), sqlc.arg(synced_at), sqlc.arg(sync_generation))
RETURNING *;

-- name: UpdateSyncedDevice :exec
-- Cột cache từ ListNodes (§13.4 "Đọc node"); owner chỉ đổi khi set_owner (node thuộc user — owner của node thuộc tag
-- là dữ liệu authoritative của nền tảng, giữ nguyên).
UPDATE device_inventory_cache
SET node_key            = sqlc.narg(node_key),
    name                = sqlc.narg(name),
    given_name          = sqlc.narg(given_name),
    ip_addresses        = sqlc.arg(ip_addresses),
    headscale_user_id   = sqlc.narg(headscale_user_id),
    owner_membership_id = CASE WHEN sqlc.arg(set_owner)::boolean THEN sqlc.narg(owner_membership_id)::uuid
                               ELSE owner_membership_id END,
    tags                = sqlc.arg(tags),
    register_method     = sqlc.narg(register_method),
    online              = sqlc.arg(online),
    last_seen           = sqlc.narg(last_seen),
    expiry              = sqlc.narg(expiry),
    approved_routes     = sqlc.arg(approved_routes),
    available_routes    = sqlc.arg(available_routes),
    subnet_routes       = sqlc.arg(subnet_routes),
    hs_created_at       = sqlc.narg(hs_created_at),
    last_synced_at      = sqlc.arg(synced_at),
    sync_generation     = sqlc.arg(sync_generation)
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: MarkDeviceRemoved :exec
-- Node không còn trong ListNodes, hoặc node id đã được cấp lại cho machine key khác (§6.3).
UPDATE device_inventory_cache
SET removed_at = sqlc.arg(removed_at), online = false, last_synced_at = sqlc.arg(removed_at),
    sync_generation = sqlc.arg(sync_generation)
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND removed_at IS NULL;

-- name: SetDeviceExpiry :exec
-- Kết quả đọc lại sau ExpireNode của quy tắc kẹp hạn.
UPDATE device_inventory_cache SET expiry = sqlc.narg(expiry)
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND removed_at IS NULL;

-- name: ListDevicesPage :many
-- GET /tenants/{t}/devices: thiết bị còn sống, thứ tự ổn định (first_seen_at, id) (§13.1). own_membership: quyền
-- phạm vi own (End User) — chỉ thiết bị của chính membership đó và không có tag (§8.4 bất biến 3b).
SELECT sqlc.embed(d), COALESCE(i.display_name, i.email::text, '')::text AS owner_display
FROM device_inventory_cache d
LEFT JOIN tenant_memberships m ON m.tenant_id = d.tenant_id AND m.id = d.owner_membership_id
LEFT JOIN identities i ON i.tenant_id = m.tenant_id AND i.id = m.identity_id
WHERE d.tenant_id = sqlc.arg(tenant_id) AND d.removed_at IS NULL
  AND (sqlc.narg(own_membership)::uuid IS NULL
       OR (d.owner_membership_id = sqlc.narg(own_membership)::uuid AND cardinality(d.tags) = 0))
  AND (sqlc.narg(owner)::uuid IS NULL OR d.owner_membership_id = sqlc.narg(owner)::uuid)
  AND (sqlc.narg(online)::boolean IS NULL OR d.online = sqlc.narg(online)::boolean)
  AND (sqlc.narg(tag)::text IS NULL OR sqlc.narg(tag)::text = ANY (d.tags))
  AND (sqlc.narg(search)::text IS NULL
       OR strpos(lower(COALESCE(d.given_name, '') || ' ' || COALESCE(d.name, '')), lower(sqlc.narg(search)::text)) > 0)
  AND (sqlc.narg(after_seen)::timestamptz IS NULL
       OR (d.first_seen_at, d.id) > (sqlc.narg(after_seen)::timestamptz, sqlc.narg(after_id)::uuid))
ORDER BY d.first_seen_at, d.id
LIMIT sqlc.arg(row_limit);

-- name: GetLiveDevice :one
SELECT sqlc.embed(d), COALESCE(i.display_name, i.email::text, '')::text AS owner_display
FROM device_inventory_cache d
LEFT JOIN tenant_memberships m ON m.tenant_id = d.tenant_id AND m.id = d.owner_membership_id
LEFT JOIN identities i ON i.tenant_id = m.tenant_id AND i.id = m.identity_id
WHERE d.tenant_id = sqlc.arg(tenant_id) AND d.id = sqlc.arg(id) AND d.removed_at IS NULL;

-- name: LockLiveDevice :one
SELECT * FROM device_inventory_cache
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND removed_at IS NULL
FOR UPDATE;

-- name: LockDevice :one
-- Job device.revoke: hàng của thiết bị kể cả đã removed (sync có thể đã gỡ node trước khi job chạy).
SELECT * FROM device_inventory_cache
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id)
FOR UPDATE;

-- name: SetDeviceGivenName :exec
UPDATE device_inventory_cache SET given_name = sqlc.arg(given_name)
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND removed_at IS NULL;

-- name: SetDeviceTags :exec
-- PUT /devices/{id}/tags (P4-T15): tập tag Headscale trả về sau SetTags. Node có tag không còn thuộc user nào (PL-09,
-- Headscale ≥ 0.28) — chủ sở hữu trong sổ bị gỡ như cách inventory.sync chuẩn hóa (normalise).
UPDATE device_inventory_cache SET tags = sqlc.arg(tags), owner_membership_id = NULL
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND removed_at IS NULL;

-- name: StartDeviceRevocation :one
-- Pha 1 của thu hồi hai pha (T-17): pending cho tới khi job đọc lại xác nhận. Thiết bị đang pending ⇒ 0 hàng.
UPDATE device_inventory_cache
SET revocation_state = 'pending', revocation_kind = sqlc.arg(kind), revocation_requested_at = now(),
    revocation_verified_at = NULL, revocation_job_id = NULL
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND removed_at IS NULL AND revocation_state <> 'pending'
RETURNING *;

-- name: SetDeviceRevocationJob :exec
UPDATE device_inventory_cache SET revocation_job_id = sqlc.arg(job_id)
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND revocation_state = 'pending';

-- name: SettleDeviceRevocation :one
-- Pha 2: applied (đọc lại đã khớp) hoặc failed (Headscale từ chối, hết lượt) — chỉ cho đúng job đang chở yêu cầu và
-- chỉ một lần (0 hàng khi đã chốt hoặc đã có yêu cầu mới).
UPDATE device_inventory_cache
SET revocation_state       = sqlc.arg(state),
    revocation_verified_at = CASE WHEN sqlc.arg(state)::text = 'applied' THEN now() ELSE NULL END,
    expiry                 = CASE WHEN sqlc.arg(set_expiry)::boolean THEN sqlc.narg(expiry)::timestamptz ELSE expiry END,
    online                 = CASE WHEN sqlc.arg(remove)::boolean THEN false ELSE online END,
    removed_at             = CASE WHEN sqlc.arg(remove)::boolean THEN COALESCE(removed_at, now()) ELSE removed_at END
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND revocation_state = 'pending'
  AND revocation_job_id = sqlc.arg(job_id)
RETURNING *;

-- name: ListOrphanedRevocations :many
-- Thu hồi còn pending mà job đã kết thúc không thành công (hết lượt, timeout, bị reaper thu hồi, hủy) hoặc job đã bị
-- retention xóa: chốt failed (lưới an toàn của handler và của Alerter).
SELECT d.id, d.revocation_job_id, d.revocation_kind,
       COALESCE(j.status, '')::text           AS job_status,
       COALESCE(j.error ->> 'code', '')::text AS job_error_code,
       COALESCE(j.input, '{}'::jsonb)         AS job_input
FROM device_inventory_cache d
LEFT JOIN provisioning_jobs j ON j.tenant_id = d.tenant_id AND j.id = d.revocation_job_id
WHERE d.tenant_id = sqlc.arg(tenant_id) AND d.revocation_state = 'pending'
  AND (j.id IS NULL OR j.status IN ('failed', 'cancelled', 'rolled_back'))
  AND (sqlc.narg(job_id)::uuid IS NULL OR d.revocation_job_id = sqlc.narg(job_id)::uuid)
ORDER BY d.id;

-- name: FailOrphanedRevocation :one
UPDATE device_inventory_cache SET revocation_state = 'failed', revocation_verified_at = NULL
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND revocation_state = 'pending'
  AND revocation_job_id IS NOT DISTINCT FROM sqlc.narg(job_id)::uuid
RETURNING id;

-- name: CountDevices :one
-- Tổng số thiết bị còn sống và số đang online theo góc nhìn của control plane (dashboard — P2-T13a).
SELECT count(*)::bigint AS total, count(*) FILTER (WHERE online)::bigint AS online
FROM device_inventory_cache
WHERE tenant_id = sqlc.arg(tenant_id) AND removed_at IS NULL;

-- name: ListRunningInstances :many
-- Pool platform: instance cần inventory.sync theo lịch (§13.5) — instance đang chạy của tenant còn phục vụ (tenant
-- đang deprovision không còn được đồng bộ — P3-T09).
SELECT ti.id, ti.tenant_id FROM tenant_instances ti
JOIN tenants t ON t.id = ti.tenant_id
WHERE ti.status = 'running' AND t.status IN ('provisioning', 'active', 'suspended')
ORDER BY ti.id;

-- name: ListExpiringDevices :many
-- Thông báo "sắp hết hạn" (P3-T05b): thiết bị còn sống, không đang/đã thu hồi, khóa node hết hạn trong (now, before].
SELECT id, owner_membership_id, COALESCE(given_name, name, '')::text AS display_name, expiry
FROM device_inventory_cache
WHERE tenant_id = sqlc.arg(tenant_id) AND instance_id = sqlc.arg(instance_id) AND removed_at IS NULL
  AND revocation_state = 'none' AND expiry > now() AND expiry <= sqlc.arg(before)::timestamptz
ORDER BY expiry, id
LIMIT 200;
