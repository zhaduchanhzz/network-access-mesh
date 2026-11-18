-- Backup/restore v1 của instance tenant (P3-T11 — §17.1–§17.2, §13.5 `instance.backup` / `instance.restore`, §6.3
-- `backups` + migration backup_manifest). Hàng sổ không chứa secret: wrapped_data_key là data key ĐÃ BỌC bằng khóa backup của tenant
-- (SecretStore, key_ref), manifest là văn bản đã ký của Agent. Cột tường minh, không SELECT *.

-- ---------------------------------------------------------------- pool platform (worker, api)

-- name: GetInstanceForBackup :one
-- Registry của một instance cho job backup/restore: trạng thái instance + tenant, host, phiên bản, có job nhóm
-- lifecycle khác đang chạy (khóa chạy của tenant — §13.5 (d)) không.
SELECT ti.id, ti.tenant_id, t.slug, t.status AS tenant_status, ti.status, ti.host_id, ti.headscale_version,
       ti.api_key_secret_ref, ti.api_key_prefix
FROM tenant_instances ti
JOIN tenants t ON t.id = ti.tenant_id
WHERE ti.id = sqlc.arg(id);

-- name: ListBackupSchedule :many
-- Lịch instance.backup: instance running/stopped (không quarantined/removed — §11.4) của tenant còn phục vụ, kèm thời
-- điểm bắt đầu của lần backup gần nhất (mọi trạng thái — một lần lỗi cũng tính, job retry theo lượt của nó) và chu kỳ
-- theo plan (PlanLimits.backup_interval_minutes của subscription còn hiệu lực, override trước — §17.1 "theo plan"; 0 =
-- không có ⇒ MG_BACKUP_INTERVAL).
SELECT ti.id, ti.tenant_id,
       COALESCE((SELECT max(b.started_at) FROM backups b WHERE b.instance_id = ti.id), '1970-01-01T00:00:00Z'::timestamptz)::timestamptz AS last_started_at,
       COALESCE((SELECT COALESCE((s.overrides->>'backup_interval_minutes')::integer, (p.limits->>'backup_interval_minutes')::integer)
                 FROM subscriptions s JOIN subscription_plans p ON p.id = s.plan_id
                 WHERE s.tenant_id = ti.tenant_id AND s.status IN ('trialing', 'active', 'past_due')
                 LIMIT 1), 0)::integer AS interval_minutes
FROM tenant_instances ti
JOIN tenants t ON t.id = ti.tenant_id
WHERE ti.status IN ('running', 'stopped') AND t.status IN ('provisioning', 'active', 'suspended')
ORDER BY ti.id;

-- name: ListBackupFreshness :many
-- Độ tươi backup theo instance (P3-T16 — cảnh báo §16.3 "quá hạn lịch backup của tenant"): đúng tập instance của
-- ListBackupSchedule, kèm finished_at của bản backup thành công gần nhất (succeeded hoặc purged; epoch = chưa từng có —
-- khi đó mốc là created_at của instance) và chu kỳ theo plan (0 = không có ⇒ MG_BACKUP_INTERVAL).
SELECT ti.id, ti.tenant_id, ti.created_at,
       COALESCE((SELECT max(b.finished_at) FROM backups b
                 WHERE b.instance_id = ti.id AND b.status IN ('succeeded', 'purged')), '1970-01-01T00:00:00Z'::timestamptz)::timestamptz AS last_success_at,
       COALESCE((SELECT COALESCE((s.overrides->>'backup_interval_minutes')::integer, (p.limits->>'backup_interval_minutes')::integer)
                 FROM subscriptions s JOIN subscription_plans p ON p.id = s.plan_id
                 WHERE s.tenant_id = ti.tenant_id AND s.status IN ('trialing', 'active', 'past_due')
                 LIMIT 1), 0)::integer AS interval_minutes
FROM tenant_instances ti
JOIN tenants t ON t.id = ti.tenant_id
WHERE ti.status IN ('running', 'stopped') AND t.status IN ('provisioning', 'active', 'suspended')
ORDER BY ti.id;

-- name: ListPlatformBackupsPage :many
-- GET /platform/backups (P3-T11): mới nhất trước, thứ tự ổn định (started_at, id) giảm dần cho phân trang (§13.1).
SELECT b.id, b.tenant_id, b.instance_id, b.kind, b.status, b.storage_uri, b.size_bytes, b.sha256, b.headscale_version,
       b.started_at, b.finished_at, b.expires_at, b.verified_at, b.job_id, b.sequence, b.method, b.manifest_sha256
FROM backups b
WHERE (sqlc.narg(tenant_id)::uuid IS NULL OR b.tenant_id = sqlc.narg(tenant_id)::uuid)
  AND (sqlc.narg(instance_id)::uuid IS NULL OR b.instance_id = sqlc.narg(instance_id)::uuid)
  AND (sqlc.narg(status)::text IS NULL OR b.status = sqlc.narg(status)::text)
  AND (sqlc.narg(before_started_at)::timestamptz IS NULL
       OR (b.started_at, b.id) < (sqlc.narg(before_started_at)::timestamptz, sqlc.narg(before_id)::uuid))
ORDER BY b.started_at DESC, b.id DESC
LIMIT sqlc.arg(row_limit);

-- name: GetBackupForRestoreRequest :one
-- POST /platform/instances/{id}/restore và thực thi phê duyệt: hàng sổ mà yêu cầu restore nêu tên.
SELECT b.id, b.tenant_id, b.instance_id, b.kind, b.status, b.sequence, b.started_at, b.finished_at
FROM backups b
WHERE b.id = sqlc.arg(id);

-- ---------------------------------------------------------------- pool tenant (worker)

-- name: NextInstanceBackupSequence :one
-- Sequence của backup kế tiếp: lớn hơn mọi sequence đã cấp cho instance (kể cả hàng lỗi/purged).
SELECT COALESCE(max(sequence), 0)::bigint AS last FROM backups WHERE instance_id = sqlc.arg(instance_id);

-- name: InsertInstanceBackup :one
INSERT INTO backups (tenant_id, instance_id, kind, status, storage_uri, key_ref, headscale_version, job_id, sequence, wrapped_data_key)
VALUES (sqlc.arg(tenant_id), sqlc.arg(instance_id), 'instance', 'running', sqlc.arg(storage_uri), sqlc.arg(key_ref),
        sqlc.arg(headscale_version), sqlc.arg(job_id), sqlc.arg(sequence), sqlc.arg(wrapped_data_key))
RETURNING id, started_at;

-- name: FinishInstanceBackup :one
-- Backup xong: manifest đã được worker kiểm chữ ký + danh tính trước khi ghi.
UPDATE backups
SET status = 'succeeded', size_bytes = sqlc.arg(size_bytes), sha256 = sqlc.arg(sha256), manifest = sqlc.arg(manifest),
    manifest_signature = sqlc.arg(manifest_signature), manifest_sha256 = sqlc.arg(manifest_sha256), method = sqlc.arg(method),
    finished_at = now(), expires_at = sqlc.arg(expires_at)
WHERE id = sqlc.arg(id) AND status = 'running'
RETURNING id;

-- name: FailInstanceBackup :exec
UPDATE backups SET status = 'failed', finished_at = now() WHERE id = sqlc.arg(id) AND status = 'running';

-- name: FailStaleInstanceBackups :exec
-- Hàng running của một job trước (worker chết giữa chừng) của cùng instance: lỗi — một backup không bao giờ treo running.
UPDATE backups SET status = 'failed', finished_at = now()
WHERE instance_id = sqlc.arg(instance_id) AND status = 'running' AND id <> sqlc.arg(keep_id);

-- name: GetInstanceBackup :one
-- Hàng sổ của một restore (pool tenant: RLS chỉ cho hàng của chính tenant — sổ của A không trỏ được archive của B).
SELECT id, tenant_id, instance_id, status, sequence, wrapped_data_key, key_ref, headscale_version, sha256, size_bytes,
       manifest, manifest_signature, manifest_sha256, method, started_at, finished_at
FROM backups
WHERE id = sqlc.arg(id) AND kind = 'instance';

-- name: ListSucceededInstanceBackups :many
-- Retention cục bộ: các backup succeeded của instance, mới nhất trước.
SELECT id, sequence, expires_at FROM backups
WHERE instance_id = sqlc.arg(instance_id) AND status = 'succeeded' AND sequence IS NOT NULL
ORDER BY sequence DESC;

-- name: PurgeInstanceBackupsBelow :execrows
-- Archive của các sequence này đã bị Agent xóa (retain_from_sequence): hàng sổ → purged (giữ để audit — §6.4).
UPDATE backups SET status = 'purged'
WHERE instance_id = sqlc.arg(instance_id) AND status = 'succeeded' AND sequence < sqlc.arg(below);

-- name: SetBackupVerified :exec
-- Một restore từ bản này đã hoàn tất (§6.3 verified_at: lần kiểm restore gần nhất).
UPDATE backups SET verified_at = now() WHERE id = sqlc.arg(id) AND status = 'succeeded';

-- name: ListRestorePlanDevices :many
-- Sổ thiết bị của instance TRƯỚC khi restore (đối chiếu theo machine_key — §17.2 bước 5): trạng thái mong muốn (route
-- đã duyệt, tag) của thiết bị còn sống, thu hồi và thời điểm gỡ của thiết bị đã gỡ.
SELECT id, machine_key, name, removed_at, revocation_state, revocation_kind, revocation_requested_at, expiry, tags,
       approved_routes, first_seen_at
FROM device_inventory_cache
WHERE instance_id = sqlc.arg(instance_id)
ORDER BY first_seen_at, id;

-- name: ListOffboardedHeadscaleUsers :many
-- Headscale user (mg-<membership uuid>) của thành viên đã offboard (§17.2 bước 5).
SELECT headscale_username FROM tenant_memberships WHERE status = 'offboarded' ORDER BY headscale_username;

-- name: ListMembershipHeadscaleNames :many
SELECT id, headscale_username, headscale_user_id FROM tenant_memberships ORDER BY id;

-- name: ClearMembershipHeadscaleUserIDs :execrows
-- §17.2 bước 6: phân giải lại headscale_user_id theo tên trong MỘT transaction — đặt NULL trước (id số của bản khôi
-- phục có thể trùng id mà nền tảng đã ghi cho user khác), rồi gán lại theo tên.
UPDATE tenant_memberships SET headscale_user_id = NULL, updated_at = now(), version = version + 1
WHERE headscale_user_id IS NOT NULL;

-- name: SetMembershipHeadscaleUserID :exec
UPDATE tenant_memberships SET headscale_user_id = sqlc.arg(headscale_user_id), updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id);

-- name: InsertImportedPolicyVersion :one
-- §17.2 bước 4, nhánh "PostgreSQL cũ hơn bản backup": policy trong bản backup (chuỗi instance khôi phục đang phục vụ)
-- thành một version mới trạng thái validated — policy.apply chỉ áp version approved, nên nó chỉ được áp sau khi
-- Owner/Admin rà soát và duyệt (§7.3). content_sha256 = sha256 của đúng chuỗi (DB kiểm).
INSERT INTO policy_versions (tenant_id, version, kind, source_hujson, content_sha256, state, validation_report)
VALUES (sqlc.arg(tenant_id), sqlc.arg(version), 'user', sqlc.arg(source_hujson), sqlc.arg(content_sha256), 'validated',
        sqlc.arg(validation_report))
RETURNING id, version;
