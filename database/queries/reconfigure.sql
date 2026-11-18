-- Job instance.reconfigure (P3-T13, §11.4 hàng Reconfigure, §13.5) và POST /platform/instances/{instanceId}/reconfigure.
-- Pool platform trừ khi ghi khác; điều kiện tenant_id tường minh là lớp thứ hai sau RLS. Version cấu hình: `pending`
-- (đã ghi, chưa chạy) → `applied` (đang hiệu lực — hàng mà tenant_instances.config_version_id trỏ tới; version trước
-- chuyển `superseded`) hoặc `failed` (đã lùi về version trước). Không truy vấn nào đọc hay ghi secret.

-- name: GetReconfigureTarget :one
-- Instance của job + slug/trạng thái tenant + điểm vào công khai của host (derp.server.ipv4 render lại từ đây — §17.4).
SELECT sqlc.embed(ti), t.slug AS tenant_slug, t.status AS tenant_status, h.name AS host_name,
       h.public_entry AS host_public_entry
FROM tenant_instances ti
JOIN tenants t ON t.id = ti.tenant_id
JOIN hosts h ON h.id = ti.host_id
WHERE ti.id = sqlc.arg(id) AND ti.tenant_id = sqlc.arg(tenant_id);

-- name: GetInstanceConfigVersion :one
SELECT * FROM instance_config_versions
WHERE tenant_id = sqlc.arg(tenant_id) AND instance_id = sqlc.arg(instance_id) AND id = sqlc.arg(id);

-- name: InsertPendingConfigVersion :one
-- Bước config.record: version mới ở `pending`, id do job chọn trước (created_resources) — chạy lại không tạo version thứ
-- hai. rendered_config là bản mô tả không secret; nội dung thật nằm trên host, đối chiếu bằng config_sha256.
INSERT INTO instance_config_versions (id, tenant_id, instance_id, version, template_version, params, rendered_config,
                                      config_sha256, status, created_by)
VALUES (sqlc.arg(id), sqlc.arg(tenant_id), sqlc.arg(instance_id),
        (SELECT COALESCE(max(v.version), 0) + 1 FROM instance_config_versions v WHERE v.instance_id = sqlc.arg(instance_id)),
        sqlc.arg(template_version), sqlc.arg(params), sqlc.arg(rendered_config), sqlc.arg(config_sha256)::text,
        'pending', sqlc.narg(created_by))
RETURNING *;

-- name: TransitionConfigVersionStatus :execrows
-- Chuyển trạng thái có điều kiện (from); applied_at ghi lần đầu version được áp dụng.
UPDATE instance_config_versions
SET status = sqlc.arg(status)::text,
    applied_at = CASE WHEN sqlc.arg(status)::text = 'applied' THEN COALESCE(applied_at, now()) ELSE applied_at END
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND status = ANY (sqlc.arg(from_status)::text[]);

-- name: SwapInstanceConfigVersion :execrows
-- Đổi version hiện hành của instance có điều kiện (instance còn trỏ version mong đợi) + derp_region_id đã render.
UPDATE tenant_instances
SET config_version_id = sqlc.arg(config_version_id)::uuid,
    derp_region_id = COALESCE(sqlc.narg(derp_region_id)::integer, derp_region_id), updated_at = now(),
    version = version + 1
WHERE id = sqlc.arg(id) AND tenant_id = sqlc.arg(tenant_id) AND config_version_id = sqlc.arg(expected_version_id)::uuid;
