-- Module network (P4-T12 — §12.3, §13.2 "routes", "dns", "resources"; bảng network_resources, dns_records của 0022).
-- Mọi truy vấn chạy trên pool tenant (bảng T); điều kiện tenant_id tường minh là lớp thứ hai sau RLS. api: CRUD
-- catalog, tạo/xóa bản ghi DNS, đọc cấu hình DNS đang hiệu lực; worker: đọc bản ghi (job dns.records_write ghi
-- extra-records.json qua Agent) và registry của instance.

-- ---------------------------------------------------------------- network_resources

-- name: ListNetworkResources :many
-- Thứ tự ổn định (created_at, id) tăng dần (§13.1 "Pagination").
SELECT * FROM network_resources
WHERE tenant_id = sqlc.arg(tenant_id)
  AND (created_at, id) > (sqlc.arg(after_created_at)::timestamptz, sqlc.arg(after_id)::uuid)
ORDER BY created_at, id
LIMIT sqlc.arg(page_limit);

-- name: GetNetworkResource :one
SELECT * FROM network_resources
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: LockNetworkResource :one
SELECT * FROM network_resources
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id)
FOR UPDATE;

-- name: InsertNetworkResource :one
-- Trùng tên ⇒ unique_violation (network_resources_tenant_id_name_key); owner_group_id của tenant khác ⇒ FK ghép
-- (tenant_id, owner_group_id) vi phạm.
INSERT INTO network_resources (tenant_id, name, kind, address, ports, protocol, tags, owner_group_id, description)
VALUES (sqlc.arg(tenant_id), sqlc.arg(name), sqlc.arg(kind), sqlc.arg(address), sqlc.arg(ports)::text[],
        sqlc.narg(protocol), sqlc.arg(tags)::text[], sqlc.narg(owner_group_id), sqlc.narg(description))
RETURNING *;

-- name: UpdateNetworkResource :one
-- version = khóa lạc quan (ETag): hàng đã khóa FOR UPDATE và If-Match đã kiểm trong cùng transaction.
UPDATE network_resources
SET name = sqlc.arg(name), kind = sqlc.arg(kind), address = sqlc.arg(address), ports = sqlc.arg(ports)::text[],
    protocol = sqlc.narg(protocol), tags = sqlc.arg(tags)::text[], owner_group_id = sqlc.narg(owner_group_id),
    description = sqlc.narg(description), updated_at = now(), version = version + 1
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id)
RETURNING *;

-- name: DeleteNetworkResource :execrows
DELETE FROM network_resources
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- ---------------------------------------------------------------- dns_records

-- name: ListDNSRecords :many
-- Toàn bộ bản ghi của tenant theo thứ tự của file extra-records.json (name, type, value) — tối đa MaxDNSRecords.
SELECT * FROM dns_records
WHERE tenant_id = sqlc.arg(tenant_id)
ORDER BY name, type, value;

-- name: CountDNSRecords :one
SELECT count(*)::bigint AS n FROM dns_records WHERE tenant_id = sqlc.arg(tenant_id);

-- name: LockDNSRecordSet :exec
-- Tuần tự hóa các thay đổi tập bản ghi của một tenant (trần số bản ghi đếm đúng khi hai lần tạo đồng thời): khóa
-- advisory theo giao dịch, không giữ qua commit.
SELECT pg_advisory_xact_lock(hashtextextended('dns_records:' || sqlc.arg(tenant_id)::uuid::text, 0));

-- name: GetDNSRecord :one
SELECT * FROM dns_records
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: InsertDNSRecord :one
-- Trùng (name, type, value) ⇒ unique_violation (dns_records_tenant_id_name_type_value_key).
INSERT INTO dns_records (tenant_id, name, type, value, created_by)
VALUES (sqlc.arg(tenant_id), sqlc.arg(name), sqlc.arg(type), sqlc.arg(value), sqlc.narg(created_by))
RETURNING *;

-- name: DeleteDNSRecord :one
DELETE FROM dns_records
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id)
RETURNING *;

-- ---------------------------------------------------------------- instance (DNS settings, records job)

-- name: GetNetworkInstance :one
-- Instance chưa removed của tenant (MVP: tối đa một) với slug của tenant, MagicDNS base domain và tham số
-- nameservers của version cấu hình đang hiệu lực (NULL khi instance chưa có version do orchestrator ghi — instance
-- adopt chưa backfill, P3-T14b).
SELECT i.id AS instance_id, i.status AS instance_status, i.base_domain, i.config_version_id, t.slug,
       t.status AS tenant_status, v.version AS config_version, (v.params -> 'nameservers')::jsonb AS nameservers
FROM tenant_instances i
JOIN tenants t ON t.id = i.tenant_id
LEFT JOIN instance_config_versions v ON v.tenant_id = i.tenant_id AND v.id = i.config_version_id
WHERE i.tenant_id = sqlc.arg(tenant_id) AND i.status <> 'removed';

-- name: GetUnfinishedReconfigure :one
-- Lần reconfigure chưa kết thúc của instance (§13.5 (b): tối đa một — khóa dedupe instance:<id>:instance.reconfigure).
SELECT id, status, input, created_at FROM provisioning_jobs
WHERE tenant_id = sqlc.arg(tenant_id) AND instance_id = sqlc.arg(instance_id) AND kind = 'instance.reconfigure'
  AND status IN ('queued', 'running', 'compensating', 'failed_resumable')
ORDER BY created_at DESC
LIMIT 1;
