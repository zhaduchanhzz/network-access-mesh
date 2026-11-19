-- Module relay (P3-T05c, §10, §10.6): RelayService — đọc relay_regions / relay_assignments (0010) + kết quả probe
-- (relay_regions.last_probe / last_probe_at, 0016) cho GET /tenants/{t}/relay (pool tenant, RLS) và
-- GET /platform/relay-regions (pool platform); job relay.probe (pool platform của worker) ghi kết quả probe. Bước 17 của
-- provisioning (relay.assign — queries/provisioning.sql) là nơi DUY NHẤT tạo hàng relay; xóa: compensation của bước đó và
-- bước relay.remove của deprovision (queries/deprovision.sql — P3-T09). Cột tường minh, không SELECT *.

-- name: ListRelayProbeTargets :many
-- Pool platform: region cần relay.probe theo lịch — region embedded đang active có ít nhất một assignment active tới một
-- instance đang chạy (DERP nhúng sống trong chính instance; instance không chạy thì không có gì để probe). Một hàng mỗi
-- region (instance phục vụ: assignment ưu tiên cao nhất). region embedded luôn có tenant (CHECK của 0010). Tenant đang
-- deprovision (hoặc đã xóa) không còn là target (P3-T09).
SELECT DISTINCT ON (r.id) r.id, a.tenant_id, a.instance_id, r.last_probe_at
FROM relay_regions r
JOIN relay_assignments a ON a.relay_region_id = r.id AND a.status = 'active'
JOIN tenant_instances i ON i.id = a.instance_id AND i.tenant_id = a.tenant_id AND i.status = 'running'
JOIN tenants t ON t.id = a.tenant_id AND t.status IN ('provisioning', 'active', 'suspended')
WHERE r.kind = 'embedded' AND r.status = 'active'
ORDER BY r.id, a.priority, a.instance_id;

-- name: GetRelayRegionForProbe :one
-- Pool platform: region của một job relay.probe, có instance đang chạy phục vụ nó hay không, và đồng hồ DB lúc bắt đầu
-- probe (checked_at của kết quả).
SELECT r.id, r.kind, r.status, r.hostname, r.ipv4, r.stun_port,
       EXISTS (SELECT 1 FROM relay_assignments a
               JOIN tenant_instances i ON i.id = a.instance_id AND i.tenant_id = a.tenant_id
               WHERE a.relay_region_id = r.id AND a.status = 'active' AND i.status = 'running')::boolean AS serving,
       clock_timestamp()::timestamptz AS checked_at
FROM relay_regions r
WHERE r.id = sqlc.arg(id) AND r.tenant_id = sqlc.arg(tenant_id)::uuid;

-- name: RecordRelayProbe :execrows
-- Pool platform: ghi kết quả một lần probe. Kết quả của lần probe bắt đầu sớm hơn kết quả đã ghi bị bỏ qua (0 hàng): một
-- probe chậm không bao giờ đè probe mới hơn. Không đổi version/updated_at (trạng thái quản trị của region).
UPDATE relay_regions
SET last_probe = sqlc.arg(probe), last_probe_at = sqlc.arg(checked_at)
WHERE id = sqlc.arg(id) AND tenant_id = sqlc.arg(tenant_id)::uuid
  AND (last_probe_at IS NULL OR last_probe_at < sqlc.arg(checked_at));

-- name: ListTenantRelay :many
-- Pool tenant (GET /tenants/{t}/relay): assignment của các instance chưa removed của tenant, với region và trạng thái
-- instance, kèm đồng hồ DB để xét độ cũ. RLS chỉ cho thấy hàng của tenant đang đặt; điều kiện tenant_id tường minh là lớp
-- phòng thủ thứ hai.
SELECT a.id, a.priority, a.status,
       r.id AS region_id, r.code, r.name, r.kind, r.derp_region_id, r.hostname, r.ipv4, r.ipv6, r.stun_port, r.derp_port,
       r.verify_mode, r.status AS region_status, r.last_probe, r.last_probe_at,
       i.status AS instance_status, statement_timestamp()::timestamptz AS now
FROM relay_assignments a
JOIN relay_regions r ON r.id = a.relay_region_id AND r.tenant_id = a.tenant_id
JOIN tenant_instances i ON i.id = a.instance_id AND i.tenant_id = a.tenant_id
WHERE a.tenant_id = sqlc.arg(tenant_id) AND i.status <> 'removed'
ORDER BY a.priority, a.created_at, a.id;

-- name: ListRelayRegionsPage :many
-- Pool platform (GET /platform/relay-regions): một trang region của mọi tenant (và region dùng chung — Phase 7), thứ tự
-- ổn định (created_at, id); GET /platform/tenants/{t}/relay-regions (P4-T02) lọc theo tenant_id của region.
SELECT r.id, r.code, r.name, r.kind, r.derp_region_id, r.hostname, r.ipv4, r.ipv6, r.stun_port, r.derp_port, r.verify_mode,
       r.host_id, r.tenant_id, r.status, r.last_probe, r.last_probe_at, r.created_at, r.updated_at, r.version
FROM relay_regions r
WHERE (sqlc.narg(tenant_id)::uuid IS NULL OR r.tenant_id = sqlc.narg(tenant_id)::uuid)
  AND (sqlc.narg(after_created_at)::timestamptz IS NULL
       OR (r.created_at, r.id) > (sqlc.narg(after_created_at)::timestamptz, sqlc.narg(after_id)::uuid))
ORDER BY r.created_at, r.id
LIMIT sqlc.arg(row_limit);

-- name: ListRelayAssignmentsOfRegions :many
-- Pool platform: assignment của các region trong một trang, với trạng thái instance (instance phục vụ region embedded).
SELECT a.id, a.tenant_id, a.instance_id, a.relay_region_id, a.priority, a.status, i.status AS instance_status
FROM relay_assignments a
JOIN tenant_instances i ON i.id = a.instance_id AND i.tenant_id = a.tenant_id
WHERE a.relay_region_id = ANY (sqlc.arg(region_ids)::uuid[])
ORDER BY a.relay_region_id, a.priority, a.created_at, a.id;
