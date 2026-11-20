-- Module monitoring (P2-T13a, §16): health của instance (job health.probe ghi tenant_instances.last_health /
-- last_health_at), Tenant Dashboard (pool tenant) và Platform Health (pool platform). Cột tường minh, không SELECT *.
-- Số liệu thiết bị KHÔNG đọc ở đây: monitoring nhận chúng qua service của devices (§13.6).

-- name: ListHealthProbeTargets :many
-- Pool platform: instance cần health.probe theo lịch (§13.5) — chỉ instance đang chạy của tenant còn phục vụ
-- (provisioning, active, suspended): tenant đang deprovision không còn là target (P3-T09, §11.4 "gỡ target
-- scrape/probe của instance").
SELECT ti.id, ti.tenant_id FROM tenant_instances ti
JOIN tenants t ON t.id = ti.tenant_id
WHERE ti.status = 'running' AND t.status IN ('provisioning', 'active', 'suspended')
ORDER BY ti.id;

-- name: GetInstanceForProbe :one
-- Pool platform: instance của một job health.probe và đồng hồ DB lúc bắt đầu probe (checked_at của kết quả).
SELECT id, tenant_id, status, clock_timestamp()::timestamptz AS checked_at
FROM tenant_instances
WHERE id = sqlc.arg(id) AND tenant_id = sqlc.arg(tenant_id);

-- name: RecordInstanceHealth :execrows
-- Pool platform: ghi kết quả một lần probe. Kết quả của lần probe bắt đầu sớm hơn kết quả đã ghi bị bỏ qua (0 hàng):
-- một probe chậm không bao giờ đè probe mới hơn. Không đổi version/updated_at (ETag của instance).
UPDATE tenant_instances
SET last_health = sqlc.arg(health), last_health_at = sqlc.arg(checked_at)
WHERE id = sqlc.arg(id) AND tenant_id = sqlc.arg(tenant_id)
  AND (last_health_at IS NULL OR last_health_at < sqlc.arg(checked_at));

-- name: GetTenantInstanceHealth :one
-- Pool tenant (dashboard): instance chưa removed của tenant (MVP: tối đa một) với health gần nhất, kèm đồng hồ DB để
-- xét độ cũ.
SELECT id, status, last_health, last_health_at, statement_timestamp()::timestamptz AS now
FROM tenant_instances
WHERE tenant_id = sqlc.arg(tenant_id) AND status <> 'removed';

-- name: GetTenantDiagnosticsInstance :one
-- Pool tenant (Connectivity Diagnostics — P5-T08): trạng thái tenant, instance chưa removed (MVP: tối đa một; vắng ⇒
-- cột instance NULL) với health gần nhất và hạn API key (chỉ thời điểm — không secret, không prefix), kèm đồng hồ DB.
SELECT t.status AS tenant_status, ti.id AS instance_id, ti.status AS instance_status, ti.last_health,
       ti.last_health_at, ti.api_key_expires_at, statement_timestamp()::timestamptz AS now
FROM tenants t
LEFT JOIN tenant_instances ti ON ti.tenant_id = t.id AND ti.status <> 'removed'
WHERE t.id = sqlc.arg(tenant_id)
ORDER BY ti.created_at DESC NULLS LAST
LIMIT 1;

-- name: MonitoringNow :one
-- Đồng hồ DB của một lần tổng hợp (checked_at của Platform Health).
SELECT statement_timestamp()::timestamptz AS now;

-- name: CountTenantsByStatus :many
-- Pool platform: số tenant theo trạng thái.
SELECT status, count(*)::bigint AS tenants FROM tenants
GROUP BY status
ORDER BY status;

-- name: ListInstancesHealth :many
-- Pool platform: mọi instance chưa removed với health gần nhất (tổng hợp Platform Health).
SELECT id, tenant_id, status, last_health, last_health_at FROM tenant_instances
WHERE status <> 'removed'
ORDER BY id;

-- name: CountJobsByStatus :many
-- Pool platform: job chưa kết thúc theo trạng thái (hàng đợi của nền tảng, §13.5).
SELECT status, count(*)::bigint AS jobs FROM provisioning_jobs
WHERE status IN ('queued', 'running', 'compensating', 'failed_resumable')
GROUP BY status
ORDER BY status;

-- name: CountJobsFailedSince :one
-- Pool platform: job kết thúc thất bại (failed, rolled_back) từ một thời điểm.
SELECT count(*)::bigint AS jobs FROM provisioning_jobs
WHERE status IN ('failed', 'rolled_back') AND finished_at >= sqlc.arg(since)::timestamptz;

-- name: LatestFinishedPlatformJob :one
-- Pool platform: lần chạy kết thúc gần nhất của một job platform định kỳ (job.reaper mỗi phút = heartbeat của worker,
-- §16.2).
SELECT status, finished_at FROM provisioning_jobs
WHERE kind = sqlc.arg(kind) AND tenant_id IS NULL AND finished_at IS NOT NULL
ORDER BY finished_at DESC
LIMIT 1;
