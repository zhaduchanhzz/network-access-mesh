-- Placement (P3-T04, §11.3 bước 3 `placement.allocate`): chỉ pool platform của worker (store.WithPlatformTx — hosts là
-- bảng P, nhánh platform của tenant_instances thấy instance của mọi tenant). Mọi lần cấp phát chạy trong MỘT transaction:
-- khóa các hàng host ứng viên (FOR UPDATE, theo thứ tự id — không deadlock giữa hai lần cấp phát) rồi đọc lại trạng thái
-- cấp phát dưới khóa; UNIQUE(host_id, run_uid) và các partial UNIQUE của tenant_instances (0001) là chốt chặn cuối.

-- name: LockPlacementHosts :many
-- Host nhận instance mới (status active), lọc theo vùng của tenant khi tenant có deployment_region; khóa hàng tới hết
-- transaction. Cần quyền UPDATE trên ≥ 1 cột của hosts (mg_worker_platform có — 0001).
SELECT * FROM hosts
WHERE status = 'active'
  AND (sqlc.narg(region)::text IS NULL OR region = sqlc.narg(region)::text)
ORDER BY id
FOR UPDATE;

-- name: ListHostAllocations :many
-- Mọi instance (kể cả removed: UID không tái sử dụng) của các host đã khóa — đọc SAU khi có khóa (READ COMMITTED: lệnh
-- mới thấy mọi lần cấp phát đã commit trước khi khóa được nhả).
SELECT host_id, status, run_uid, net_cidr, stun_port
FROM tenant_instances
WHERE host_id = ANY (sqlc.arg(host_ids)::uuid[]);

-- name: GetLiveInstanceByHostname :one
-- partial UNIQUE(control_hostname) WHERE status <> 'removed' (0001): instance chưa removed đang giữ hostname.
SELECT id, tenant_id, status FROM tenant_instances
WHERE control_hostname = sqlc.arg(control_hostname) AND status <> 'removed';
