-- Quản lý host (P3-T04, §13.2 `GET/POST/PATCH /platform/hosts`, lệnh `meshguard admin host-set`): pool platform của api
-- (mg_api_platform — hosts là bảng P; quyền UPDATE theo cột của 0001, không có quyền đổi `name`). Mọi lần ghi cấu hình
-- khóa hàng host (FOR UPDATE) trước khi đếm instance chưa removed — cùng khóa mà placement (LockPlacementHosts) lấy
-- trước khi cấp phát — nên luật "capacity không thấp hơn số instance đang sống" và "dải cấp phát không đổi khi còn
-- instance sống" không bị một lần cấp phát song song vượt qua. CHECK của 0014 vẫn là chốt cuối.

-- name: ListHostsPage :many
-- GET /platform/hosts: thứ tự ổn định (created_at, id) cho phân trang (§13.1).
SELECT * FROM hosts
WHERE (sqlc.narg(status)::text IS NULL OR status = sqlc.narg(status)::text)
  AND (sqlc.narg(region)::text IS NULL OR region = sqlc.narg(region)::text)
  AND (sqlc.narg(after_created_at)::timestamptz IS NULL
       OR (created_at, id) > (sqlc.narg(after_created_at)::timestamptz, sqlc.narg(after_id)::uuid))
ORDER BY created_at, id
LIMIT sqlc.arg(row_limit);

-- name: LockHost :one
-- PATCH: khóa hàng tới hết transaction (placement chờ, rồi đọc lại hàng đã sửa).
SELECT * FROM hosts
WHERE id = sqlc.arg(id)
FOR UPDATE;

-- name: InsertHost :one
-- POST /platform/hosts: cấu hình đầy đủ (giá trị mặc định do service đặt, đã kiểm theo CHECK của 0014).
INSERT INTO hosts (name, region, status, capacity, public_entry, run_uid_range, stun_port_range, tenant_net_pool)
VALUES (sqlc.arg(name), sqlc.arg(region), sqlc.arg(status), sqlc.arg(capacity), sqlc.arg(public_entry),
        sqlc.arg(run_uid_range), sqlc.narg(stun_port_range), sqlc.arg(tenant_net_pool))
RETURNING *;

-- name: UpdateHostConfig :one
-- PATCH /platform/hosts/{hostId}, host-set: ghi lại toàn bộ cấu hình do người vận hành quản lý (hàng đã khóa bằng
-- LockHost). Không đụng name, agent_*, last_heartbeat_at.
UPDATE hosts
SET region = sqlc.arg(region), status = sqlc.arg(status), capacity = sqlc.arg(capacity),
    public_entry = sqlc.arg(public_entry), run_uid_range = sqlc.arg(run_uid_range),
    stun_port_range = sqlc.narg(stun_port_range), tenant_net_pool = sqlc.arg(tenant_net_pool), updated_at = now()
WHERE id = sqlc.arg(id)
RETURNING *;
