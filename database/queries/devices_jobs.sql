-- name: CreateDevice :one
-- Pool tenant (bảng T). FK ghép (tenant_id, instance_id) và (tenant_id, owner_membership_id): tham chiếu chéo tenant
-- bị DB từ chối.
INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, name, given_name,
                                    owner_membership_id)
VALUES (sqlc.arg(tenant_id), sqlc.arg(instance_id), sqlc.arg(headscale_node_id), sqlc.arg(machine_key), sqlc.narg(name),
        sqlc.narg(given_name), sqlc.narg(owner_membership_id))
RETURNING *;

-- name: ListLiveDevices :many
SELECT * FROM device_inventory_cache
WHERE tenant_id = sqlc.arg(tenant_id) AND removed_at IS NULL
ORDER BY first_seen_at, id;
