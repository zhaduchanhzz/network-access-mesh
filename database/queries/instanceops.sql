-- Job instance.restart / instance.upgrade (P3-T13a, §11.4 hàng Restart, Upgrade; §13.5) và đợt nâng cấp
-- `meshguard-worker admin upgrade-wave`. Pool platform; không truy vấn nào đọc hay ghi secret.

-- name: ListUpgradeCandidates :many
-- Đợt nâng cấp với --all: mọi instance `running` (không quarantined/stopped/removed) có version cấu hình do orchestrator
-- ghi, của tenant active/suspended, chưa chạy image đích — theo thứ tự id (ổn định giữa hai lần chạy lệnh).
SELECT ti.id
FROM tenant_instances ti
JOIN tenants t ON t.id = ti.tenant_id
WHERE ti.status = 'running'
  AND ti.config_version_id IS NOT NULL
  AND ti.image_digest <> sqlc.arg(image_digest)::text
  AND t.status IN ('active', 'suspended')
ORDER BY ti.id;
