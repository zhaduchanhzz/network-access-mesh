-- Reconcile chỉ báo cáo (P3-T12, §11.4, §13.5): trạng thái mong muốn của instance (registry) mà job instance.reconcile /
-- host.reconcile so với thực tế (Agent + Headscale). Mọi truy vấn ở pool platform của worker, chỉ ĐỌC — báo cáo là
-- output của chính job (provisioning_jobs.output), không có cột/bảng riêng. Cột tường minh, không SELECT *.

-- name: ListReconcileTargets :many
-- Instance được reconcile theo lịch: starting/running/stopped (không reconcile allocated, failed, removed và quarantined
-- — §11.4: reconcile bỏ qua instance quarantined).
SELECT id, tenant_id FROM tenant_instances
WHERE status IN ('starting', 'running', 'stopped')
ORDER BY id;

-- name: GetInstanceForReconcile :one
-- Trạng thái mong muốn của một instance: registry + config version đang áp dụng (NULL khi chưa ghi — instance dựng tay
-- của Phase 1) + có job nhóm lifecycle của tenant đang chạy không (khi đó reconcile bỏ qua: drift là tạm thời) + đồng
-- hồ DB lúc bắt đầu.
SELECT ti.id, ti.tenant_id, t.slug, ti.status, ti.image_digest, ti.net_cidr, ti.run_uid, ti.api_key_prefix,
       ti.noise_key_fingerprint, cv.config_sha256 AS desired_config_sha256,
       EXISTS (SELECT 1 FROM provisioning_jobs j
               WHERE j.lock_key = 'tenant:' || ti.tenant_id::text || ':lifecycle'
                 AND j.status IN ('running', 'compensating'))::boolean AS lifecycle_busy,
       clock_timestamp()::timestamptz AS checked_at
FROM tenant_instances ti
JOIN tenants t ON t.id = ti.tenant_id
LEFT JOIN instance_config_versions cv ON cv.tenant_id = ti.tenant_id AND cv.id = ti.config_version_id
WHERE ti.id = sqlc.arg(id) AND ti.tenant_id = sqlc.arg(tenant_id);

-- name: ListInstancesForHostReconcile :many
-- Mọi instance của registry (cả removed) để đối chiếu với inventory của host (ListInstances của Agent).
SELECT ti.id, ti.tenant_id, t.slug, ti.status
FROM tenant_instances ti
JOIN tenants t ON t.id = ti.tenant_id
ORDER BY ti.id;

-- name: LatestInstanceReconcileReports :many
-- Đọc cho monitoring: báo cáo reconcile gần nhất của mỗi instance (output của job instance.reconcile đã kết thúc thành
-- công trong cửa sổ, chỉ các lần đã kiểm — bỏ lần bị bỏ qua).
SELECT DISTINCT ON (instance_id) instance_id::uuid AS instance_id, tenant_id::uuid AS tenant_id, output,
       finished_at::timestamptz AS finished_at
FROM provisioning_jobs
WHERE kind = 'instance.reconcile' AND status = 'succeeded' AND instance_id IS NOT NULL
  AND finished_at >= sqlc.arg(since)::timestamptz AND output ->> 'status' IS NOT NULL
ORDER BY instance_id, finished_at DESC;

-- name: LatestHostReconcileReport :one
-- Đọc cho monitoring: báo cáo host.reconcile gần nhất (job platform).
SELECT output, finished_at::timestamptz AS finished_at
FROM provisioning_jobs
WHERE kind = 'host.reconcile' AND tenant_id IS NULL AND status = 'succeeded' AND output ->> 'status' IS NOT NULL
ORDER BY finished_at DESC
LIMIT 1;
