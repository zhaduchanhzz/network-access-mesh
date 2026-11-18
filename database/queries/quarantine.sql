-- Quarantine / release của instance (P3-T18, §11.4). Mọi truy vấn ở pool platform (api: yêu cầu + executor của phê
-- duyệt; worker: job instance.quarantine / instance.release và step gate của framework job). Không cột/bảng mới:
-- tenant_instances.status đã có 'quarantined' (0001).

-- name: GetInstanceForQuarantine :one
-- Instance + tenant của nó (slug, trạng thái) — đọc của job và của executor release.
SELECT ti.id, ti.tenant_id, t.slug, t.status AS tenant_status, ti.status, ti.noise_key_fingerprint
FROM tenant_instances ti
JOIN tenants t ON t.id = ti.tenant_id
WHERE ti.id = sqlc.arg(id);

-- name: LockInstanceForQuarantine :one
-- Như GetInstanceForQuarantine, khóa hàng instance (FOR UPDATE) trước khi đổi trạng thái: trạng thái trước (from) ghi
-- vào created_resources/audit là trạng thái thật lúc đổi.
SELECT ti.id, ti.tenant_id, t.slug, t.status AS tenant_status, ti.status, ti.noise_key_fingerprint
FROM tenant_instances ti
JOIN tenants t ON t.id = ti.tenant_id
WHERE ti.id = sqlc.arg(id)
FOR UPDATE OF ti;

-- name: QuarantineGate :one
-- Step gate (jobs.StepGate — §11.4: "mọi job ... bỏ qua instance đang quarantine"): quarantined = instance của job (job
-- phạm vi instance) hoặc instance chưa removed của tenant (job phạm vi tenant, ví dụ tenant.provision) đang
-- 'quarantined'; quarantine_requested = có job instance.quarantine của cùng instance chưa kết thúc hoặc tạo sau job này
-- (release dừng khi bị quarantine lại giữa chừng).
SELECT EXISTS (SELECT 1 FROM tenant_instances ti
               WHERE ti.tenant_id = sqlc.arg(tenant_id) AND ti.status = 'quarantined'
                 AND (sqlc.narg(instance_id)::uuid IS NULL OR ti.id = sqlc.narg(instance_id)::uuid))::boolean AS quarantined,
       EXISTS (SELECT 1 FROM provisioning_jobs q
               JOIN provisioning_jobs me ON me.id = sqlc.arg(job_id)
               WHERE q.kind = 'instance.quarantine' AND q.instance_id = me.instance_id AND q.id <> me.id
                 AND (q.status IN ('queued', 'running') OR q.created_at > me.created_at))::boolean AS quarantine_requested;
