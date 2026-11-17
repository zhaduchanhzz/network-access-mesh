-- Xoay API key của instance Headscale (P3-T10 — §11.4 "API key rotation", §13.5 `apikey.rotate`, §7.6): job
-- apikey.rotate, lịch của nó + gauge hạn key, và lệnh `meshguard-worker admin apikey-rotate`. Mọi truy vấn chạy trên
-- pool platform của worker (chỉ role platform được UPDATE tenant_instances — 0001) và chỉ đọc/ghi reference mgsec:// +
-- prefix công khai + hạn của key — không bao giờ là key (§6.3). Cột tường minh, không SELECT *.

-- name: GetInstanceForKeyRotation :one
-- Trạng thái của một instance cho một lần xoay: registry + trạng thái tenant + có job nhóm lifecycle của tenant đang
-- chạy không (đúng điều kiện bỏ qua của GetInstanceForReconcile ở reconcile.sql — §13.5 (d)).
SELECT ti.id, ti.tenant_id, t.slug, t.status AS tenant_status, ti.status, ti.api_key_secret_ref, ti.api_key_prefix,
       ti.api_key_expires_at,
       EXISTS (SELECT 1 FROM provisioning_jobs j
               WHERE j.lock_key = 'tenant:' || ti.tenant_id::text || ':lifecycle'
                 AND j.status IN ('running', 'compensating'))::boolean AS lifecycle_busy
FROM tenant_instances ti
JOIN tenants t ON t.id = ti.tenant_id
WHERE ti.id = sqlc.arg(id) AND ti.tenant_id = sqlc.arg(tenant_id);

-- name: SwapInstanceAPIKey :one
-- Đổi key hiện hành CÓ ĐIỀU KIỆN: chỉ khi hàng còn trỏ đúng reference đã đọc lúc bắt đầu lần xoay (không hàng ⇒ hàng
-- đã bị đổi giữa chừng — xung đột, không ghi gì).
UPDATE tenant_instances
SET api_key_secret_ref = sqlc.arg(new_ref)::text, api_key_prefix = sqlc.arg(new_prefix)::text,
    api_key_expires_at = sqlc.arg(new_expires_at)::timestamptz, updated_at = now(), version = version + 1
WHERE id = sqlc.arg(id) AND tenant_id = sqlc.arg(tenant_id)
  AND api_key_secret_ref IS NOT DISTINCT FROM sqlc.narg(old_ref)::text
RETURNING id, version;

-- name: GetInstanceAPIKeyRef :one
-- Đọc lại reference hiện hành sau một lần đổi có kết quả không chắc (lỗi ở bước commit).
SELECT api_key_secret_ref FROM tenant_instances
WHERE id = sqlc.arg(id) AND tenant_id = sqlc.arg(tenant_id);

-- name: ListAPIKeyExpiries :many
-- Lịch của apikey.rotate và gauge hạn key: instance starting/running đã ghi key, của tenant mà lần xoay với tới được
-- (provisioning, active, suspended — instance của tenant suspended vẫn chạy, §11.4). Instance quarantined/removed/
-- stopped không có ở đây (§11.4: job bỏ qua instance quarantined).
SELECT ti.id, ti.tenant_id, ti.api_key_prefix, ti.api_key_expires_at
FROM tenant_instances ti
JOIN tenants t ON t.id = ti.tenant_id
WHERE ti.status IN ('starting', 'running') AND ti.api_key_secret_ref IS NOT NULL
  AND t.status IN ('provisioning', 'active', 'suspended')
ORDER BY ti.id;
