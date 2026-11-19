-- Truy vấn của module enrollment (P4-T06 — §7.4, bảng enrollment_requests của 0020). Pool tenant (bảng T): api tạo,
-- duyệt, phát, claim, thu hồi; worker (job enrollment.reconcile) đổi trạng thái theo quyền cột của 0020. tenant_id
-- được lọc tường minh ở mọi truy vấn (lớp thứ hai sau RLS — §8.8). Không cột nào giữ plaintext: chỉ hash SHA-256 của
-- Auth ID / session / mã enrollment và id số của pre-auth key.

-- name: GetEnrollmentContext :one
-- Thiết lập của tenant (TenantSettings.enrollment, đọc có kiểu ở config) + instance đang phục vụ (đích của
-- --login-server và của Headscale). Không có instance chưa removed ⇒ cột instance NULL.
SELECT t.status AS tenant_status, t.settings, i.id AS instance_id, i.server_url
FROM tenants t
LEFT JOIN tenant_instances i ON i.tenant_id = t.id AND i.status <> 'removed'
WHERE t.id = sqlc.arg(tenant_id);

-- name: GetEnrollmentMember :one
-- Thành viên của tenant (chủ thiết bị, người yêu cầu): trạng thái, tên Headscale user ổn định mg-<membership> (cột sinh
-- của 0002) và tên hiển thị (CreateUser chỉ nhận display name — không gửi email, §7.4 bước 3).
SELECT m.id, m.status, m.headscale_username, COALESCE(i.display_name, '')::text AS display_name
FROM tenant_memberships m
JOIN identities i ON i.tenant_id = m.tenant_id AND i.id = m.identity_id
WHERE m.tenant_id = sqlc.arg(tenant_id) AND m.id = sqlc.arg(id);

-- name: InsertEnrollmentRequest :one
INSERT INTO enrollment_requests (tenant_id, instance_id, requested_by_membership_id, method, target_membership_id,
                                 device_label, requested_tags, ephemeral, reusable, status)
VALUES (sqlc.arg(tenant_id), sqlc.arg(instance_id), sqlc.arg(requested_by_membership_id), sqlc.arg(method),
        sqlc.narg(target_membership_id), sqlc.narg(device_label), sqlc.arg(requested_tags), sqlc.arg(ephemeral),
        sqlc.arg(reusable), sqlc.arg(status))
RETURNING *;

-- name: GetEnrollmentRequest :one
SELECT * FROM enrollment_requests
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: LockEnrollmentRequest :one
SELECT * FROM enrollment_requests
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id)
FOR UPDATE;

-- name: ListEnrollmentRequestsPage :many
-- Mới nhất trước (index (tenant_id, created_at DESC, id DESC) của 0020). member: chỉ yêu cầu người đó tạo hoặc thiết
-- bị của người đó (ô ○ của End User — §8.6); statuses: giá trị cột (trạng thái phía API đã ánh xạ ngược).
SELECT * FROM enrollment_requests
WHERE tenant_id = sqlc.arg(tenant_id)
  AND (sqlc.narg(member)::uuid IS NULL OR requested_by_membership_id = sqlc.narg(member)::uuid
       OR target_membership_id = sqlc.narg(member)::uuid)
  AND (sqlc.narg(statuses)::text[] IS NULL OR status = ANY (sqlc.narg(statuses)::text[]))
  AND (sqlc.narg(after_created)::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg(after_created)::timestamptz, sqlc.narg(after_id)::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(row_limit);

-- name: SetEnrollmentRequestState :one
-- api: mọi cột trạng thái (quyền UPDATE cột của mg_api_tenant — 0020); nội dung được duyệt (người yêu cầu, chủ thiết
-- bị, phương thức, nhãn, tag, cờ key) không có ở đây — bất biến ở DB. version tăng ở mọi lần ghi.
UPDATE enrollment_requests
SET status                 = sqlc.arg(status),
    approver_membership_id = sqlc.narg(approver_membership_id),
    approved_at            = sqlc.narg(approved_at),
    issued_at              = sqlc.narg(issued_at),
    headscale_preauthkey_id = sqlc.narg(headscale_preauthkey_id),
    auth_id_hash           = sqlc.narg(auth_id_hash),
    session_id_hash        = sqlc.narg(session_id_hash),
    enroll_code_hash       = sqlc.narg(enroll_code_hash),
    claimed_at             = sqlc.narg(claimed_at),
    claimed_from_ip        = sqlc.narg(claimed_from_ip),
    registered_machine_key = sqlc.narg(registered_machine_key),
    reported_hostname      = sqlc.narg(reported_hostname),
    credential_expires_at  = sqlc.narg(credential_expires_at),
    consumed_node_id       = sqlc.narg(consumed_node_id),
    failure_code           = sqlc.narg(failure_code),
    updated_at             = now(),
    version                = version + 1
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id)
RETURNING *;

-- name: SetEnrollmentRequestOutcome :one
-- worker (enrollment.reconcile): chỉ các cột mg_worker_tenant được ghi (0020) — hết hạn, đã dùng, lỗi.
UPDATE enrollment_requests
SET status                 = sqlc.arg(status),
    registered_machine_key = sqlc.narg(registered_machine_key),
    reported_hostname      = sqlc.narg(reported_hostname),
    consumed_node_id       = sqlc.narg(consumed_node_id),
    failure_code           = sqlc.narg(failure_code),
    updated_at             = now(),
    version                = version + 1
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id)
RETURNING *;

-- name: LockPendingWebAuth :many
-- Claim (§7.4 bước 6): yêu cầu web-auth đang chờ thiết bị CỦA CHÍNH thành viên, phát trong CÙNG phiên Portal (hash của
-- sessions.public_id), chưa quá hạn — khóa tới hết transaction (hai claim đồng thời không cùng dùng một yêu cầu).
SELECT * FROM enrollment_requests
WHERE tenant_id = sqlc.arg(tenant_id) AND requested_by_membership_id = sqlc.arg(member) AND method = 'web_auth'
  AND status = 'awaiting_device' AND session_id_hash = sqlc.arg(session_id_hash) AND credential_expires_at > now()
ORDER BY issued_at, id
FOR UPDATE;

-- name: EnrollmentAuthIDSeen :one
-- Một Auth ID đã từng được claim trong tenant (partial UNIQUE (tenant_id, auth_id_hash) của 0020): claim lại ⇒ 409.
SELECT EXISTS (SELECT 1 FROM enrollment_requests
               WHERE tenant_id = sqlc.arg(tenant_id) AND auth_id_hash = sqlc.arg(auth_id_hash))::boolean AS seen;

-- name: LiveDeviceByMachineKey :one
-- Sổ thiết bị: node (machine key) đã có từ trước trên instance — §7.4 bước 8 (b): re-auth của thiết bị hiện hữu không
-- bao giờ bị xóa.
SELECT * FROM device_inventory_cache
WHERE tenant_id = sqlc.arg(tenant_id) AND instance_id = sqlc.arg(instance_id) AND machine_key = sqlc.arg(machine_key)
  AND removed_at IS NULL
ORDER BY first_seen_at DESC, id DESC
LIMIT 1;

-- name: LockLiveDeviceOfNode :one
SELECT * FROM device_inventory_cache
WHERE tenant_id = sqlc.arg(tenant_id) AND instance_id = sqlc.arg(instance_id)
  AND headscale_node_id = sqlc.arg(headscale_node_id) AND removed_at IS NULL
FOR UPDATE;

-- name: InsertEnrolledDevice :one
-- Thiết bị vừa đăng ký và được xác minh (§7.4 bước 8 "ghi device_inventory_cache"): cột cache từ node trả về, liên kết
-- enrollment_request_id và owner là dữ liệu authoritative của nền tảng; inventory.sync cập nhật phần cache sau đó.
INSERT INTO device_inventory_cache (tenant_id, instance_id, headscale_node_id, machine_key, node_key, name, given_name,
                                    ip_addresses, headscale_user_id, owner_membership_id, tags, register_method, online,
                                    last_seen, expiry, hs_created_at, enrollment_request_id)
VALUES (sqlc.arg(tenant_id), sqlc.arg(instance_id), sqlc.arg(headscale_node_id), sqlc.arg(machine_key),
        sqlc.narg(node_key), sqlc.narg(name), sqlc.narg(given_name), sqlc.arg(ip_addresses), sqlc.narg(headscale_user_id),
        sqlc.narg(owner_membership_id), sqlc.arg(tags), sqlc.narg(register_method), sqlc.arg(online),
        sqlc.narg(last_seen), sqlc.narg(expiry), sqlc.narg(hs_created_at), sqlc.arg(enrollment_request_id))
RETURNING *;

-- name: LinkDeviceEnrollment :exec
-- Hàng thiết bị đã có (sync đi trước): gắn liên kết enrollment và owner khi còn trống — không bao giờ ghi đè.
UPDATE device_inventory_cache
SET enrollment_request_id = COALESCE(enrollment_request_id, sqlc.arg(enrollment_request_id)),
    owner_membership_id   = COALESCE(owner_membership_id, sqlc.narg(owner_membership_id)::uuid)
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id);

-- name: ListOpenEnrollmentRequests :many
-- worker (enrollment.reconcile): yêu cầu chưa kết thúc.
SELECT * FROM enrollment_requests
WHERE tenant_id = sqlc.arg(tenant_id)
  AND status IN ('requested', 'pending_approval', 'approved', 'awaiting_device', 'claimed', 'registered',
                 'credential_issued')
ORDER BY created_at, id;

-- name: ListLiveReusableEnrollmentKeys :many
-- worker (enrollment.reconcile): key reusable đã dùng (consumed) chưa hết hạn trước expired_after (= lúc chạy trừ thời
-- gian ân hạn) — node mà key đó đăng ký thêm được đưa vào sổ thiết bị và thông báo device.new (lịch reconcile chạy cả
-- khi chỉ còn các key này).
SELECT * FROM enrollment_requests
WHERE tenant_id = sqlc.arg(tenant_id) AND status = 'consumed' AND reusable AND headscale_preauthkey_id IS NOT NULL
  AND credential_expires_at > sqlc.arg(expired_after)::timestamptz
ORDER BY created_at, id;

-- name: LinkConsumedEnrollmentDevices :many
-- worker: thiết bị đăng ký bằng key một lần (consumed) hoặc web-auth (verified) mà sổ đã có nhưng chưa có liên kết
-- enrollment — gắn liên kết (dữ liệu authoritative, §6.3). Chỉ yêu cầu kết thúc trong 7 ngày gần nhất. Trả hàng vừa
-- gắn kèm phương thức của yêu cầu: hàng của pre-auth key được thông báo device.new đúng lần gắn này (P4-T06).
UPDATE device_inventory_cache d
SET enrollment_request_id = r.id
FROM enrollment_requests r
WHERE d.tenant_id = sqlc.arg(tenant_id) AND r.tenant_id = sqlc.arg(tenant_id) AND d.instance_id = r.instance_id
  AND d.headscale_node_id = r.consumed_node_id AND d.removed_at IS NULL AND d.enrollment_request_id IS NULL
  AND r.status IN ('consumed', 'verified') AND r.updated_at > now() - interval '7 days'
RETURNING d.id, d.owner_membership_id, d.name, d.given_name, d.hs_created_at, r.method;
