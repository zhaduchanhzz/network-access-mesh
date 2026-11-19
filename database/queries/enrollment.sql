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
-- của 0002), tên hiển thị (CreateUser chỉ nhận display name — không gửi email, §7.4 bước 3) và identity (quyết định của
-- support actor: người quyết định không bao giờ là identity của người yêu cầu — 0028).
SELECT m.id, m.status, m.headscale_username, COALESCE(i.display_name, '')::text AS display_name, m.identity_id
FROM tenant_memberships m
JOIN identities i ON i.tenant_id = m.tenant_id AND i.id = m.identity_id
WHERE m.tenant_id = sqlc.arg(tenant_id) AND m.id = sqlc.arg(id);

-- name: InsertEnrollmentRequest :one
-- requested_ttl_minutes (0027): hạn key người yêu cầu xin — /start của yêu cầu đã duyệt phát key theo nó.
INSERT INTO enrollment_requests (tenant_id, instance_id, requested_by_membership_id, method, target_membership_id,
                                 device_label, requested_tags, ephemeral, reusable, status, requested_ttl_minutes)
VALUES (sqlc.arg(tenant_id), sqlc.arg(instance_id), sqlc.arg(requested_by_membership_id), sqlc.arg(method),
        sqlc.narg(target_membership_id), sqlc.narg(device_label), sqlc.arg(requested_tags), sqlc.arg(ephemeral),
        sqlc.arg(reusable), sqlc.arg(status), sqlc.narg(requested_ttl_minutes))
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
-- api: mọi cột trạng thái (quyền UPDATE cột của mg_api_tenant — 0020, 0028); nội dung được duyệt (người yêu cầu, chủ thiết
-- bị, phương thức, nhãn, tag, cờ key) không có ở đây — bất biến ở DB. Người quyết định: membership hoặc support grant
-- (0028 — đúng một khi đã quyết định). version tăng ở mọi lần ghi.
UPDATE enrollment_requests
SET status                 = sqlc.arg(status),
    approver_membership_id = sqlc.narg(approver_membership_id),
    approver_support_grant_id = sqlc.narg(approver_support_grant_id),
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

-- name: LockLiveSupportGrant :one
-- Quyết định của support actor (0028 — §8.6 ô G của tenant.enrollment:approve, §8.7): grant của CHÍNH người gọi vào
-- tenant còn hiệu lực ở lúc quyết định (approved ∧ starts_at ≤ now() < expires_at — như kiểm của WithTenantTx), khóa FOR
-- SHARE tới hết transaction: một lần thu hồi/hết hạn đã commit ⇒ không hàng (EvalPlanQual đọc lại bản mới), một lần
-- đang chạy ⇒ chờ rồi đọc lại; thu hồi đến sau chờ quyết định commit. Pool tenant: RLS (tenant_id = app.tenant_id) +
-- quyền UPDATE cột của 0023 (FOR SHARE cần quyền UPDATE trên một cột).
SELECT id FROM support_access_grants
WHERE tenant_id = sqlc.arg(tenant_id) AND id = sqlc.arg(id) AND grantee_platform_user_id = sqlc.arg(grantee)
  AND status = 'approved' AND starts_at <= now() AND expires_at > now()
FOR SHARE;

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

-- name: LiveDevicesOfMachineKey :many
-- Sổ thiết bị: mọi hàng sống của một machine key trên instance — §7.4 bước 8. Hàng của CHÍNH node AuthRegister trả về
-- (cùng headscale_node_id) cho biết node đã có trong sổ; hàng của node KHÁC cùng machine key (node của user khác — với
-- user khác Headscale tạo node MỚI, V-28) không làm node vừa tạo thành "đã có", nhưng một lần re-auth chỉ được chấp
-- nhận khi mọi hàng của máy đều thuộc chính thành viên.
SELECT * FROM device_inventory_cache
WHERE tenant_id = sqlc.arg(tenant_id) AND instance_id = sqlc.arg(instance_id) AND machine_key = sqlc.arg(machine_key)
  AND removed_at IS NULL
ORDER BY first_seen_at DESC, id DESC;

-- name: LiveDeviceIDsOfMember :many
-- Claim (§7.4 bước 8), trong transaction ghi claimed — TRƯỚC AuthRegister: các hàng sống của thành viên trên instance.
-- Hàng của node AuthRegister trả về chỉ chứng minh node có từ trước claim khi nó có trong tập này: hàng một
-- inventory.sync đồng thời chèn sau đó (snapshot liệt kê node vừa tạo) không làm node mới thành "đã có" — không phụ
-- thuộc đồng hồ của Headscale (created_at của node).
SELECT id FROM device_inventory_cache
WHERE tenant_id = sqlc.arg(tenant_id) AND instance_id = sqlc.arg(instance_id)
  AND owner_membership_id = sqlc.arg(member) AND removed_at IS NULL;

-- name: ClaimRejectionsOfNode :many
-- Claim (§7.4 bước 8): phán quyết của những claim trước về node này (id + machine key) SAU khi nó được tạo —
-- node_mismatch (lẽ ra đã bị xóa: DeleteNode không thành) hay foreign_node (đã expire) — và các claim không bao giờ tới
-- phán quyết với node MỚI (tạo từ lúc tạo yêu cầu đó): claim_unfinished (claim không ghi được registered, hay reconcile
-- đóng yêu cầu kẹt ở claimed/registered — tiến trình dừng, ghi phán quyết lỗi). claim_unfinished chỉ tính như
-- node_mismatch khi node không qua kiểm bước 8 của CHÍNH yêu cầu đó (priorVerdicts — Go: hostname đã ghi phải là
-- mg-<mã> khớp enroll_code_hash của yêu cầu, node của người yêu cầu, không tag, CLI): node hợp lệ của một claim dừng
-- sau khi ghi registered là thiết bị của người yêu cầu — không bao giờ bị xóa hay bị từ chối khi re-auth. Node đã bị
-- từ chối không bao giờ được chấp nhận như một lần re-auth. updated_at của yêu cầu failed là lúc từ chối (trạng thái
-- cuối, không ghi lại); id node được cấp lại cho node mới cùng machine key thì node mới có created_at muộn hơn và không
-- bị tính. record_failed (ghi verified lỗi) không được tính: node đó đã qua kiểm.
SELECT failure_code, reported_hostname, enroll_code_hash, requested_by_membership_id
FROM enrollment_requests
WHERE tenant_id = sqlc.arg(tenant_id) AND instance_id = sqlc.arg(instance_id) AND method = 'web_auth'
  AND status = 'failed' AND consumed_node_id = sqlc.arg(node_id) AND registered_machine_key = sqlc.arg(machine_key)
  AND updated_at >= sqlc.arg(node_created_at)::timestamptz - interval '1 second'
  AND (failure_code IN ('node_mismatch', 'foreign_node')
       OR failure_code = 'claim_unfinished' AND sqlc.arg(node_created_at)::timestamptz >= created_at - interval '1 second');

-- name: ListMemberWebAuthClaims :many
-- Claim khi câu trả lời của AuthRegister bị mất (§13.4 quy tắc 3 — đọc lại, không gửi lại): các yêu cầu web-auth KHÁC
-- của cùng thành viên trên instance đã claim (claimed/registered: thiết bị của nó tên mg-<mã của nó>) hoặc đã có node
-- (registered/verified: consumed_node_id) — node của chúng không phải node mà claim này có thể đã tạo. any_status
-- (reconcile của claim kẹt ở claimed — C1, sau ≥ 15 phút): mọi yêu cầu web-auth khác của thành viên, mọi trạng thái
-- (cả yêu cầu đã kết thúc với node hợp lệ của nó, hay chờ claim với mã của nó).
SELECT id, status, enroll_code_hash, consumed_node_id FROM enrollment_requests
WHERE tenant_id = sqlc.arg(tenant_id) AND instance_id = sqlc.arg(instance_id) AND method = 'web_auth'
  AND requested_by_membership_id = sqlc.arg(member) AND id <> sqlc.arg(id)
  AND (sqlc.arg(any_status)::boolean OR status IN ('claimed', 'registered', 'verified'));

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

-- name: CountPendingEnrollmentLinks :one
-- worker (lịch enrollment.reconcile): số hàng sổ thiết bị mà LinkConsumedEnrollmentDevices sẽ gắn liên kết — cùng điều
-- kiện. inventory.sync ghi hàng của node SAU khi yêu cầu đã kết thúc (consumed/verified — node id dùng lại) ⇒ lịch vẫn
-- chạy reconcile một lượt để gắn (và thông báo device.new cho pre-auth key), dù tenant không còn yêu cầu mở.
SELECT count(*) FROM device_inventory_cache d
JOIN enrollment_requests r ON r.tenant_id = d.tenant_id AND r.instance_id = d.instance_id
  AND r.consumed_node_id = d.headscale_node_id
WHERE d.tenant_id = sqlc.arg(tenant_id) AND d.removed_at IS NULL AND d.enrollment_request_id IS NULL
  AND (r.registered_machine_key IS NULL OR d.machine_key = r.registered_machine_key)
  AND r.status IN ('consumed', 'verified') AND r.updated_at > now() - interval '7 days';

-- name: LinkConsumedEnrollmentDevices :many
-- worker: thiết bị đăng ký bằng key một lần (consumed) hoặc web-auth (verified) mà sổ đã có nhưng chưa có liên kết
-- enrollment — gắn liên kết (dữ liệu authoritative, §6.3). Chỉ yêu cầu kết thúc trong 7 ngày gần nhất. Trả hàng vừa
-- gắn kèm phương thức của yêu cầu: hàng của pre-auth key được thông báo device.new đúng lần gắn này (P4-T06). Hàng
-- phải mang đúng machine key node đã đăng ký (registered_machine_key): hàng cũ của một node id dùng lại (machine key
-- khác) không bao giờ nhận liên kết của yêu cầu mới.
UPDATE device_inventory_cache d
SET enrollment_request_id = r.id
FROM enrollment_requests r
WHERE d.tenant_id = sqlc.arg(tenant_id) AND r.tenant_id = sqlc.arg(tenant_id) AND d.instance_id = r.instance_id
  AND d.headscale_node_id = r.consumed_node_id AND d.removed_at IS NULL AND d.enrollment_request_id IS NULL
  AND (r.registered_machine_key IS NULL OR d.machine_key = r.registered_machine_key)
  AND r.status IN ('consumed', 'verified') AND r.updated_at > now() - interval '7 days'
RETURNING d.id, d.owner_membership_id, d.name, d.given_name, d.hs_created_at, r.method;
