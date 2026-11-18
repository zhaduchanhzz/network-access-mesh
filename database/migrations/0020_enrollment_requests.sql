-- 0020 — Yêu cầu thêm thiết bị (bản đồ migration §6.3, P4-T05; luồng §7.4): enrollment_requests (T) + FK ghép
-- device_inventory_cache (tenant_id, enrollment_request_id) → enrollment_requests (tenant_id, id) (cột tạo ở 0005 không
-- kèm FK; chú thích ở đó còn ghi "0012" theo bản đồ cũ — migration đã chạy là bất biến).
-- Người dùng: module enrollment (P4-T06: pre-auth key, web-auth claim, duyệt trước bước thiết bị, job
-- enrollment.reconcile), danh mục tag (P4-T15: requested_tags chỉ nhận tag có trong tenant_tags — kiểm ở service),
-- QuotaChecker (P3-T06a: credential/yêu cầu còn hạn), retention.sweep (180 ngày sau trạng thái cuối — §6.4).
-- Forward-only, expand-only: một bảng mới + một FK trên cột đang NULL ở mọi hàng (chưa module nào ghi cột này) — một DB
-- có giá trị mồ côi ở cột đó không migrate được cho tới khi sửa hàng đó.

-- +goose Up

-- ---------------------------------------------------------------- enrollment_requests (T — bảng nội bộ tenant)
-- Không lưu plaintext pre-auth key, Auth ID hay mã enrollment (§6.3): chỉ SHA-256 (32 byte) của Auth ID, của session id
-- Portal phát mã (ràng buộc "cùng phiên" của claim — §7.4 bước 6) và của mã enrollment một lần (đặt trong hostname
-- mg-<mã>); headscale_preauthkey_id là id số của key ở Headscale, không phải key.
-- Trạng thái (§7.4): web-auth requested → (pending_approval → approved | rejected) → awaiting_device → claimed →
-- registered → verified; pre-auth key requested → (pending_approval → approved | rejected) → credential_issued →
-- consumed; mọi trạng thái chưa kết thúc → expired | revoked | failed (kèm failure_code). Thứ tự chuyển do module
-- enrollment giữ; DB ép các bất biến của từng trạng thái:
--   * phê duyệt gắn với REQUEST (người yêu cầu, nhãn, phương thức, tag, cờ key) — các cột đó bất biến (không cấp UPDATE),
--     nên nội dung không đổi được sau khi duyệt; approver_membership_id = người quyết định (duyệt hoặc từ chối), khác
--     người yêu cầu; approved_at chỉ có khi đã duyệt;
--   * credential (mã + lệnh hoặc pre-auth key) chỉ tồn tại sau lúc phát (issued_at) và hết hạn không quá 15 phút sau đó
--     (T-06: không có enrollment credential vô thời hạn; cửa sổ web-auth 10 phút ⊂ giới hạn này);
--   * web-auth luôn là thiết bị của chính người yêu cầu (claim chỉ nhận yêu cầu của chính thành viên đó), không tag;
--     key chỉ-tag (không chủ) phải mang ít nhất một tag; reusable/ephemeral chỉ có ở pre-auth key.
-- Cột trạng thái do api (tạo, duyệt, phát, claim) và worker (reconcile: hết hạn, đã dùng, lỗi) ghi.
CREATE TABLE enrollment_requests (
    id                         uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id                  uuid        NOT NULL REFERENCES tenants (id),
    instance_id                uuid        NOT NULL,
    requested_by_membership_id uuid        NOT NULL,
    method                     text        NOT NULL CHECK (method IN ('web_auth', 'preauth_key', 'oidc')),
    target_membership_id       uuid,       -- chủ thiết bị; NULL = key chỉ-tag (§7.4 phương thức B)
    device_label               text        CHECK (length(device_label) BETWEEN 1 AND 100),
    -- tên tag theo cùng định dạng tenant_tags.name (0021); thuộc danh mục của tenant — kiểm ở service (P4-T15). Kiểm trên
    -- dạng văn bản của mảng: phần tử chỉ gồm [a-z0-9:-] không bao giờ được trích dẫn, nên phần tử NULL, rỗng, có dấu
    -- phẩy/ngoặc/khoảng trắng, mảng nhiều chiều hay chỉ số dưới khác 1 đều không khớp.
    requested_tags             text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(requested_tags) <= 64
        AND requested_tags::text ~ '^\{(tag:[a-z][a-z0-9-]{0,49}(,tag:[a-z][a-z0-9-]{0,49})*)?\}$'),
    ephemeral                  boolean     NOT NULL DEFAULT false,
    reusable                   boolean     NOT NULL DEFAULT false,
    status                     text        NOT NULL DEFAULT 'requested'
        CHECK (status IN ('requested', 'pending_approval', 'approved', 'rejected', 'awaiting_device', 'claimed', 'registered',
                          'verified', 'credential_issued', 'consumed', 'expired', 'revoked', 'failed')),
    approver_membership_id     uuid,
    approved_at                timestamptz,
    issued_at                  timestamptz,  -- lúc phát mã/lệnh hoặc pre-auth key (/issue, /start hoặc ngay khi tạo)
    headscale_preauthkey_id    bigint      CHECK (headscale_preauthkey_id > 0),
    auth_id_hash               bytea       CHECK (octet_length(auth_id_hash) = 32),
    session_id_hash            bytea       CHECK (octet_length(session_id_hash) = 32),
    enroll_code_hash           bytea       CHECK (octet_length(enroll_code_hash) = 32),
    claimed_at                 timestamptz,
    claimed_from_ip            inet,
    registered_machine_key     text        CHECK (length(registered_machine_key) BETWEEN 1 AND 200),
    reported_hostname          text        CHECK (length(reported_hostname) BETWEEN 1 AND 255),
    credential_expires_at      timestamptz,
    consumed_node_id           bigint      CHECK (consumed_node_id > 0),  -- id node ở Headscale đã đăng ký bằng yêu cầu này
    failure_code               text        CHECK (failure_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    created_at                 timestamptz NOT NULL DEFAULT now(),
    updated_at                 timestamptz NOT NULL DEFAULT now(),
    version                    bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    -- chủ thiết bị và tag theo phương thức
    CHECK (target_membership_id IS NOT NULL OR (method = 'preauth_key' AND cardinality(requested_tags) > 0)),
    CHECK (method <> 'web_auth' OR target_membership_id = requested_by_membership_id),
    CHECK (method = 'preauth_key' OR (cardinality(requested_tags) = 0 AND NOT ephemeral AND NOT reusable)),
    -- trạng thái riêng của từng phương thức
    CHECK (status NOT IN ('awaiting_device', 'claimed') OR method = 'web_auth'),
    CHECK (status NOT IN ('credential_issued', 'consumed') OR method = 'preauth_key'),
    CHECK (status NOT IN ('registered', 'verified') OR method IN ('web_auth', 'oidc')),
    -- phê duyệt: người quyết định ≠ người yêu cầu; chưa quyết định ⇒ chưa có gì; approved ⇒ có người + thời điểm
    CHECK (approver_membership_id <> requested_by_membership_id),
    CHECK (approved_at IS NULL OR approver_membership_id IS NOT NULL),
    CHECK (status NOT IN ('requested', 'pending_approval') OR (approver_membership_id IS NULL AND approved_at IS NULL)),
    CHECK (status <> 'approved' OR approved_at IS NOT NULL),
    CHECK (status <> 'rejected' OR (approver_membership_id IS NOT NULL AND approved_at IS NULL)),
    -- credential: chỉ sau lúc phát, hạn ≤ 15 phút (T-06); trạng thái từ lúc phát trở đi luôn có nó (trừ OIDC gốc)
    CHECK ((issued_at IS NULL) = (credential_expires_at IS NULL)),
    CHECK (credential_expires_at > issued_at AND credential_expires_at <= issued_at + interval '15 minutes'),
    CHECK (status NOT IN ('requested', 'pending_approval', 'approved', 'rejected') OR issued_at IS NULL),
    CHECK (method = 'oidc' OR status NOT IN ('awaiting_device', 'claimed', 'registered', 'verified', 'credential_issued',
                                              'consumed') OR issued_at IS NOT NULL),
    -- dấu vết theo phương thức: mã/Auth ID chỉ ở web-auth, key chỉ ở pre-auth key
    CHECK (method = 'web_auth' OR (auth_id_hash IS NULL AND enroll_code_hash IS NULL AND claimed_at IS NULL)),
    CHECK (method = 'preauth_key' OR headscale_preauthkey_id IS NULL),
    CHECK (method <> 'web_auth' OR issued_at IS NULL OR (enroll_code_hash IS NOT NULL AND session_id_hash IS NOT NULL)),
    CHECK (method <> 'web_auth' OR status NOT IN ('claimed', 'registered', 'verified')
           OR (claimed_at IS NOT NULL AND auth_id_hash IS NOT NULL)),
    CHECK (status NOT IN ('credential_issued', 'consumed') OR headscale_preauthkey_id IS NOT NULL),
    CHECK (status NOT IN ('registered', 'verified', 'consumed') OR consumed_node_id IS NOT NULL),
    CHECK (status <> 'failed' OR failure_code IS NOT NULL),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, instance_id) REFERENCES tenant_instances (tenant_id, id),
    FOREIGN KEY (tenant_id, requested_by_membership_id) REFERENCES tenant_memberships (tenant_id, id),
    FOREIGN KEY (tenant_id, target_membership_id) REFERENCES tenant_memberships (tenant_id, id),
    FOREIGN KEY (tenant_id, approver_membership_id) REFERENCES tenant_memberships (tenant_id, id)
);
-- Claim tra yêu cầu theo Auth ID / mã enrollment: mỗi giá trị trỏ đúng một yêu cầu của tenant.
CREATE UNIQUE INDEX enrollment_requests_auth_id_key ON enrollment_requests (tenant_id, auth_id_hash)
    WHERE auth_id_hash IS NOT NULL;
CREATE UNIQUE INDEX enrollment_requests_enroll_code_key ON enrollment_requests (tenant_id, enroll_code_hash)
    WHERE enroll_code_hash IS NOT NULL;
CREATE INDEX enrollment_requests_tenant_status_idx ON enrollment_requests (tenant_id, status);  -- quota, reconcile, hàng chờ duyệt
CREATE INDEX enrollment_requests_tenant_created_idx ON enrollment_requests (tenant_id, created_at DESC, id DESC);
CREATE INDEX enrollment_requests_requester_idx ON enrollment_requests (tenant_id, requested_by_membership_id);

-- ---------------------------------------------------------------- FK của cột tạo ở 0005
-- Liên kết enrollment của thiết bị là dữ liệu authoritative của nền tảng, giữ theo vòng đời tenant (§6.4) ⇒ không
-- ON DELETE: retention.sweep chỉ xóa được yêu cầu không còn thiết bị nào trỏ tới (hàng thiết bị removed bị xóa sau 90
-- ngày — sau đó yêu cầu mới xóa được).
-- Kiểm hàng có sẵn: ADD FOREIGN KEY kiểm mọi hàng hiện có bằng MỘT truy vấn chạy dưới quyền owner (mg_migrator), mà
-- FORCE ROW LEVEL SECURITY lọc hết hàng của owner (không có policy) ⇒ phép kiểm sẽ trống rỗng và một giá trị mồ côi lọt
-- qua (đã thử: TestMigrations0020To0023OnSchema19Data). Vì vậy tạm NO FORCE trên bảng tham chiếu trong cùng transaction
-- rồi FORCE lại (mẫu "migration dữ liệu" của database/README.md); bảng đích mới tạo, rỗng.
ALTER TABLE device_inventory_cache NO FORCE ROW LEVEL SECURITY;
ALTER TABLE device_inventory_cache
    ADD CONSTRAINT device_inventory_cache_enrollment_request_fkey
    FOREIGN KEY (tenant_id, enrollment_request_id) REFERENCES enrollment_requests (tenant_id, id);
ALTER TABLE device_inventory_cache FORCE ROW LEVEL SECURITY;
CREATE INDEX device_inventory_cache_enrollment_idx ON device_inventory_cache (tenant_id, enrollment_request_id)
    WHERE enrollment_request_id IS NOT NULL;

-- ---------------------------------------------------------------- RLS (T: không nhánh platform — §6.1)
ALTER TABLE enrollment_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollment_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY enrollment_requests_tenant ON enrollment_requests TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());

-- ---------------------------------------------------------------- quyền
-- Chỉ role tenant (bảng T). Bất biến (không cấp UPDATE): id, tenant_id, instance_id, requested_by_membership_id, method,
-- target_membership_id, device_label, requested_tags, ephemeral, reusable, created_at — nội dung được duyệt.
-- api: tạo, duyệt/từ chối, phát (/issue, /start), claim, thu hồi (P4-T06). worker: job enrollment.reconcile (hết hạn,
-- phát hiện key đã dùng / node đã đăng ký, lỗi) và retention 180 ngày.
REVOKE ALL ON enrollment_requests FROM PUBLIC;
GRANT SELECT, INSERT ON enrollment_requests TO mg_api_tenant;
GRANT UPDATE (status, approver_membership_id, approved_at, issued_at, headscale_preauthkey_id, auth_id_hash, session_id_hash,
              enroll_code_hash, claimed_at, claimed_from_ip, registered_machine_key, reported_hostname,
              credential_expires_at, consumed_node_id, failure_code, updated_at, version)
    ON enrollment_requests TO mg_api_tenant;
GRANT SELECT, DELETE ON enrollment_requests TO mg_worker_tenant;
GRANT UPDATE (status, registered_machine_key, reported_hostname, consumed_node_id, failure_code, updated_at, version)
    ON enrollment_requests TO mg_worker_tenant;
