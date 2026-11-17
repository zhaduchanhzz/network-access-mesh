-- 0009 — Dual control, lời mời, outbox thông báo (bản đồ migration §6.3, P3-T06): approval_requests (T+P),
-- tenant_invitations (T), notification_outbox (T+P); thêm UNIQUE (id, idp_id) trên identities làm đích FK ghép của lời mời.
-- Người dùng: P3-T04a (approvals 2P), P3-T05a (lời mời), P3-T05b (notifications); retention 180/90 ngày (§6.4) do
-- retention.sweep của worker.
-- Expand-only: chỉ thêm bảng và một ràng buộc UNIQUE chứa khóa chính sẵn có của identities (không ghi lại hàng nào).
-- Forward-only.

-- +goose Up

-- ---------------------------------------------------------------- identities: đích FK ghép (id, idp_id)
-- Lời mời chỉ được nhận bởi identity của ĐÚNG IdP ghi trong lời mời (§6.3, P3-T05a): FK (accepted_identity_id, idp_id).
ALTER TABLE identities ADD CONSTRAINT identities_id_idp_key UNIQUE (id, idp_id);

-- ---------------------------------------------------------------- approval_requests (T+P)
-- Dual control (2P — §8.6). scope platform ⇔ tenant_id NULL (cùng mẫu với identity_providers/identities): yêu cầu 2P
-- của nền tảng về một tenant (xóa, restore…) mang đích ở (resource_type, resource_id) chứ không ở tenant_id, nên pool
-- tenant không bao giờ thấy nó (endpoint phạm vi tenant chỉ thấy scope tenant). Người yêu cầu/người duyệt ràng buộc bằng
-- FK ghép: identity cùng scope với yêu cầu ((id, scope) → identities) và, với yêu cầu tenant, cùng tenant
-- ((tenant_id, id) → identities) — identity của tenant không duyệt được yêu cầu platform và ngược lại; không tự duyệt
-- (CHECK). payload = tham số đã chuẩn hóa, không chứa secret, là đầu vào duy nhất của job; payload_sha256 (hex) tính
-- trên chính nó. payload, payload_sha256, người yêu cầu, đích, hạn là bất biến (role ứng dụng không có quyền UPDATE trên
-- các cột này). approved_by_identity_id + decided_at bắt buộc khi approved/executed; job_id chỉ ở executed (chuyển
-- executed + ghi job_id trong cùng transaction enqueue job); job bị retention xóa trước ⇒ job_id về NULL.
CREATE TABLE approval_requests (
    id                       uuid        PRIMARY KEY DEFAULT uuidv7(),
    scope                    text        NOT NULL CHECK (scope IN ('platform', 'tenant')),
    tenant_id                uuid        REFERENCES tenants (id),  -- NULL ⇔ scope platform
    action                   text        NOT NULL CHECK (action ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$' AND length(action) <= 100),
    resource_type            text        NOT NULL CHECK (resource_type ~ '^[a-z][a-z_]{0,31}$'),
    resource_id              text        CHECK (length(resource_id) BETWEEN 1 AND 128),
    payload                  jsonb       NOT NULL CHECK (jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 16384),
    payload_sha256           text        NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    requested_by_identity_id uuid        NOT NULL,
    approved_by_identity_id  uuid,
    decided_at               timestamptz,
    status                   text        NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'executed')),
    reason                   text        CHECK (length(reason) <= 1000),  -- lý do của người yêu cầu, hiển thị cho người duyệt
    expires_at               timestamptz NOT NULL,  -- mặc định 24 giờ (§8.6, cấu hình ở system_settings) — do ứng dụng đặt
    job_id                   uuid,
    created_at               timestamptz NOT NULL DEFAULT now(),
    CHECK ((scope = 'platform') = (tenant_id IS NULL)),
    CHECK (approved_by_identity_id <> requested_by_identity_id),  -- không tự duyệt
    CHECK (expires_at > created_at),
    CHECK (status <> 'pending' OR (decided_at IS NULL AND approved_by_identity_id IS NULL)),
    CHECK (status NOT IN ('approved', 'executed') OR (decided_at IS NOT NULL AND approved_by_identity_id IS NOT NULL)),
    CHECK (status <> 'rejected' OR decided_at IS NOT NULL),
    CHECK (job_id IS NULL OR status = 'executed'),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (requested_by_identity_id, scope) REFERENCES identities (id, scope),
    FOREIGN KEY (tenant_id, requested_by_identity_id) REFERENCES identities (tenant_id, id),
    FOREIGN KEY (approved_by_identity_id, scope) REFERENCES identities (id, scope),
    FOREIGN KEY (tenant_id, approved_by_identity_id) REFERENCES identities (tenant_id, id),
    -- yêu cầu platform (tenant_id NULL) vẫn trỏ được job của tenant đích; yêu cầu tenant chỉ trỏ job của chính tenant
    FOREIGN KEY (job_id) REFERENCES provisioning_jobs (id) ON DELETE SET NULL,
    FOREIGN KEY (tenant_id, job_id) REFERENCES provisioning_jobs (tenant_id, id) ON DELETE SET NULL (job_id)
);
CREATE INDEX approval_requests_tenant_created_idx ON approval_requests (tenant_id, created_at DESC, id DESC);
CREATE INDEX approval_requests_created_idx ON approval_requests (created_at DESC, id DESC);  -- GET /platform/approvals
CREATE INDEX approval_requests_open_idx ON approval_requests (expires_at)                  -- hết hạn, P3-T17
    WHERE status IN ('pending', 'approved');

-- ---------------------------------------------------------------- tenant_invitations (T)
-- Lời mời người chưa từng đăng nhập (§6.3, §8.2): membership chỉ được tạo khi một identity đăng nhập qua đúng IdP của
-- tenant ghi trong lời mời (FK ghép (idp_id, tenant_id) → identity_providers và (accepted_identity_id, idp_id) →
-- identities), có email đã xác minh trùng lời mời và đổi token còn hạn (kiểm ở service — P3-T05a). Chỉ lưu SHA-256 của
-- token. Role mời luôn phạm vi tenant (FK ghép như tenant_memberships). invited_by_identity_id: tham chiếu actor, không
-- FK (NULL = system — lời mời Owner ở bước tenant.configure, §11.3). idp_id, email, role, tenant bất biến.
CREATE TABLE tenant_invitations (
    id                     uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id              uuid        NOT NULL REFERENCES tenants (id),
    idp_id                 uuid        NOT NULL,
    email                  citext      NOT NULL CHECK (length(email::text) BETWEEN 3 AND 320 AND email::text ~ '^[^@[:space:]]+@[^@[:space:]]+$'),
    role_id                uuid        NOT NULL,
    role_scope             text        NOT NULL DEFAULT 'tenant' CHECK (role_scope = 'tenant'),
    invited_by_identity_id uuid,
    token_hash             bytea       NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at             timestamptz NOT NULL,
    status                 text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
    accepted_identity_id   uuid,
    accepted_at            timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    version                bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    CHECK (expires_at > created_at),
    CHECK ((status = 'accepted') = (accepted_identity_id IS NOT NULL)),
    CHECK ((status = 'accepted') = (accepted_at IS NOT NULL)),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (idp_id, tenant_id) REFERENCES identity_providers (id, tenant_id),
    FOREIGN KEY (role_id, role_scope) REFERENCES roles (id, scope),
    FOREIGN KEY (tenant_id, accepted_identity_id) REFERENCES identities (tenant_id, id),
    FOREIGN KEY (accepted_identity_id, idp_id) REFERENCES identities (id, idp_id)
);
CREATE UNIQUE INDEX tenant_invitations_pending_email_key ON tenant_invitations (tenant_id, email) WHERE status = 'pending';
CREATE INDEX tenant_invitations_tenant_created_idx ON tenant_invitations (tenant_id, created_at DESC, id DESC);
CREATE INDEX tenant_invitations_pending_expiry_idx ON tenant_invitations (expires_at) WHERE status = 'pending';

-- ---------------------------------------------------------------- notification_outbox (T+P)
-- Ghi cùng transaction với sự kiện gốc; job notification.send gửi và retry (P3-T05b). Không chứa secret. Người nhận là
-- một membership của chính tenant (FK ghép — in-portal + email theo identity), hoặc một địa chỉ email (lời mời: người
-- nhận chưa có membership), hoặc cả hai. tenant_id NULL = thông báo phạm vi platform (chỉ email, không membership).
-- status là trạng thái gửi; read_at chỉ cho thông báo in-portal của một membership.
CREATE TABLE notification_outbox (
    id                      uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id               uuid        REFERENCES tenants (id),
    recipient_membership_id uuid,
    recipient_email         citext      CHECK (length(recipient_email::text) BETWEEN 3 AND 320),
    kind                    text        NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$' AND length(kind) <= 100),
    payload                 jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 8192),
    status                  text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed', 'cancelled')),
    attempts                integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    sent_at                 timestamptz,
    read_at                 timestamptz,
    created_at              timestamptz NOT NULL DEFAULT now(),
    CHECK (recipient_membership_id IS NOT NULL OR recipient_email IS NOT NULL),
    CHECK (tenant_id IS NOT NULL OR recipient_membership_id IS NULL),
    CHECK ((status = 'sent') = (sent_at IS NOT NULL)),
    CHECK (read_at IS NULL OR recipient_membership_id IS NOT NULL),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, recipient_membership_id) REFERENCES tenant_memberships (tenant_id, id)
);
CREATE INDEX notification_outbox_recipient_idx ON notification_outbox (tenant_id, recipient_membership_id, created_at DESC, id DESC)
    WHERE recipient_membership_id IS NOT NULL;                                                     -- GET /tenants/{t}/notifications
CREATE INDEX notification_outbox_pending_idx ON notification_outbox (created_at) WHERE status = 'pending';  -- notification.send
CREATE INDEX notification_outbox_sent_idx ON notification_outbox (sent_at) WHERE sent_at IS NOT NULL;      -- retention 90 ngày

-- ---------------------------------------------------------------- RLS
-- approval_requests (T+P) · tenant_invitations (T — bảng nội bộ tenant, không nhánh platform) · notification_outbox (T+P)
ALTER TABLE approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY approval_requests_tenant ON approval_requests TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY approval_requests_platform ON approval_requests TO mg_app_platform
    USING (tenant_id = app_tenant_id() OR app_is_platform()) WITH CHECK (tenant_id = app_tenant_id() OR app_is_platform());

ALTER TABLE tenant_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_invitations_tenant ON tenant_invitations TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());

ALTER TABLE notification_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_outbox_tenant ON notification_outbox TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY notification_outbox_platform ON notification_outbox TO mg_app_platform
    USING (tenant_id = app_tenant_id() OR app_is_platform()) WITH CHECK (tenant_id = app_tenant_id() OR app_is_platform());

-- ---------------------------------------------------------------- quyền bảng
REVOKE ALL ON approval_requests, tenant_invitations, notification_outbox FROM PUBLIC;

-- api: tạo yêu cầu, duyệt/từ chối, chuyển executed + job_id khi enqueue (P3-T04a). worker: đọc (job kiểm yêu cầu đã
-- executed); pool platform của worker chuyển yêu cầu quá hạn sang expired (cả P3-T17) và xóa theo retention 180 ngày.
GRANT SELECT, INSERT ON approval_requests TO mg_api_tenant, mg_api_platform;
GRANT UPDATE (status, approved_by_identity_id, decided_at, job_id) ON approval_requests TO mg_api_tenant, mg_api_platform;
GRANT SELECT ON approval_requests TO mg_worker_tenant, mg_worker_platform;
GRANT UPDATE (status) ON approval_requests TO mg_worker_platform;
GRANT DELETE ON approval_requests TO mg_worker_platform;

-- api: mời, gửi lại (token + hạn mới), thu hồi, nhận lời mời (P3-T05a). worker: lời mời Owner ở bước tenant.configure
-- và thu hồi khi compensation (§11.3 bước 16), hết hạn, xóa theo retention 180 ngày (theo từng tenant).
GRANT SELECT, INSERT ON tenant_invitations TO mg_api_tenant, mg_worker_tenant;
GRANT UPDATE (token_hash, expires_at, status, accepted_identity_id, accepted_at, updated_at, version)
    ON tenant_invitations TO mg_api_tenant;
GRANT UPDATE (status, updated_at, version) ON tenant_invitations TO mg_worker_tenant;
GRANT DELETE ON tenant_invitations TO mg_worker_tenant;

-- mọi tiến trình ghi outbox cùng transaction với sự kiện; api tenant đánh dấu đã đọc (của chính người gọi — kiểm ở
-- service); worker gửi (status/attempts/sent_at) và xóa theo retention 90 ngày.
GRANT SELECT, INSERT ON notification_outbox TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;
GRANT UPDATE (read_at) ON notification_outbox TO mg_api_tenant;
GRANT UPDATE (status, attempts, sent_at) ON notification_outbox TO mg_worker_tenant, mg_worker_platform;
GRANT DELETE ON notification_outbox TO mg_worker_platform;
