-- 0023 — Support Access Grant và liên kết identity (bản đồ migration §6.3, P4-T05; §8.7): support_access_grants (T+P),
-- identity_links (T) + trigger kiểm người quyết định của grant.
-- Người dùng: support grant (P4-T13 — API phía tenant /tenants/{t}/support-grants và /platform/support-grants, job
-- grant.expire; kiểm "grant còn hiệu lực" của WithTenantTx với actor loại support — §6.1 hàng Platform scope; IT-17);
-- identity_links: bảng tạo sẵn, chưa dùng ở MVP — luồng liên kết thuộc P7-T06 (chưa cấp quyền cho role ứng dụng nào).
-- Forward-only, expand-only.

-- +goose Up

-- ---------------------------------------------------------------- support_access_grants (T+P)
-- Một yêu cầu của nhân sự nền tảng (requested_by_platform_user_id, thường chính là grantee) vào MỘT tenant với role hiệu
-- lực phạm vi support (support_operator / support_admin — cột Staff của §8.6; FK ghép (scope, key) → roles), lý do,
-- mã ticket, cửa sổ thời gian ≤ 8 giờ (§8.7). Grant luôn được tạo ở trạng thái pending; người quyết định:
--   approval_kind = tenant      ⇒ approved_by_membership_id: membership ĐANG HOẠT ĐỘNG của chính tenant đó (FK ghép) có
--                                 quyền tenant.support_grant:decide (duyệt hoặc từ chối — §8.6);
--   approval_kind = breakglass  ⇒ approved_by_platform_user_id: Super Admin đang hoạt động, khác người yêu cầu và khác
--                                 grantee; người yêu cầu cũng phải là Super Admin đang hoạt động ("hai Super Admin" —
--                                 §8.7 bước 2). Break-glass chỉ duyệt, không từ chối (từ chối là của tenant).
-- §6.3 ghi một cột approved_by_identity_id; ở đây người quyết định là membership (tenant) hoặc platform user (break-glass)
-- để mọi ràng buộc phạm vi là FK khai báo (IT-03: FK giữa bảng tenant luôn gắn tenant_id) — identity suy ra qua join.
-- Phần động (đang hoạt động, có quyền, là Super Admin) chỉ kiểm được lúc quyết định ⇒ trigger mg_support_grant_guard
-- (dưới). Trạng thái: pending → approved | rejected | revoked (rút lại) | expired; approved → revoked | expired; rejected,
-- revoked, expired là trạng thái cuối. Quyết định và cửa sổ thời gian không đổi được sau khi đã quyết định (gia hạn =
-- grant mới). "Còn hiệu lực" = approved ∧ starts_at ≤ now() < expires_at (revoked_at chỉ có ở revoked).
CREATE TABLE support_access_grants (
    id                            uuid        PRIMARY KEY DEFAULT uuidv7(),
    tenant_id                     uuid        NOT NULL REFERENCES tenants (id),
    grantee_platform_user_id      uuid        NOT NULL REFERENCES platform_users (id),
    requested_by_platform_user_id uuid        NOT NULL REFERENCES platform_users (id),
    effective_role_scope          text        NOT NULL DEFAULT 'support' CHECK (effective_role_scope = 'support'),
    effective_role_key            text        NOT NULL,
    reason                        text        NOT NULL CHECK (length(reason) BETWEEN 1 AND 1000),
    ticket_ref                    text        NOT NULL CHECK (length(ticket_ref) BETWEEN 1 AND 200),
    approval_kind                 text        CHECK (approval_kind IN ('tenant', 'breakglass')),
    approved_by_membership_id     uuid,
    approved_by_platform_user_id  uuid        REFERENCES platform_users (id),
    decided_at                    timestamptz,
    starts_at                     timestamptz NOT NULL DEFAULT now(),
    expires_at                    timestamptz NOT NULL,
    revoked_at                    timestamptz,
    status                        text        NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'revoked', 'expired')),
    created_at                    timestamptz NOT NULL DEFAULT now(),
    updated_at                    timestamptz NOT NULL DEFAULT now(),
    version                       bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    CHECK (expires_at > starts_at AND expires_at - starts_at <= interval '8 hours'),
    -- người quyết định đúng loại phê duyệt; chưa quyết định ⇒ không có người quyết định
    CHECK (approval_kind IS DISTINCT FROM 'tenant'
           OR (approved_by_membership_id IS NOT NULL AND approved_by_platform_user_id IS NULL)),
    CHECK (approval_kind IS DISTINCT FROM 'breakglass'
           OR (approved_by_platform_user_id IS NOT NULL AND approved_by_membership_id IS NULL)),
    CHECK (approval_kind IS NOT NULL OR (approved_by_membership_id IS NULL AND approved_by_platform_user_id IS NULL)),
    CHECK ((approval_kind IS NULL) = (decided_at IS NULL)),
    CHECK (status <> 'pending' OR approval_kind IS NULL),
    CHECK (status NOT IN ('approved', 'rejected') OR approval_kind IS NOT NULL),
    CHECK (status <> 'rejected' OR approval_kind = 'tenant'),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
    -- break-glass: người duyệt khác người yêu cầu và khác grantee
    CHECK (approved_by_platform_user_id <> requested_by_platform_user_id),
    CHECK (approved_by_platform_user_id <> grantee_platform_user_id),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (effective_role_scope, effective_role_key) REFERENCES roles (scope, key),
    FOREIGN KEY (tenant_id, approved_by_membership_id) REFERENCES tenant_memberships (tenant_id, id)
);
CREATE INDEX support_access_grants_tenant_created_idx ON support_access_grants (tenant_id, created_at DESC, id DESC);
CREATE INDEX support_access_grants_created_idx ON support_access_grants (created_at DESC, id DESC);  -- GET /platform/support-grants
CREATE INDEX support_access_grants_open_idx ON support_access_grants (expires_at)                  -- job grant.expire
    WHERE status IN ('pending', 'approved');
CREATE INDEX support_access_grants_grantee_live_idx ON support_access_grants (grantee_platform_user_id, tenant_id)
    WHERE status = 'approved';                                                                       -- grant đang hiệu lực của staff

-- Trigger kiểm (chạy với quyền và RLS của người gọi — SECURITY INVOKER): grant mới luôn pending; chuyển trạng thái chỉ
-- theo sơ đồ trên, quyết định + cửa sổ bất biến sau khi quyết định; lúc pending → approved/rejected, người quyết định phải
-- hợp lệ ở thời điểm đó. Phép tra đọc tenant_memberships/identities/role_permissions (pool tenant, đúng app.tenant_id
-- của grant) hoặc platform_users/roles/identities (pool platform); ngữ cảnh khác ⇒ RLS lọc mất hàng hoặc thiếu quyền đọc
-- ⇒ từ chối (fail closed): pool platform không duyệt kiểu tenant được, pool tenant không duyệt break-glass được.
-- Lỗi: 23514 (chuyển trạng thái / cửa sổ sai), 42501 (người quyết định không đủ điều kiện).
-- +goose StatementBegin
CREATE FUNCTION mg_support_grant_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'pending' THEN
      RAISE EXCEPTION 'support_access_grants: grant mới phải ở trạng thái pending (nhận %)', NEW.status
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.status <> 'pending' AND ROW(NEW.approval_kind, NEW.approved_by_membership_id, NEW.approved_by_platform_user_id,
                                     NEW.decided_at, NEW.starts_at, NEW.expires_at)
      IS DISTINCT FROM ROW(OLD.approval_kind, OLD.approved_by_membership_id, OLD.approved_by_platform_user_id,
                           OLD.decided_at, OLD.starts_at, OLD.expires_at) THEN
    RAISE EXCEPTION 'support_access_grants: quyết định và cửa sổ thời gian bất biến sau khi đã quyết định (%)', OLD.status
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.status IN ('rejected', 'revoked', 'expired')
     AND ROW(NEW.status, NEW.revoked_at) IS DISTINCT FROM ROW(OLD.status, OLD.revoked_at) THEN
    RAISE EXCEPTION 'support_access_grants: % là trạng thái cuối', OLD.status USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.status = 'approved' AND NEW.status NOT IN ('approved', 'revoked', 'expired') THEN
    RAISE EXCEPTION 'support_access_grants: approved → % không hợp lệ', NEW.status USING ERRCODE = 'check_violation';
  END IF;
  -- người quyết định chỉ được ghi bằng chính lần duyệt/từ chối (pending → revoked/expired không mang quyết định)
  IF OLD.status = 'pending' AND NEW.status IN ('revoked', 'expired') AND NEW.approval_kind IS NOT NULL THEN
    RAISE EXCEPTION 'support_access_grants: pending → % không mang quyết định', NEW.status USING ERRCODE = 'check_violation';
  END IF;

  IF OLD.status = 'pending' AND NEW.status IN ('approved', 'rejected') THEN
    IF NEW.status = 'approved' AND NEW.expires_at <= now() THEN
      RAISE EXCEPTION 'support_access_grants: không duyệt grant đã hết cửa sổ thời gian' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.approval_kind = 'tenant' THEN
      IF NOT EXISTS (
          SELECT 1
            FROM public.tenant_memberships m
            JOIN public.identities i ON i.id = m.identity_id
            JOIN public.role_permissions rp ON rp.role_id = m.role_id
           WHERE m.tenant_id = NEW.tenant_id AND m.id = NEW.approved_by_membership_id
             AND m.status = 'active' AND i.status = 'active'
             AND rp.permission_key = 'tenant.support_grant:decide' AND rp.scope = 'any' AND rp.condition IS NULL) THEN
        RAISE EXCEPTION 'support_access_grants: người quyết định không phải membership đang hoạt động có quyền tenant.support_grant:decide của tenant'
          USING ERRCODE = 'insufficient_privilege';
      END IF;
    ELSE  -- breakglass (CHECK: chỉ duyệt)
      IF (SELECT count(*)
            FROM public.platform_users pu
            JOIN public.identities i ON i.id = pu.identity_id
            JOIN public.roles r ON r.id = pu.role_id
           WHERE pu.id IN (NEW.approved_by_platform_user_id, NEW.requested_by_platform_user_id)
             AND pu.status = 'active' AND i.status = 'active' AND r.scope = 'platform' AND r.key = 'super_admin') <> 2 THEN
        RAISE EXCEPTION 'support_access_grants: break-glass cần hai Super Admin đang hoạt động (người yêu cầu ≠ người duyệt)'
          USING ERRCODE = 'insufficient_privilege';
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION mg_support_grant_guard() FROM PUBLIC;

CREATE TRIGGER support_access_grants_guard BEFORE INSERT OR UPDATE ON support_access_grants
    FOR EACH ROW EXECUTE FUNCTION mg_support_grant_guard();

-- ---------------------------------------------------------------- identity_links (T)
-- Chuyển membership khi tenant đổi IdP (§6.3, §8.2): identity cũ → identity mới của CÙNG tenant (FK ghép), thuộc hai IdP
-- khác nhau ((id, idp_id) → identities, UNIQUE của 0009); mỗi identity cũ liên kết một lần, mỗi identity mới nhận một
-- identity cũ. Người dùng phải chứng minh cả hai identity trong một phiên + step-up + audit (P7-T06). linked_by: tham
-- chiếu actor, không FK.
CREATE TABLE identity_links (
    tenant_id       uuid        NOT NULL REFERENCES tenants (id),
    old_identity_id uuid        NOT NULL,
    old_idp_id      uuid        NOT NULL,
    new_identity_id uuid        NOT NULL,
    new_idp_id      uuid        NOT NULL,
    linked_at       timestamptz NOT NULL DEFAULT now(),
    linked_by       uuid,
    PRIMARY KEY (tenant_id, old_identity_id),
    UNIQUE (tenant_id, new_identity_id),
    CHECK (old_identity_id <> new_identity_id),
    CHECK (old_idp_id <> new_idp_id),
    FOREIGN KEY (tenant_id, old_identity_id) REFERENCES identities (tenant_id, id),
    FOREIGN KEY (tenant_id, new_identity_id) REFERENCES identities (tenant_id, id),
    FOREIGN KEY (old_identity_id, old_idp_id) REFERENCES identities (id, idp_id),
    FOREIGN KEY (new_identity_id, new_idp_id) REFERENCES identities (id, idp_id)
);

-- ---------------------------------------------------------------- RLS
-- support_access_grants (T+P: tenant thấy grant vào chính mình — transparency §8.7; nền tảng thấy mọi grant) ·
-- identity_links (T)
ALTER TABLE support_access_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE support_access_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY support_access_grants_tenant ON support_access_grants TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());
CREATE POLICY support_access_grants_platform ON support_access_grants TO mg_app_platform
    USING (tenant_id = app_tenant_id() OR app_is_platform()) WITH CHECK (tenant_id = app_tenant_id() OR app_is_platform());

ALTER TABLE identity_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_links FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_links_tenant ON identity_links TO mg_app_tenant
    USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());

-- ---------------------------------------------------------------- quyền
-- Bất biến (không cấp UPDATE): id, tenant_id, grantee, người yêu cầu, role hiệu lực, lý do, ticket, created_at.
-- api platform: tạo yêu cầu (POST /platform/support-grants), duyệt break-glass, thu hồi (SA), rút lại. api tenant: duyệt,
-- từ chối, thu hồi (/tenants/{t}/support-grants/{id}/…). Mọi pool đọc: GET danh sách hai phía, kiểm grant còn hiệu lực
-- trong WithTenantTx của actor support (api và worker). worker platform: job grant.expire (P4-T13) và lệnh
-- post-restore-reconcile (P3-T17 — thu hồi grant đã duyệt, cho hết hạn yêu cầu chưa quyết định của bản dump): chỉ trạng
-- thái + mốc thu hồi. Không ai xóa (grant là bằng chứng của truy cập hỗ trợ — chưa có retention).
REVOKE ALL ON support_access_grants, identity_links FROM PUBLIC;
GRANT SELECT ON support_access_grants TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;
GRANT INSERT ON support_access_grants TO mg_api_platform;
GRANT UPDATE (status, approval_kind, approved_by_membership_id, decided_at, starts_at, expires_at, revoked_at, updated_at,
              version)
    ON support_access_grants TO mg_api_tenant;
GRANT UPDATE (status, approval_kind, approved_by_platform_user_id, decided_at, starts_at, expires_at, revoked_at, updated_at,
              version)
    ON support_access_grants TO mg_api_platform;
GRANT UPDATE (status, revoked_at, updated_at, version) ON support_access_grants TO mg_worker_platform;
-- identity_links: không cấp gì cho role ứng dụng cho tới P7-T06.
