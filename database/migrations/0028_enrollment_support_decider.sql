-- 0028 — Người quyết định một yêu cầu enrollment có thể là nhân viên nền tảng qua Support Access Grant (P4-T06/C4 — quyết
-- định của chủ dự án 2026-11-19; §8.6 ô G của tenant.enrollment:approve ở cột Staff, §8.7).
-- Trước 0028, mọi quyết định (duyệt hoặc từ chối) ghi approver_membership_id — CHECK + FK ghép tới tenant_memberships của
-- 0020 — nên staff (không có membership trong tenant) bị handler từ chối 403 support_actor_not_member. Cột mới
-- approver_support_grant_id ghi grant mà staff dùng để quyết định (FK ghép (tenant_id, id) tới support_access_grants của
-- 0023: chỉ grant vào CHÍNH tenant của yêu cầu); người quyết định là ĐÚNG MỘT trong hai cột khi có quyết định:
--   * approved_at có giá trị (đã duyệt — kể cả các trạng thái sau đó: issued, claimed, …) ⇒ đúng một người quyết định;
--   * rejected ⇒ đúng một người quyết định, không approved_at;
--   * requested / pending_approval ⇒ không người quyết định nào (0020 đã ép cho approver_membership_id);
--   * không bao giờ cả hai.
-- Grant "còn hiệu lực" (approved ∧ starts_at ≤ now() < expires_at, đúng grantee) ở lúc quyết định là phần động — kiểm ở
-- module enrollment trong CHÍNH transaction ghi quyết định (khóa FOR SHARE hàng grant: một lần thu hồi đồng thời hoặc đã
-- commit trước ⇒ từ chối, hoặc chờ quyết định commit), như mọi thao tác ghi của support actor (store.ErrSupportGrantNotLive).
-- Grant không bao giờ bị xóa (0023) ⇒ FK không ON DELETE. "Người quyết định ≠ người yêu cầu" của 0020 giữ nguyên cho
-- membership; staff không bao giờ là người yêu cầu (tạo yêu cầu cần membership).
-- Quyền cột (mẫu 0020/0023/0026): chỉ mg_api_tenant được ghi cột mới (duyệt/từ chối là của api); worker không ghi người
-- quyết định. RLS của bảng (T) không đổi.
--
-- Forward-only, expand-only: cột mới NULL ở mọi hàng có sẵn (nghĩa cũ: người quyết định là membership) ⇒ FK không có giá
-- trị nào để kiểm. Hai CHECK không tên của 0020 cấm quyết định không có membership — "approved_at ⇒ approver_membership_id"
-- và "rejected ⇒ approver_membership_id" — được thay bằng dạng "đúng một trong hai" (mọi hàng hợp lệ trước 0028 vẫn hợp lệ:
-- cột mới NULL). Tên PostgreSQL tự đặt cho chúng (enrollment_requests_check7, _check10 — thứ tự CHECK nhiều cột của 0020)
-- được kiểm cùng định nghĩa trước khi xóa: tên lệch ⇒ migration dừng nguyên khối, không xóa nhầm ràng buộc khác.

-- +goose Up

ALTER TABLE enrollment_requests ADD COLUMN approver_support_grant_id uuid;

-- +goose StatementBegin
DO $$
DECLARE
  want CONSTANT text[][] := ARRAY[
    ['enrollment_requests_check7', 'CHECK (((approved_at IS NULL) OR (approver_membership_id IS NOT NULL)))'],
    ['enrollment_requests_check10',
     'CHECK (((status <> ''rejected''::text) OR ((approver_membership_id IS NOT NULL) AND (approved_at IS NULL))))']];
  got text;
BEGIN
  FOR i IN 1 .. array_length(want, 1) LOOP
    SELECT pg_get_constraintdef(c.oid) INTO got FROM pg_catalog.pg_constraint c
     WHERE c.conrelid = 'public.enrollment_requests'::regclass AND c.conname = want[i][1] AND c.contype = 'c';
    IF got IS DISTINCT FROM want[i][2] THEN
      RAISE EXCEPTION '0028: ràng buộc % của enrollment_requests là % — chờ %', want[i][1], coalesce(got, '(không có)'), want[i][2]
        USING ERRCODE = 'object_not_in_prerequisite_state';
    END IF;
  END LOOP;
END
$$;
-- +goose StatementEnd

ALTER TABLE enrollment_requests
    DROP CONSTRAINT enrollment_requests_check7,
    DROP CONSTRAINT enrollment_requests_check10,
    -- người quyết định: không bao giờ cả membership lẫn support grant
    ADD CONSTRAINT enrollment_requests_one_decider_check
        CHECK (num_nonnulls(approver_membership_id, approver_support_grant_id) <= 1),
    -- thay "approved_at ⇒ approver_membership_id" (0020): đã duyệt ⇒ đúng một người quyết định
    ADD CONSTRAINT enrollment_requests_approved_decider_check
        CHECK (approved_at IS NULL OR num_nonnulls(approver_membership_id, approver_support_grant_id) = 1),
    -- thay "rejected ⇒ approver_membership_id, không approved_at" (0020)
    ADD CONSTRAINT enrollment_requests_rejected_decider_check
        CHECK (status <> 'rejected'
               OR (num_nonnulls(approver_membership_id, approver_support_grant_id) = 1 AND approved_at IS NULL)),
    -- chưa quyết định ⇒ không support grant (0020 đã ép cho membership)
    ADD CONSTRAINT enrollment_requests_undecided_grant_check
        CHECK (status NOT IN ('requested', 'pending_approval') OR approver_support_grant_id IS NULL),
    ADD CONSTRAINT enrollment_requests_approver_support_grant_fkey
        FOREIGN KEY (tenant_id, approver_support_grant_id) REFERENCES support_access_grants (tenant_id, id);

-- ---------------------------------------------------------------- quyền
-- api (duyệt/từ chối — SetEnrollmentRequestState ghi mọi cột trạng thái, nên cũng chép lại giá trị cột này ở các lần ghi
-- sau: /start, claim, /revoke). worker (SetEnrollmentRequestOutcome) không chạm người quyết định.
GRANT UPDATE (approver_support_grant_id) ON enrollment_requests TO mg_api_tenant;
