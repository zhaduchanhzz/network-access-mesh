-- 0007 — Chủ của client_secret_ref (G2 F3, rà soát bảo mật nội bộ vòng 1 — docs/planning/evidence/G2-security-review.md):
-- owner segment của identity_providers.client_secret_ref (mgsec://<owner>/<name>#<version>) phải là tenant_id của IdP,
-- hoặc "platform" khi tenant_id IS NULL. Ở 0002 cột chỉ CHECK định dạng, nên hàng IdP của tenant A có thể trỏ tới API key
-- Headscale của tenant B: callback sẽ giải mã key đó và gửi làm client_secret tới IdP của A, RemoveIssuer(purge) sẽ hủy
-- nó. Phần TÊN (idp.<idp id>.client hoặc idp-client-secret.<idp id>) do code kiểm (idp.Registration.OwnClientSecretRef,
-- ở callback và ở driver IdP) — DB chỉ kiểm chủ.
-- Expand-only: một CHECK, không ghi lại hàng nào, không đổi truy vấn nào của ứng dụng. Database đang có một tham chiếu sai
-- chủ không migrate được (goose chạy mỗi migration trong một transaction: dừng ở 0006) cho tới khi hàng đó được sửa — fail
-- closed có chủ đích. Số 0007 trùng chỗ bản đồ migration §6.3 dành cho P3-T06: có thể phải đánh số lại khi gộp.
-- Forward-only.

-- +goose Up

ALTER TABLE identity_providers
    ADD CONSTRAINT identity_providers_client_secret_ref_owner
    CHECK (client_secret_ref IS NULL
           OR starts_with(client_secret_ref, 'mgsec://' || COALESCE(tenant_id::text, 'platform') || '/'));
