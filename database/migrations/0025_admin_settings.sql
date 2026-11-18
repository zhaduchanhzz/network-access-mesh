-- 0025 — Quản trị nền tảng và thiết lập của tenant (P4-T03a; §6.3 platform_users "status — tập giá trị chốt ở P4-T03a",
-- §6.1 "audit cùng transaction với thay đổi", §8.6 phê duyệt trong tenant). Số tạm 0025 (sau 0024 của P4-T09; bản đồ
-- §6.3 dời usage của P6-T11 sang 0026). Forward-only, expand-only: không bảng mới, không đổi dữ liệu.
--
-- platform_users.status:
--   active    — dùng được (Authorizer chỉ nhận platform user active — §8.8 lớp 1);
--   disabled  — PATCH {"status":"disabled"} hoặc DELETE /platform/users/{id}: mọi session của identity bị thu hồi cùng
--               transaction, không quyết định nào còn nhận người đó; PATCH {"status":"active"} mở lại. Hàng không bao
--               giờ bị xóa (UNIQUE identity_id, audit tham chiếu id).
-- CHECK kiểm trên heap nên áp lên mọi hàng có sẵn (bootstrap-super-admin chỉ ghi 'active'); giá trị khác ⇒ migration
-- thất bại nguyên khối.
--
-- Quyền cột cho pool tenant (mg_api_tenant) — các thao tác của tenant ghi đúng hàng của chính tenant (RLS
-- tenants_tenant / identity_providers_tenant: id/tenant_id = app_tenant_id()) TRONG transaction tenant, cùng
-- transaction với sự kiện audit của tenant (RLS audit_events: transaction tenant chỉ nhận sự kiện của chính tenant):
--   tenants (settings, updated_at, version)
--       PATCH /tenants/{t}/settings, PUT /tenants/{t}/settings/security và việc thực thi yêu cầu phê duyệt phạm vi
--       tenant của thao tác đó (approvals.Execute chạy trong WithTenantJobTx). Trước 0025 chỉ pool platform ghi được
--       cột này — mà transaction platform không ghi được audit của tenant.
--   identity_providers (client_secret_ref, required_claims, allowed_email_domains, claim_mapping, updated_at, version)
--       PATCH /tenants/{t}/identity-provider (Tenant Owner) và việc thực thi một thay đổi do nền tảng khởi xướng lên
--       hàng IdP của tenant đã được hai Super Admin duyệt (audit + thông báo hiển thị cho tenant). issuer, client_id,
--       driver, scope, tenant_id, status, require_email_verified KHÔNG được cấp (bất biến / ngoài phạm vi MVP — §8.2).
--       CHECK chủ của client_secret_ref (0007) vẫn chặn reference của chủ khác.
-- mg_worker_tenant không được cấp gì: chỉ api ghi các cột này.

-- +goose Up

ALTER TABLE platform_users
    ADD CONSTRAINT platform_users_status_check CHECK (status IN ('active', 'disabled'));

GRANT UPDATE (settings, updated_at, version) ON tenants TO mg_api_tenant;

GRANT UPDATE (client_secret_ref, required_claims, allowed_email_domains, claim_mapping, updated_at, version)
    ON identity_providers TO mg_api_tenant;
