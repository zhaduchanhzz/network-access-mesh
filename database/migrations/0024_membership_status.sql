-- 0024 — Trạng thái membership và tra job theo tài nguyên (P4-T09, §6.3 tenant_memberships "status — tập giá trị chốt ở
-- P4-T09", §8.2 vòng đời danh tính, §13.2 users). Forward-only, expand-only: không đổi dữ liệu.
--
-- tenant_memberships.status:
--   active      — dùng được (authz chỉ nhận membership active — §8.8 lớp 1);
--   locked      — PATCH /users/{id} {"status":"locked"}: khóa truy cập Portal (session bị thu hồi), mở lại được bằng
--                 {"status":"active"}; KHÔNG chạm node của người đó (cắt mạng là offboard);
--   offboarded  — DELETE /users/{id}: trạng thái cuối (service không bao giờ đưa membership rời trạng thái này); job
--                 member.offboard expire node + pre-auth key của Headscale user mg-<membership_uuid> và vô hiệu user ở IdP
--                 do nền tảng host; identity bị disabled (không đăng nhập lại được). Đã dùng từ P3-T11 (kế hoạch
--                 reconcile sau restore: ListOffboardedHeadscaleUsers).
-- CHECK kiểm trên heap (không qua RLS) nên áp lên mọi hàng có sẵn; giá trị khác ⇒ migration thất bại nguyên khối.
--
-- provisioning_jobs (tenant_id, resource_type, resource_id, created_at DESC, id DESC): trạng thái hai pha của offboard
-- (pending/applied/failed — như thu hồi thiết bị, T-17) là trạng thái của job member.offboard mới nhất của membership
-- (resource membership/<id>), đọc kèm mỗi hàng của GET /users — index giữ phép tra này theo tài nguyên, không quét job của
-- cả tenant.

-- +goose Up

ALTER TABLE tenant_memberships
    ADD CONSTRAINT tenant_memberships_status_check CHECK (status IN ('active', 'locked', 'offboarded'));

CREATE INDEX provisioning_jobs_resource_idx ON provisioning_jobs (tenant_id, resource_type, resource_id, created_at DESC, id DESC)
    WHERE resource_type IS NOT NULL;
