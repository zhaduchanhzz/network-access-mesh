-- Quyền trên schema `river` của job queue (P2-T12, §6.1, §6.3). Bảng do rivermigrate tạo (owner mg_migrator) nên
-- quyền không thể nằm trong migration goose; store.MigrateQueue chạy file này bằng mg_migrator sau MỖI lần migrate
-- River (idempotent). Quyền cấp tường minh theo tên bảng — không default privileges (truy vấn CI
-- database/checks/partition_grants.sql báo mọi default privileges) —, nên bản River mới thêm bảng thì phải sửa file
-- này: TestMigrateQueue liệt kê mọi bảng của schema và fail khi gặp bảng chưa được xếp loại.
--
--   mg_worker_platform — River client của worker: lấy/hoàn tất job, bầu leader, rescue, lập lịch, job định kỳ, dọn dẹp.
--   mg_api_tenant, mg_api_platform, mg_worker_tenant — chỉ enqueue trong cùng transaction với thay đổi nghiệp vụ
--     (InsertTx): INSERT … ON CONFLICT (unique_key) DO UPDATE SET kind … RETURNING ⇒ SELECT, INSERT, UPDATE (kind).
--   Không role nào có TRUNCATE; mg_readonly, mg_audit_writer, mg_partition_maint không có quyền gì ở schema này.

REVOKE ALL ON SCHEMA river FROM PUBLIC;
GRANT USAGE ON SCHEMA river TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;

REVOKE ALL ON ALL TABLES IN SCHEMA river FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA river FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA river FROM PUBLIC;

-- river_migration chỉ dành cho mg_migrator (owner).
GRANT SELECT, INSERT, UPDATE, DELETE ON river.river_job, river.river_leader, river.river_queue, river.river_notification
    TO mg_worker_platform;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE river.river_job_id_seq, river.river_notification_id_seq TO mg_worker_platform;

GRANT SELECT, INSERT ON river.river_job TO mg_api_tenant, mg_worker_tenant, mg_api_platform;
GRANT UPDATE (kind) ON river.river_job TO mg_api_tenant, mg_worker_tenant, mg_api_platform;
GRANT USAGE ON SEQUENCE river.river_job_id_seq TO mg_api_tenant, mg_worker_tenant, mg_api_platform;

-- river_job_state_in_bitmask: điều kiện của unique index và mệnh đề ON CONFLICT của lệnh chèn.
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA river TO mg_api_tenant, mg_worker_tenant, mg_api_platform, mg_worker_platform;
