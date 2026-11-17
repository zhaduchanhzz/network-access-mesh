-- P2-T05b — chạy MỘT lần khi idp-db khởi tạo data dir (entrypoint của image postgres, sau 10-keycloak-db.sql).
-- Role idp_backup của dịch vụ idp-backup (project mg-backup): CHỈ ĐỌC — pg_read_all_data (SELECT mọi bảng/sequence và
-- USAGE mọi schema, kể cả bảng Keycloak tạo sau này khi nâng cấp), CONNECT vào DB keycloak, mặc định read-only;
-- KHÔNG superuser/CREATEDB/CREATEROLE/REPLICATION/BYPASSRLS (Keycloak không dùng RLS), không TEMPORARY (10-… đã
-- REVOKE ALL ON DATABASE keycloak FROM PUBLIC). Mật khẩu đọc từ Docker secret ngay trong psql như 10-keycloak-db.sql —
-- không qua tham số dòng lệnh hay biến môi trường; tắt ghi câu lệnh lỗi vào log.
-- idp-db đã khởi tạo từ trước (data dir có sẵn): chạy file này một lần bằng tay — docs/operations/backup-restore.md.
SET log_min_error_statement = 'panic';
SET log_statement = 'none';
\set pw `cat /run/secrets/idp_backup_db_password`
CREATE ROLE idp_backup LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'pw';
\unset pw
GRANT pg_read_all_data TO idp_backup;
GRANT CONNECT ON DATABASE keycloak TO idp_backup;
ALTER ROLE idp_backup SET default_transaction_read_only = on;
