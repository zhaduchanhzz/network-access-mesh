-- Bootstrap database của Management Plane (P2-T03, §6.1) — chạy bằng SUPERUSER của cụm PostgreSQL, kết nối vào
-- chính database `meshguard`, MỘT lần trước migration đầu tiên; chạy lại được (idempotent). Ví dụ:
--   docker exec -i <postgres> psql -U postgres -d meshguard -v ON_ERROR_STOP=1 < database/bootstrap/superuser.sql
-- hoặc store.Bootstrap() trong Go (test tích hợp dùng đường này).
--
-- Chỉ chứa phần role mg_migrator (CREATEROLE, KHÔNG superuser) không tự làm được:
--   * mg_migrator — owner của database (⇒ của schema public), chạy migration, tạo các role còn lại ở 0001/0004;
--   * mg_backup   — chỉ đọc + BYPASSRLS cho pg_dump của service pg-backup (P2-T03a): chỉ superuser cấp được
--                   BYPASSRLS; pg_read_all_data cho quyền SELECT trên mọi bảng/partition hiện có và tạo sau này.
-- KHÔNG đặt mật khẩu ở đây: role được tạo không mật khẩu (không đăng nhập được) cho tới khi bước triển khai đặt mật
-- khẩu từ file secret (database/README.md, mục "Mật khẩu role").

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mg_migrator') THEN
    CREATE ROLE mg_migrator LOGIN NOSUPERUSER NOCREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
  END IF;
  ALTER ROLE mg_migrator LOGIN NOSUPERUSER NOCREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;

  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mg_backup') THEN
    CREATE ROLE mg_backup LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS;
  END IF;
  ALTER ROLE mg_backup LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS;

  EXECUTE format('ALTER DATABASE %I OWNER TO mg_migrator', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO mg_backup', current_database());
END
$$;

GRANT pg_read_all_data TO mg_backup;
ALTER ROLE mg_backup SET default_transaction_read_only = on;
