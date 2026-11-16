-- P2-T05 — chạy MỘT lần khi idp-db khởi tạo data dir (entrypoint của image postgres, user postgres 999).
-- Keycloak dùng role riêng `keycloak`: KHÔNG superuser, chỉ sở hữu DB `keycloak` (đủ cho Liquibase tạo/nâng schema);
-- superuser `postgres` chỉ để bảo trì. Mật khẩu đọc từ Docker secret ngay trong psql (\set + backtick) — không qua
-- tham số dòng lệnh hay biến môi trường; tắt ghi câu lệnh lỗi vào log để mật khẩu không lọt ra log nếu có lỗi.
SET log_min_error_statement = 'panic';
SET log_statement = 'none';
\set pw `cat /run/secrets/idp_db_password`
CREATE ROLE keycloak LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'pw';
\unset pw
CREATE DATABASE keycloak OWNER keycloak ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE keycloak FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE keycloak TO keycloak;
