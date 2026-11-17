-- Seed gói tối thiểu (P3-T06) — viết tay. store.Migrate áp file này sau migration (cùng transaction với rbac.sql, bằng
-- mg_migrator, theo thứ tự tên file). Khác rbac.sql (đồng bộ đúng nội dung file ở mỗi lần chạy): gói là dữ liệu chủ dự
-- án chỉnh được qua /platform/plans (P4-T03a), nên seed CHỈ CHÈN khi chưa có gói cùng key — không bao giờ ghi đè limits,
-- tên hay is_active đã có; gói bị xóa tay (chỉ mg_migrator xóa được) được chèn lại ở lần migrate sau.
--
-- Gói `standard` — gói mặc định của MVP (TenantCreate.plan_key — §13.3). Khóa theo PlanLimits (§13.3), kiểm bởi CHECK
-- mg_plan_limits_valid (0012). Giá trị khởi đầu, chủ dự án chỉnh được — KHÔNG phải số đo năng lực (§5.5: chưa công bố giới
-- hạn số node trước khi có số liệu đo):
--   max_devices 100                     — HS-23: upstream ước lượng "100s of devices" cho một tailnet ít biến động
--   max_users 100                       — trần ≤ max_devices (mỗi người dùng có ít nhất một thiết bị)
--   max_tagged_devices 25               — thiết bị gắn tag (server/router/exit) là phần nhỏ của tailnet — ASSUMED
--   max_live_enrollment_credentials 25  — pre-auth key/mã enrollment còn hạn cùng lúc (key một lần, ≤ 15 phút — T-06) — ASSUMED
--   backup_interval_minutes 60          — §17.1: SQLite của tenant "1 giờ → 15 phút (theo plan)"; MVP 1 giờ
--   instance {cpus 1, memory_mb 512, pids 256} — đúng tham số container của tenant A/B hiện chạy (P1-T07, §14.5)
-- Trần số tenant toàn nền tảng không thuộc plan: system_settings quota.max_tenants (0012).

INSERT INTO subscription_plans (key, name, limits)
VALUES ('standard', 'Standard (MVP)',
        '{"max_devices": 100, "max_users": 100, "max_tagged_devices": 25, "max_live_enrollment_credentials": 25,
          "backup_interval_minutes": 60, "instance": {"cpus": 1, "memory_mb": 512, "pids": 256}}')
ON CONFLICT (key) DO NOTHING;
