-- 0019 — Kết quả probe relay (P3-T05c, §10.6, §13.5 `relay.probe`): relay_regions.last_probe / last_probe_at = kết quả
-- của lần probe gần nhất ĐÃ GHI (job relay.probe của worker gọi Prober của P3-T03a: GET /derp/probe qua listener công
-- khai của edge + STUN binding tới điểm vào công khai) và đồng hồ DB lúc probe BẮT ĐẦU (checked_at của API). Cùng quy
-- ước với tenant_instances.last_health / last_health_at (P2-T13a): tài liệu chỉ gồm mã ổn định + số đo được (trạng thái
-- HTTP, mã lỗi của prober, thời gian), không thông điệp thô, không secret; probe bắt đầu sớm hơn không đè probe mới hơn;
-- version/updated_at của region (trạng thái quản trị) không đổi khi ghi probe. Số hiệu 0019 TẠM THỜI — người điều phối
-- đánh lại khi gộp (0016–0018 dành cho các task Phase 3 song song).
-- Expand-only: hai cột NULL-able + CHECK + quyền cột; không đổi truy vấn nào của bản đang chạy (bước 17 dùng
-- RETURNING * — thêm cột không đổi hành vi). Forward-only.

-- +goose Up

ALTER TABLE relay_regions
    ADD COLUMN last_probe    jsonb,
    ADD COLUMN last_probe_at timestamptz;

-- Có tài liệu ⇔ có thời điểm; tài liệu là một object JSON (nội dung do module relay kiểm khi đọc — bản ghi lạ ⇒
-- invalid_record, không bao giờ thành con số).
ALTER TABLE relay_regions
    ADD CONSTRAINT relay_regions_probe_pair CHECK ((last_probe IS NULL) = (last_probe_at IS NULL)),
    ADD CONSTRAINT relay_regions_probe_object CHECK (last_probe IS NULL OR jsonb_typeof(last_probe) = 'object');

-- Chỉ pool platform của worker ghi (job relay.probe); mọi pool đã đọc được bảng (0010).
GRANT UPDATE (last_probe, last_probe_at) ON relay_regions TO mg_worker_platform;
