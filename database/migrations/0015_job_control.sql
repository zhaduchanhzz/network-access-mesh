-- 0015 — Điều khiển job vòng đời (P3-T05, §11.3, §13.2 `POST /platform/jobs/{id}/retry|cancel|rollback`, §6.3):
-- cột provisioning_jobs.cancel_requested_at = thời điểm người vận hành gọi `/cancel` trên job ĐANG CHẠY — handler dừng
-- SAU step hiện tại rồi chuyển failed_resumable (không tự compensation); job chưa chạy (queued) chuyển thẳng cancelled
-- và cũng mang mốc này. `/retry` xóa mốc. Chỉ pool platform đặt/xóa được (người vận hành gọi qua Platform Console; worker
-- đọc). Số hiệu 0015 tạm thời — người điều phối có thể đánh số lại khi gộp (bản đồ §6.3).
-- Expand-only: một cột NULL-able + quyền cột, không đổi truy vấn nào của bản đang chạy. Forward-only.

-- +goose Up

ALTER TABLE provisioning_jobs ADD COLUMN cancel_requested_at timestamptz;

-- Mốc chỉ có nghĩa ở job đã từng nhận yêu cầu hủy; job chưa từng chạy không bao giờ mang mốc mà vẫn queued.
ALTER TABLE provisioning_jobs
    ADD CONSTRAINT provisioning_jobs_cancel_requested CHECK (cancel_requested_at IS NULL OR status <> 'queued');

GRANT UPDATE (cancel_requested_at) ON provisioning_jobs TO mg_api_platform, mg_worker_platform;
