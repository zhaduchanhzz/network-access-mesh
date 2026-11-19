-- 0027 — Hạn pre-auth key người yêu cầu xin, giữ qua bước duyệt (P4-T06 follow-up, §7.4). Số 0027 theo phân công của
-- người điều phối cho lượt sửa này; đánh số lại khi gộp nếu cần.
-- Một yêu cầu `preauth_key` phải chờ duyệt (`requires_approval`) được tạo không credential; key chỉ được phát ở
-- `/start`, có khi nhiều giờ sau. Không có cột này thì `ttl_minutes` của request bị bỏ và `/start` luôn phát key hạn tối
-- đa (15 phút hoặc `preauth_key_ttl_max`) — dài hơn điều người yêu cầu xin. Cột ghi lúc tạo, KHÔNG cấp UPDATE cho role
-- nào (bất biến như phần còn lại của nội dung được duyệt — quyền cột của 0020); `/start` dùng nó, vẫn kẹp theo
-- `preauth_key_ttl_max` hiện hành. NULL = không xin (mặc định 15 phút); chỉ pre-auth key mang giá trị.
-- Forward-only, expand-only: cột mới NULL ở mọi hàng có sẵn (đúng nghĩa cũ: hạn mặc định).

-- +goose Up
ALTER TABLE enrollment_requests
    ADD COLUMN requested_ttl_minutes smallint CHECK (requested_ttl_minutes BETWEEN 1 AND 15),
    ADD CONSTRAINT enrollment_requests_ttl_method_check CHECK (method = 'preauth_key' OR requested_ttl_minutes IS NULL);
