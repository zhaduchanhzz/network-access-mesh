# Demo tham khảo: headscale-admin (repo R2) trên staging

> **File viết tay. Không thuộc kiến trúc.** Chủ dự án duyệt ngày 2026-11-16 ("Thực hiện luôn không cần sandbox") làm **ngoại lệ** của §25.1 quy tắc 6: chạy bản demo headscale-admin để xem UI tham khảo trước Phase 4. ADR-16 không đổi: Portal vẫn viết mới, chỉ port có chọn lọc từ R2 theo MIT. Bằng chứng và đánh giá: [ref-headscale-admin-demo.md](../../../docs/planning/evidence/ref-headscale-admin-demo.md).

| Thành phần | Chi tiết |
|---|---|
| Panel `mg-demo-panel` | headscale-admin 1.3.0, build từ mã nguồn commit `0a4ca5e` (Dockerfile của repo, `node:22-alpine` pin theo digest). Chỉ nằm trong network internal `mg-demo-int` (không ra Internet, không Docker socket, không publish cổng). Chạy non-root, rootfs read-only, `cap_drop: ALL` |
| Proxy `mg-demo-proxy` | Image edge của dự án (Caddy), non-root. Nối `mg-demo-int` với `mg-admin`, gắn token nội bộ của listener admin và **ghim instance `tenant-c`** ([Caddyfile](Caddyfile)) |
| Tenant | `tenant-c` — tenant demo riêng ([tham số](../../environments/staging/tenants/tenant-c.json)). Panel chỉ có API key của tenant này, hạn 168 giờ. A/B không bị đụng tới |
| Secret | `/opt/meshguard/demo/r2/` (root 0700): `panel.env` (master key, session secret, API key — panel chỉ đọc được qua biến môi trường, đây là độ lệch so với chuẩn của dự án); bản sao token nội bộ cho proxy. Sinh trên host, không in ra |

```bash
# dựng (trên host staging; thư mục chứa Caddyfile và up.sh)
sudo bash up.sh <thư mục>
# xem UI từ máy có SSH key của dự án — không cần mở firewall hay publish cổng
ssh -i ~/.ssh/id_ed25519_meshguard -N -L 127.0.0.1:9080:10.249.250.3:3000 mgdeploy@192.168.1.8
#   rồi mở http://127.0.0.1:9080 (lần đăng nhập đầu: panel bắt đổi mật khẩu)
# gỡ
sudo bash down.sh [--with-tenant]
```
