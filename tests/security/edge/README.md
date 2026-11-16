# Edge conformance (P1-T10a)

> **File viết tay.** Bộ kiểm conformance của edge theo §14.6 của [bản master](../../../docs/planning/implementation-master-plan.md). Chạy lại mỗi khi `infrastructure/caddy/**` hoặc template instance đổi. Bằng chứng: [P1-T10.md](../../../docs/planning/evidence/P1-T10.md).

| File | Vai trò |
|---|---|
| `run_staging.sh` | Điều phối trên host staging: network tenant giả + upstream giả, container giữ netns trên `mg-edge`/`mg-admin`/`mg-obs`, chạy các nhóm kiểm, thử API key thật (hạn 1 giờ, expire ngay), dừng tenant giả, dọn sạch |
| `conformance.py` | Các nhóm kiểm `public`, `admin`, `metrics`, `unreachable`, `real-api`, `stopped` (thư viện chuẩn Python) |
| `echo_upstream.py` | "Headscale" giả trên cổng 8080/9090: ghi lại method, path, header của mọi request tới nó |

```bash
# trên host staging (cần quyền root: nsenter, đọc file token)
sudo bash tests/security/edge/run_staging.sh mesh.<domain> <public_entry_ipv4> tenant-a tenant-b
```

Không in giá trị secret nào: token admin/metrics được đọc từ file, API key thật nằm trong file tmpfs chỉ root đọc được trong lúc chạy; log của upstream giả bị xóa khi kết thúc (nếu edge lỡ không gỡ token, log đó chứa token).
