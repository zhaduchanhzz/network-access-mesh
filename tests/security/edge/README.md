# Edge conformance (P1-T10a)

> **File viết tay.** Bộ kiểm conformance của edge theo §14.6 của [bản master](../../../docs/planning/implementation-master-plan.md). Chạy lại mỗi khi `infrastructure/caddy/**` hoặc template instance đổi. Bằng chứng: [P1-T10.md](../../../docs/planning/evidence/P1-T10.md).

| File | Vai trò |
|---|---|
| `run_staging.sh` | Điều phối trên host staging: network tenant giả + upstream giả, container giữ netns trên `mg-edge`/`mg-admin`/`mg-obs`, chạy các nhóm kiểm, thử API key thật (hạn 1 giờ, expire ngay), dừng tenant giả, dọn sạch. Khi edge có listener tunnel-facing (template ≥ 3) thì chạy thêm `tunnel-reject` từ container trên `mg-edge` và từ chính host |
| `conformance.py` | Các nhóm kiểm `public`, `admin`, `metrics`, `unreachable`, `tunnel-reject`, `real-api`, `stopped` (thư viện chuẩn Python). `tunnel-reject`: từ nguồn không phải đầu VPS, listener tunnel-facing không phục vụ request nào — kể cả khi không gửi PROXY header hoặc gửi header giả (V-17, [P1-T18](../../../docs/planning/evidence/P1-T18.md)) |
| `echo_upstream.py` | "Headscale" giả trên cổng 8080/9090: ghi lại method, path, header của mọi request tới nó |
| `external.py` | AC-20 từ Internet: chạy trên một máy **ngoài** nền tảng — quét TCP 1 065 cổng của IP điểm vào, path cấm và traversal trên mọi hostname tenant, `/bootstrap-dns`, cổng 80, SNI lạ, `admin.<domain>` |
| `dns_leak.py` | Bắt gói DNS trên host khi gửi nhãn tenant ngẫu nhiên ([P1-T12d](../../../docs/planning/evidence/P1-T12d.md)) |

```bash
# trên host staging (cần quyền root: nsenter, đọc file token)
eval "$(python3 tools/mgenv.py export infrastructure/environments/staging/staging.env)"   # domain, IP… từ env file
sudo bash tests/security/edge/run_staging.sh "mesh.$MG_BASE_DOMAIN" "$MG_PUBLIC_IPV4" tenant-a tenant-b
# từ một máy ngoài nền tảng (Internet)
python3 -I tests/security/edge/external.py "$MG_PUBLIC_IPV4" "mesh.$MG_BASE_DOMAIN" tenant-a,tenant-b
```

Không in giá trị secret nào: token admin/metrics được đọc từ file, API key thật nằm trong file tmpfs chỉ root đọc được trong lúc chạy; log của upstream giả bị xóa khi kết thúc (nếu edge lỡ không gỡ token, log đó chứa token).
