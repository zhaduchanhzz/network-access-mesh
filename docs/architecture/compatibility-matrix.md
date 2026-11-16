# Compatibility Matrix

> **Trích sinh tự động** từ [implementation-master-plan.md](../planning/implementation-master-plan.md) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.
> Nguồn: §2.7. Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README](../README.md).

### 2.7 Compatibility Matrix

| Cặp thành phần | Trạng thái | Ghi chú |
|---|---|---|
| Headscale `0.29.7` ↔ Tailscale client `≥ 1.80.0` | VERIFIED (sàn cứng trong code) | Client cũ hơn nhận HTTP 400 |
| Headscale `0.29.7` ↔ Tailscale client `1.104.4+` | VERIFIED (khuyến nghị trong changelog; build với `tailscale.com v1.104.4`) | — |
| Headscale `0.29.7` ↔ Tailscale client `1.104.7` trên Linux/Windows/macOS/iOS/Android | **REQUIRES VALIDATION** | Ngoài bảng capability của tag; smoke test từng OS ở Phase 5 |
| Headscale `0.29.7` ↔ Caddy `2.11.x` (control upgrade + DERP upgrade) | **REQUIRES VALIDATION** | Upstream không test sau proxy; gate Phase 1 |
| STUN dùng chung (`stund`) ↔ official client | **REQUIRES VALIDATION** (V-02) | Với client, region vẫn ở dạng chuẩn `host:443` + `host:3478`; kiểm bằng `tailscale netcheck` |
| Control/DERP ↔ VPS l4proxy (PROXY v2) ↔ Caddy | **REQUIRES VALIDATION** (V-16…V-18) | Chuyển tiếp tầng 4 trong suốt với HTTP Upgrade; cần đo stream dài |
| Embedded STUN publish trực tiếp qua Docker (phương án dự phòng) | **REQUIRES VALIDATION** | IPv4 kỳ vọng giữ IP nguồn; IPv6: **UNSUPPORTED ở MVP** (mất IP nguồn qua `userland-proxy` khi bridge chỉ-IPv4 — EG-10) |
| Headscale `0.29.x` → `0.30` | VERIFIED là **breaking** (API v1 bị thay, gRPC bị bỏ) | Adapter có lớp version; không nâng tự động |
| derper `v1.104.x` ↔ Headscale `/verify` | VERIFIED (tài liệu + test upstream) | Chỉ dùng ở Phase 7 |
| Headscale ↔ PostgreSQL | Hỗ trợ ở mức legacy — **không dùng** | HS-02 |
| Peer relays ↔ client stable | **REQUIRES VALIDATION** | CL-13 |
| Private CA / self-signed ↔ official client | **UNSUPPORTED như giả định chung** | CL-02, CL-03 |
| Cloudflare Proxy/Tunnel ↔ Headscale | **UNSUPPORTED** | HS-15 |
| Rootless Docker ↔ giữ IP nguồn ở cổng publish | **REQUIRES VALIDATION** | ST-10: không giữ theo mặc định; có cấu hình giữ được — chưa thử; MVP dùng rootful |
