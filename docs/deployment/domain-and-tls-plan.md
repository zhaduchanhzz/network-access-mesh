# Domain & TLS Plan

> **Trích sinh tự động** từ [implementation-master-plan.md](../planning/implementation-master-plan.md) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.
> Nguồn: §15.4. Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README](../README.md).

### 15.4 Domain & TLS plan

| Tên | Mục đích | Chứng chỉ |
|---|---|---|
| `app.<domain>` | Tenant Portal + SaaS API | ACME (DNS-01 hoặc HTTP-01 khi public) |
| `admin.<domain>` | Platform Console, Grafana | Như trên; tùy chọn giới hạn IP |
| `auth.<domain>` | IdP | Như trên |
| `*.mesh.<domain>` | Control plane + DERP của từng tenant (`<slug>.mesh.<domain>`) | **Một wildcard qua DNS-01** — tránh trần 50 chứng chỉ/tuần (EG-06) và tránh cấp chứng chỉ theo tenant |
| `<slug>.tail.<domain>` (ví dụ) | `dns.base_domain` của MagicDNS | Không cần DNS public; chỉ cần **không** trùng/không là cha của host control (RT-07) |
| Domain riêng của khách (Phase 7) | Control URL theo thương hiệu khách | On-demand TLS + endpoint `ask` (`/internal/edge/ask`) chỉ chấp nhận domain đã đăng ký |

Bản ghi DNS ở chế độ Internet-facing: `*.mesh.<domain>`, `app.<domain>`, `auth.<domain>` → **A record trỏ về IP công khai của VPS**; `admin.<domain>` **chỉ** có trong DNS nội bộ (trỏ về IP LAN của host). Chứng chỉ vẫn do edge trên host LAN xin qua DNS-01 (không cần inbound), nên không có khóa riêng nào nằm trên VPS.

**MVP chỉ IPv4.** Không tạo bản ghi AAAA cho `*.mesh.<domain>`, `app.<domain>`, `auth.<domain>`, `admin.<domain>`; `derp.server.ipv6` render rỗng và `hosts.public_entry.ipv6` để trống (§10.1); edge và `l4proxy` publish cổng với **IPv4 tường minh** (`l4proxy` cũng có thể chạy host network và chỉ bind IPv4). Lý do (EG-10): với `userland-proxy` mặc định và bridge chỉ-IPv4, kết nối tới địa chỉ IPv6 của host được chuyển vào IPv4 của container và **mất IP nguồn** — mọi client IPv6 sẽ gộp thành một IP private trong PROXY header, log, CrowdSec và giới hạn tốc độ. Không có AAAA vẫn chưa đủ: nếu cổng còn bind `[::]`, kết nối cố ý tới IPv6 của VPS sẽ hiện ra dưới một IP private (hệ quả suy ra — ASSUMED). Kiểm ở G1: `docker port` và `ss -lnt` trên host LAN (P1-T10) và trên VPS (P1-T17) không có bind `[::]` cho 80/443/8080/8443. Dual-stack là một thay đổi riêng, phải kiểm chứng trước khi bật (backlog sau MVP, chưa có task).

Bổ sung: bản ghi **CAA** giới hạn CA, đồng thời giới hạn `validationmethods=dns-01` và `accounturi` của tài khoản ACME đang dùng (GW-04) — nhờ đó bên kiểm soát IP mà DNS trỏ tới (VPS) không thể tự xin chứng chỉ qua HTTP-01/TLS-ALPN-01; volume dữ liệu ACME được persist và backup; edge chỉ được **ủy quyền challenge ACME**: `_acme-challenge.mesh.<domain>` và `_acme-challenge` của `app.`/`admin.`/`auth.` là CNAME trỏ sang một zone phụ chỉ dùng cho ACME; token của edge chỉ có quyền trên zone phụ đó (Caddy hỗ trợ đổi domain cho DNS challenge — tùy chọn `dns_challenge_override_domain`, xác nhận cú pháp khi pin phiên bản ở P0-T03) và chỉ edge đọc được, nên edge bị chiếm không sửa được bản ghi của nền tảng hay của tenant; nếu DNS provider không cấp được token theo zone phụ: giữ token giới hạn một zone, ghi nhận rủi ro tồn dư ở T-09 và dựa vào cảnh báo thay đổi bản ghi (§16.3); theo dõi hạn chứng chỉ bằng blackbox_exporter; theo dõi Certificate Transparency để phát hiện chứng chỉ lạ cho domain (Phase 6).
