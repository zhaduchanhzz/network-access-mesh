# Server Inventory (Ubuntu host + VPS)

> **Trích sinh tự động** từ [implementation-master-plan.md](../planning/implementation-master-plan.md) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.
> Nguồn: §A. Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README](../README.md).

## Appendix A — Ubuntu Server Inventory: thông tin còn thiếu & Server Discovery Checklist

Plan Mode **không** truy cập server (chưa được cấp SSH key/phạm vi quyền; mật khẩu không được dùng). Vì vậy mọi giá trị dưới đây đang **chưa biết** và **không được tự điền**. Task `P1-T01` (Build Mode, sau khi được phép) chạy checklist read-only này và ghi kết quả vào `docs/deployment/ubuntu-server-inventory.md`.

### A.1 Thông tin còn thiếu (cần người dùng cung cấp hoặc đo ở P1-T01)

| # | Thông tin | Vì sao cần | Ảnh hưởng tới quyết định |
|---|---|---|---|
| 1 | Ubuntu version, kernel, CPU architecture | Chọn image `amd64`/`arm64`, tính năng kernel | Pin image digest theo arch |
| 2 | Số CPU core, RAM, dung lượng đĩa trống (`/`, `/opt`, `/var/lib/docker`) | Sizing | Chọn IdP profile (đầy đủ/nhẹ), monitoring profile, số tenant tối đa trên host |
| 3 | Docker Engine/Compose đã cài chưa, version, nội dung `daemon.json` | Tránh xung đột | Kế hoạch cài/nâng cấp, `default-address-pools`, log driver |
| 4 | Container/service đang chạy, cổng TCP/UDP đang bị chiếm (đặc biệt 80, 443, 3478) | Xung đột cổng | Port plan |
| 5 | Trạng thái firewall (ufw/nftables/iptables) | Baseline bảo mật | Firewall plan (chỉ đề xuất, không tự áp dụng) |
| 6 | Public IP — **đã có**: VPS với IPv4 công khai `116.118.3.46` do người dùng cung cấp (2026-11-16) làm Public Gateway. **Chưa biết** về VPS: hệ điều hành, CPU/RAM/đĩa, firewall/security group của nhà cung cấp, quota và băng thông, IPv6, có hỗ trợ WireGuard trong kernel không | Khả năng Internet-facing | Path B đã chọn (§15.3); sizing `l4proxy`; kế hoạch firewall VPS |
| 7 | Router của LAN: **không cần** port forwarding (host LAN chủ động mở tunnel ra VPS); chỉ cần cho phép UDP đi ra tới cổng tunnel của VPS. Cần biết: IP ra Internet của LAN có cố định không | Giới hạn IP nguồn cho cổng tunnel trên VPS | Quy tắc firewall VPS |
| 8 | Domain sở hữu + DNS provider (có API cho ACME DNS-01 không) | TLS hợp lệ cho official client | Chiến lược chứng chỉ (wildcard DNS-01 vs on-demand) |
| 9 | Email cho ACME account; SMTP cho thư mời/cảnh báo | Vận hành | Cấu hình edge/IdP/alerting |
| 10 | IdP sẵn có (Entra ID/Google Workspace/Keycloak…) hay cần IdP do nền tảng host | Identity | ADR về IdP |
| 11 | Đích backup ngoài host (S3-compatible/NAS) | DR | RPO/RTO khả thi |
| 12 | Thiết bị thử nghiệm: số lượng, hệ điều hành, có mạng thứ hai (LTE/hotspot) cho test NAT không | Acceptance #8–#17 | Test plan mạng thật |
| 13 | Phương thức truy cập cho Build Mode trên **cả hai máy**: user không phải root + SSH key. **Mật khẩu root của VPS đã bị chia sẻ trong hội thoại ngày 2026-11-16 ⇒ phải đổi trước khi triển khai**; mật khẩu không được ghi ở bất kỳ file nào của dự án. Host LAN: mật khẩu root đã từng được chia sẻ chưa | Bảo mật | Chặn P1-T15 cho tới khi đổi mật khẩu và có SSH key |
| 14 | IPv6 có khả dụng không | DERP/STUN IPv6 | MVP chỉ IPv4 (§15.4); chỉ ghi nhận để lập kế hoạch dual-stack về sau |
| 15 | Git hosting, CI runner, container registry sẽ dùng | Supply chain | Pipeline Phase 2/6 |
| 16 | Quy mô kỳ vọng (số tenant, thiết bị/tenant) cho MVP và 12 tháng | Capacity | Ngưỡng Go/No-Go của scale test |
| 17 | Cơ chế nâng quyền không dùng mật khẩu cho user triển khai trên host LAN và VPS (sudoers `NOPASSWD` có phạm vi, hoặc người dùng tự chạy lệnh đặc quyền) | Nhiều lệnh discovery/hardening cần quyền root trong khi mật khẩu không được dùng | Cách thực thi P1-T01, P1-T02, P1-T15 (D-13) |
| 18 | Số người vận hành nền tảng (có ≥ 2 người để thực hiện dual control không) | Thao tác 2P cần người thứ hai phê duyệt | D-11; thiết kế P3-T04a |
| 19 | Địa chỉ IP, subnet và default gateway của host LAN; dải LAN và các route/VPN sẵn có — để kiểm tra chồng lấn với `default-address-pools` dự kiến và với `100.64.0.0/10` | Bản ghi DNS trỏ IP LAN (§15.3), IP bind của listener LAN-direct (§14.6), pool Docker (§14.1) | Chọn pool địa chỉ; bản ghi split-horizon; firewall |
| 20 | Resolver của LAN có chặn tên public trỏ về IP private (DNS rebinding protection) không | Local Development dùng domain thật trỏ IP LAN (§15.3, EG-05) | Dùng DNS nội bộ/split-horizon hay bản ghi public |

### A.2 Server Discovery Checklist (chỉ lệnh read-only; không sửa cấu hình)

| # | Hạng mục | Lệnh | Ghi nhận |
|---|---|---|---|
| 1 | OS / kernel / arch | `lsb_release -ds; uname -srm; dpkg --print-architecture` | Ubuntu version, kernel, arch |
| 2 | CPU / RAM | `nproc; lscpu \| head -n 20; free -h` | cores, model, RAM/swap |
| 3 | Đĩa | `df -hT; df -i; lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT` | dung lượng trống, filesystem |
| 4 | Network interfaces / gateway | `ip -br addr; ip -br link; ip route show; ip -6 route show` | interface, IP, default gateway, IPv6 |
| 5 | DNS resolver | `resolvectl status \| head -n 40; cat /etc/resolv.conf` | resolver đang dùng |
| 6 | Docker | `docker version; docker compose version; docker info; cat /etc/docker/daemon.json` | version, storage driver, address pools, userland-proxy |
| 7 | Container / network / volume hiện có | `docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'; docker network ls; docker volume ls` | xung đột tiềm ẩn |
| 8 | Service hệ thống | `systemctl list-units --type=service --state=running --no-pager` | dịch vụ đang chạy |
| 9 | Cổng đang lắng nghe | `ss -tulpn` | TCP/UDP đã chiếm |
| 10 | Firewall | `ufw status verbose; nft list ruleset \| head -n 200; iptables -S; iptables -t nat -S` | rule hiện hành |
| 11 | Public IP / NAT / CGNAT | So sánh WAN IP trên giao diện router với IP nhìn từ ngoài. Lệnh `curl -4 -s https://api.ipify.org` là tùy chọn (tiết lộ IP cho bên thứ ba — cần người dùng đồng ý). | public IP, có CGNAT không |
| 12 | Domain / DNS | `dig +short <domain> A; dig +short <domain> AAAA; dig +short NS <zone>` | bản ghi hiện có, DNS provider |
| 13 | Đường ra của LAN | `curl -4 -s https://api.ipify.org` chạy vài lần cách nhau (tùy chọn) hoặc xem trên router | IP ra có cố định không; UDP đi ra có bị chặn không |
| 14 | External reachability | Từ mạng ngoài (LTE): `curl -s -o /dev/null -w '%{http_code}' 'https://<host>/key?v=<capver>'` (kỳ vọng 200; `/key` không có `v` trả 400, `/health` bị edge chặn); `tailscale netcheck` | chỉ thực hiện sau khi VPS gateway và DNS public đã bật (P1-T18) |
| 15 | Time sync | `timedatectl status` | NTP đồng bộ (bắt buộc cho TLS/OIDC) |
| 16 | SSH posture (chỉ đọc) | `sshd -T \| grep -Ei 'permitrootlogin\|passwordauthentication\|pubkeyauthentication'` | đầu vào cho hardening (không tự sửa) |
| 17 | Kernel params | `sysctl net.ipv4.ip_forward net.core.rmem_max net.core.wmem_max fs.inotify.max_user_instances` | baseline tuning |
| 18 | Bản vá / LSM | `aa-status --enabled; systemctl is-active unattended-upgrades; apt list --upgradable 2>/dev/null \| wc -l` | baseline bảo mật |

### A.3 VPS Discovery Checklist (chỉ lệnh read-only; chạy sau khi đã đổi mật khẩu và đăng nhập bằng SSH key)

| # | Hạng mục | Lệnh | Ghi nhận |
|---|---|---|---|
| 1 | OS / kernel / arch | `lsb_release -ds; uname -srm; dpkg --print-architecture` | Bản phân phối, kernel, arch |
| 2 | Tài nguyên | `nproc; free -h; df -hT` | CPU, RAM, đĩa của VPS |
| 3 | Mạng | `ip -br addr; ip route show; ip -6 addr` | IP công khai gắn trực tiếp hay NAT 1:1; có IPv6 không |
| 4 | Cổng đang lắng nghe | `ss -tulpn` | 80/443/3478 đã bị chiếm chưa |
| 5 | Firewall trên máy | `nft list ruleset \| head -n 200; iptables -S; ufw status verbose` | Rule hiện hành |
| 6 | Firewall phía nhà cung cấp | Kiểm tra thủ công trên trang quản trị VPS | Security group / giới hạn cổng UDP |
| 7 | WireGuard | `modinfo wireguard \| head -n 3; command -v wg` | Kernel module và công cụ có sẵn không |
| 8 | Docker | `docker version; docker compose version` | Đã cài chưa |
| 9 | SSH posture | `sshd -T \| grep -Ei 'permitrootlogin\|passwordauthentication\|pubkeyauthentication'` | Đầu vào cho hardening |
| 10 | Dịch vụ đang chạy | `systemctl list-units --type=service --state=running --no-pager` | Dịch vụ thừa cần tắt |
| 11 | Quota / băng thông | Trang quản trị VPS | Giới hạn lưu lượng tháng, tốc độ cổng — ảnh hưởng dung lượng relay |
| 12 | Time sync / bản vá | `timedatectl status; apt list --upgradable 2>/dev/null \| wc -l` | Baseline |
