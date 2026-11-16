# Server Inventory (Ubuntu host + VPS)

> **Trích sinh tự động** từ [implementation-master-plan.md](../planning/implementation-master-plan.md) bằng `tools/split_plan.py` — **không sửa tay**; sửa bản master rồi sinh lại.
> Nguồn: §A. Số mục `§` và các mã (HS-…, ADR-…, AC-…, T-…) tham chiếu theo bản master. Nhãn bằng chứng: xem [README](../README.md).

## Appendix A — Ubuntu Server Inventory: thông tin còn thiếu & Server Discovery Checklist

Plan Mode **không** truy cập server (chưa được cấp SSH key/phạm vi quyền; mật khẩu không được dùng). Vì vậy mọi giá trị dưới đây đang **chưa biết** và **không được tự điền**. Task `P1-T01` (Build Mode, sau khi được phép) chạy checklist read-only này và ghi kết quả vào `docs/deployment/ubuntu-server-inventory.md`. **Cập nhật 2026-11-16:** discovery đã chạy theo chỉ đạo của chủ dự án; kết quả ở A.4 (A.1–A.3 giữ nguyên làm danh mục câu hỏi và lệnh).

### A.1 Thông tin còn thiếu (cần người dùng cung cấp hoặc đo ở P1-T01)

| # | Thông tin | Vì sao cần | Ảnh hưởng tới quyết định |
|---|---|---|---|
| 1 | Ubuntu version, kernel, CPU architecture | Chọn image `amd64`/`arm64`, tính năng kernel | Pin image digest theo arch |
| 2 | Số CPU core, RAM, dung lượng đĩa trống (`/`, `/opt`, `/var/lib/docker`) | Sizing | Chọn IdP profile (đầy đủ/nhẹ), monitoring profile, số tenant tối đa trên host |
| 3 | Docker Engine/Compose đã cài chưa, version, nội dung `daemon.json` | Tránh xung đột | Kế hoạch cài/nâng cấp, `default-address-pools`, log driver |
| 4 | Container/service đang chạy, cổng TCP/UDP đang bị chiếm (đặc biệt 80, 443, 3478) | Xung đột cổng | Port plan |
| 5 | Trạng thái firewall (ufw/nftables/iptables) | Baseline bảo mật | Firewall plan (chỉ đề xuất, không tự áp dụng) |
| 6 | Public IP — **đã có**: VPS với IPv4 công khai `116.118.3.46` do người dùng cung cấp (2026-11-16) làm Public Gateway. Đã đo ngày 2026-11-16 (A.4): hệ điều hành, CPU/RAM/đĩa, IPv6, WireGuard trong kernel. **Còn chưa biết:** firewall/security group của nhà cung cấp, quota và băng thông | Khả năng Internet-facing | Path B đã chọn (§15.3); sizing `l4proxy`; kế hoạch firewall VPS |
| 7 | Router của LAN: **không cần** port forwarding (host LAN chủ động mở tunnel ra VPS); chỉ cần cho phép UDP đi ra tới cổng tunnel của VPS. Cần biết: IP ra Internet của LAN có cố định không | Giới hạn IP nguồn cho cổng tunnel trên VPS | Quy tắc firewall VPS |
| 8 | Domain sở hữu + DNS provider (có API cho ACME DNS-01 không) | TLS hợp lệ cho official client | Chiến lược chứng chỉ (wildcard DNS-01 vs on-demand) |
| 9 | Email cho ACME account; SMTP cho thư mời/cảnh báo | Vận hành | Cấu hình edge/IdP/alerting |
| 10 | IdP sẵn có (Entra ID/Google Workspace/Keycloak…) hay cần IdP do nền tảng host | Identity | ADR về IdP |
| 11 | Đích backup ngoài host (S3-compatible/NAS) | DR | RPO/RTO khả thi |
| 12 | Thiết bị thử nghiệm: số lượng, hệ điều hành, có mạng thứ hai (LTE/hotspot) cho test NAT không | Acceptance #8–#17 | Test plan mạng thật |
| 13 | Phương thức truy cập cho Build Mode trên **cả hai máy**: user không phải root + SSH key. **Mật khẩu root của VPS đã bị chia sẻ trong hội thoại ngày 2026-11-16 ⇒ phải đổi trước khi triển khai**; mật khẩu không được ghi ở bất kỳ file nào của dự án. Host LAN: **mật khẩu root của Proxmox** (hypervisor chứa host staging) cũng đã bị chia sẻ trong hội thoại ngày 2026-11-16 ⇒ phải đổi trước khi triển khai lên host staging (D-10). **2026-11-16: chủ dự án quyết định không đổi**, chấp nhận rủi ro | Bảo mật | Không còn chặn (D-10); P1-T15 tắt đăng nhập SSH bằng mật khẩu |
| 14 | IPv6 có khả dụng không | DERP/STUN IPv6 | MVP chỉ IPv4 (§15.4); chỉ ghi nhận để lập kế hoạch dual-stack về sau |
| 15 | Git hosting, CI runner, container registry sẽ dùng | Supply chain | Pipeline Phase 2/6 |
| 16 | Quy mô kỳ vọng (số tenant, thiết bị/tenant) cho MVP và 12 tháng | Capacity | Ngưỡng Go/No-Go của scale test |
| 17 | Cơ chế nâng quyền không dùng mật khẩu cho user triển khai trên host LAN và VPS (sudoers `NOPASSWD` có phạm vi, hoặc người dùng tự chạy lệnh đặc quyền) | Nhiều lệnh discovery/hardening cần quyền root trong khi mật khẩu không được dùng | Cách thực thi P1-T01, P1-T02, P1-T15 (D-13) |
| 18 | Số người vận hành nền tảng (có ≥ 2 người để thực hiện dual control không) | Thao tác 2P cần người thứ hai phê duyệt | D-11; thiết kế P3-T04a |
| 19 | Địa chỉ IP, subnet và default gateway của host LAN; dải LAN và các route/VPN sẵn có — để kiểm tra chồng lấn với `default-address-pools` dự kiến và với `100.64.0.0/10` | Bản ghi DNS trỏ IP LAN (§15.3), IP bind của listener LAN-direct (§14.6), pool Docker (§14.1) | Chọn pool địa chỉ; bản ghi split-horizon; firewall |
| 20 | Resolver của LAN có chặn tên public trỏ về IP private (DNS rebinding protection) không | Local Development dùng domain thật trỏ IP LAN (§15.3, EG-05) | Dùng DNS nội bộ/split-horizon hay bản ghi public |
| 21 | Máy chạy GitHub Actions runner tự host (D-12): máy vật lý hay VM, hệ điều hành, CPU/RAM/đĩa, có Docker không, nằm ở mạng nào; xác nhận **không** phải host LAN staging | Runner cần Docker để build image và chạy test tích hợp; đặt sai chỗ là rủi ro R-28 | Pin digest, CI (P0-T03, P0-T04, P0-T07) |

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

### A.4 Kết quả discovery và hạ tầng đã tạo (2026-11-16)

Theo chỉ đạo của chủ dự án ("vào và kiểm tra"; "tự tạo các VM liên quan, ưu tiên NVMe 2 TB"), discovery chỉ-đọc theo A.2/A.3 đã chạy ngày 2026-11-16 qua SSH key của dự án, và các VM dưới đây đã được tạo trên Proxmox **trước G0**. Đây là ngoại lệ do chủ dự án chỉ đạo, không phải trình tự chuẩn của §19: P1-T01 và P1-T15 vẫn chạy lại checklist ngay trước khi thay đổi host. Nhật ký thao tác, cấu hình đã đổi và lệnh hoàn tác: `docs/planning/evidence/infrastructure-bootstrap.md`.

**Máy và vai trò**

| Máy | Vai trò trong plan | Cấu hình đo được | Ghi chú |
|---|---|---|---|
| Proxmox VE 9.2, node `hanh` (192.168.1.14) | Hypervisor của host staging, runner CI và client thử | 36 core, 125 GiB RAM; storage `nvme01` (LVM-thin trên NVMe 1,9 TB, đã dùng 1,69% sau khi tạo VM) và `local-lvm` (NVMe 512 GB) | VM/CT có sẵn (100 OPNsense, 101, 102, 103 `ubuntu-lab` = 192.168.1.18) không bị động tới. SSH root cho phép mật khẩu; mật khẩu root đã lộ trong hội thoại và chủ dự án quyết định không đổi (D-10). Firewall của Proxmox đang tắt. Proxmox có địa chỉ trong tailnet riêng của chủ dự án; không có IPv6 công khai |
| VM 104 `mg-staging` (192.168.1.8, DHCP) | **Host LAN staging** của plan (thay máy 192.168.1.18 nêu trong đề bài; máy đó không được dùng) | 8 vCPU (Xeon E5-2696 v3), 24 GB RAM, không swap, đĩa 250 GB trên `nvme01`; Ubuntu 24.04.5 LTS, kernel 6.8.0-147, amd64 | Docker Engine 29.9.3 + Compose 5.7.1 (cài 2026-11-16 theo chỉ đạo của chủ dự án; `daemon.json` ở dòng `daemon.json` của §14.1); chưa bật firewall; SSH chỉ bằng key; NTP đồng bộ; `onboot=1`. **Có IPv6 công khai** qua SLAAC (V-35) |
| VM 105 `mg-ci-runner` (192.168.1.19, DHCP) | Runner GitHub Actions tự host (D-12, A.1 #21) | 6 vCPU, 16 GB RAM, đĩa 150 GB; Ubuntu 24.04.5 LTS | Tách khỏi host staging (R-28); Docker 29.9.3 + Compose 5.7.1 và runner 2.338.2 đã cài (2026-11-16); **không** gắn vào GitHub vì repo public (D-12) — giữ làm máy build/thử cục bộ; `onboot=1`; có IPv6 công khai |
| VM 106 `mg-client-a1` (192.168.1.21), VM 107 `mg-client-b1` (192.168.1.22) | Client Linux trong LAN (tenant A, tenant B) | 2 vCPU, 2 GB RAM, đĩa 20 GB; Ubuntu 24.04.5 LTS | `onboot=0`; có IPv6 công khai |
| VM 108 `mg-client-a2` (192.168.10.11), VM 109 `mg-client-b2` (192.168.10.12) | Client Linux sau NAT của OPNsense (segment `lan10`, khác LAN chính) | 2 vCPU, 2 GB RAM, đĩa 20 GB; Ubuntu 24.04.5 LTS | `onboot=0`; không có IPv6 |
| Máy Windows 11 của chủ dự án | Client hệ điều hành thứ hai (G0(4)), ở mạng ngoài LAN của Proxmox | Wi-Fi 192.168.4.0/22 | Chỉ tới được LAN của Proxmox qua tailnet riêng của chủ dự án. Client Tailscale chỉ chạy một profile một lúc (CL-01) ⇒ khi chuyển sang tenant MeshGuard sẽ mất đường tới Proxmox và các VM: chỉ thử trong cửa sổ có hẹn, chuyển lại profile cũ ngay sau đó |
| VPS 116.118.3.46 | Public Gateway (D-2, ADR-25) | 2 vCPU (QEMU), 1,9 GB RAM + 4 GB swap, đĩa 40 GB (trống 17 GB); Ubuntu 24.04 LTS, kernel 6.8.0-31, amd64 | Bảng VPS bên dưới |

Mọi VM dùng cloud image Ubuntu 24.04 (noble): `SHA256SUMS` được kiểm chữ ký GPG (khóa `D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`) rồi kiểm checksum ảnh; cloud-init tạo user `mgdeploy` chỉ với SSH public key của dự án, không đặt mật khẩu; `qemu-guest-agent` chạy. IP do DHCP cấp ⇒ trước Phase 1 cần DHCP reservation trên router cho VM 104 và 105 (bản ghi DNS và tunnel trỏ tới host staging).

**VPS — kết quả A.3**

| # | Kết quả |
|---|---|
| 3 | IPv4 công khai gắn trực tiếp trên `eth0`; **không có IPv6** công khai |
| 4 | Trước 2026-11-16: 3 dự án cũ của chủ dự án (15 container) giữ TCP 80/443 (Caddy) và UDP 3478, TCP 7881, UDP 7882 (LiveKit). **Đã dừng ngày 2026-11-16 theo yêu cầu của chủ dự án** (giữ container, image, volume và file; lệnh hoàn tác trong nhật ký) ⇒ 80/443/3478 trống. Dịch vụ thư trên host (postfix, dovecot, opendkim) vẫn chạy ở TCP 25/587 — không xung đột |
| 5 | Không có ufw; chain `INPUT` mặc định `ACCEPT`; rule nftables hiện có là của Docker ⇒ VPS chưa có firewall trên máy |
| 6, 11 | Firewall/security group phía nhà cung cấp, quota và băng thông: **chưa biết** — chủ dự án kiểm trên trang quản trị |
| 7 | Có kernel module WireGuard; chưa có công cụ `wg` |
| 8 | Docker 29.1.3 và Compose 2.40.3 từ kho của Ubuntu (gói `docker.io`), không phải Docker CE — P1-T15 quyết định giữ hay thay |
| 9 | `PermitRootLogin yes`, `PasswordAuthentication yes`; chủ dự án chọn **chưa tắt** (2026-11-16). Root có 2 SSH key; mọi lần đăng nhập root trong 14 ngày trước đều bằng key, một phần từ dải IP của Azure — nhiều khả năng là pipeline deploy của các dự án cũ; nếu còn bật, chúng có thể dựng lại các dự án và chiếm lại cổng |
| 10 | Ngoài dịch vụ hệ thống: Docker, postfix, dovecot, opendkim. Còn 2 cron và 1 timer của dự án cũ (`vnflashlearner-docker-cleanup`, `vnflashlearner-postgres-backup`, `vnflash-mail-certs.timer`): đã đọc mã, vô hại khi các dự án đã dừng (không khởi động lại container, không xóa volume hay bản dump) |
| 12 | NTP đồng bộ; 367 gói chờ cập nhật; `unattended-upgrades` chạy |
| — | User triển khai `mgdeploy` (SSH key của dự án, `sudo` NOPASSWD toàn quyền — thu hẹp ở P1-T15) |
| Sau P1-T15…P1-T18 (2026-11-16) | SSH chỉ bằng khóa (`PasswordAuthentication no`, `PermitRootLogin prohibit-password`); firewall trên máy `inet mg_vps` (vào mặc định chặn; mở TCP 22, 80, 443, 25, 587, UDP 3478, 51820); 367 gói đã vá, **chờ reboot** (libc6, dbus, apparmor) và 9 gói kernel bị giữ lại; giữ Docker gói `docker.io` 29.1.3; `mg-gateway` (`l4proxy` + `stund`) và tunnel `mg-wg0` chạy; quét từ Internet chỉ thấy 22, 80, 443, 587 (`docs/planning/evidence/P1-T15.md`, `P1-T18.md`) |

**Host staging — kết quả A.2 (VM 104)**

| # | Kết quả |
|---|---|
| 3 | `/` ext4 242 GB, trống 239 GB |
| 4 | `eth0` 192.168.1.8/24, gateway 192.168.1.1; IPv6 công khai `2405:4802:…/64` (SLAAC) |
| 5 | Resolver 192.168.1.1; **không** chặn tên công khai trỏ về IP private (đã thử bằng tên công khai trỏ tới 10.0.0.1) ⇒ trả lời A.1 #20: bản ghi public trỏ IP LAN dùng được trong LAN |
| 6 | Lúc discovery chưa có Docker; đã cài Docker 29.9.3 + Compose 5.7.1 ngày 2026-11-16 (P1-T02 làm sớm theo chỉ đạo của chủ dự án) |
| 8–9 | Chỉ dịch vụ mặc định của cloud image; chỉ SSH (22) nghe trên mọi địa chỉ, cả IPv4 và IPv6 |
| 10 | ufw tắt, không có rule nftables, `INPUT` mặc định `ACCEPT` |
| 11, 13 | IP ra Internet của LAN: lúc discovery chưa đo (lệnh đo làm lộ IP cho dịch vụ bên thứ ba). Từ P1-T15 đo bằng `stund` của chính dự án trên VPS: một IPv4 công khai (che trong bằng chứng); router có CGNAT hay không vẫn chưa kiểm — không cần cho Path B. Port forwarding (13): không dùng (Path B, §15.3) |
| 12, 14 | Domain/DNS: chứng chỉ wildcard qua DNS-01 (P1-T05); `*.mesh.` A → IP VPS (DNS-only) + CAA (P1-T18). Từ Internet (P1-T18): `/key?v=113` trả 200 qua VPS, `netcheck` và `debug derp` đạt với client trong LAN; client ở mạng ngoài (4G) còn pending |
| 15 | NTP đồng bộ, múi giờ UTC |
| 16 | SSH chỉ bằng key (`PasswordAuthentication no`); root chỉ bằng key |
| 17 | `net.ipv4.ip_forward = 0`; `rmem_max`/`wmem_max` = 212992; `fs.inotify.max_user_instances` = 128 |
| 18 | AppArmor bật; `unattended-upgrades` chạy; 0 gói chờ cập nhật |

**Domain (D-1):** `gta5web.online` dùng nameserver của Cloudflare; không có bản ghi CAA (Let's Encrypt được phép); các tên `app.`, `admin.`, `auth.`, `mesh.` và tên mẫu dưới `*.mesh.` chưa tồn tại (kiểm ngày 2026-11-16). Từ P1-T18 (2026-11-16): `*.mesh.gta5web.online` A → IP VPS (DNS-only); CAA trên `mesh.gta5web.online` chỉ cho Let's Encrypt, `dns-01`, đúng tài khoản ACME production của edge (`infrastructure/environments/staging/dns-public.json`).

**Trạng thái từng mục A.1 (đầu ra P0-T05)**

| # | Giá trị, hoặc "chưa biết — người chịu trách nhiệm" |
|---|---|
| 1 | amd64; host staging Ubuntu 24.04.5 LTS, VPS Ubuntu 24.04 LTS; kernel 6.8 |
| 2 | Host staging 8 vCPU / 24 GB / 250 GB; VPS 2 vCPU / 1,9 GB / 40 GB (trống 17 GB) |
| 3 | Host staging và runner CI: Docker 29.9.3 + Compose 5.7.1 từ kho chính thức của Docker (từ 2026-11-16); VPS: Docker 29.1.3 + Compose 2.40.3 (gói Ubuntu), không có `daemon.json` |
| 4 | Host staging chỉ có SSH; VPS: 80/443/3478 trống từ 2026-11-16, thư ở 25/587 |
| 5 | Cả hai máy chưa có firewall trên máy |
| 6 | VPS có IPv4 công khai. Firewall/security group và quota phía nhà cung cấp: chưa biết — chủ dự án |
| 7 | IP ra Internet của LAN có cố định không: chưa biết — chủ dự án (hoặc agent đo khi được đồng ý) |
| 8 | `gta5web.online`, Cloudflare (D-1) |
| 9 | Email cho ACME account và SMTP: chưa biết — chủ dự án; email ACME cần trước P1-T05, SMTP trước P2-T05 |
| 10 | Keycloak tự host, 3 realm (D-3) |
| 11 | Đích backup ngoài host: chưa biết — chủ dự án; cần trước P6-T03 |
| 12 | 4 VM Linux + máy Windows 11 (G0(4)); thiết bị di động cho Phase 5: chưa biết — chủ dự án |
| 13 | SSH key trên VPS (user `mgdeploy`) và Proxmox (root); chủ dự án quyết định không đổi mật khẩu root của VPS và Proxmox (D-10, chấp nhận rủi ro); bản sao trên máy vận hành đã xóa |
| 14 | VPS không có IPv6; LAN có IPv6 công khai (V-35) |
| 15 | GitHub (repo public) + GitHub Actions trên runner của GitHub + GHCR (D-12, quyết định lại 2026-11-16) |
| 16 | Quy mô kỳ vọng cho MVP và 12 tháng: chưa biết — chủ dự án; cần trước P6-T08 |
| 17 | `sudo` NOPASSWD toàn quyền, tạm thời (D-13) |
| 18 | Từ 2 người trở lên (D-11) |
| 19 | Host staging 192.168.1.8/24, gateway 192.168.1.1; LAN 192.168.1.0/24; segment `lan10` 192.168.10.0/24 sau OPNsense; Proxmox và máy Windows thuộc tailnet riêng của chủ dự án (dải `100.64.0.0/10`, `fd7a:115c:a1e0::/48`), máy Windows tới LAN qua subnet route của tailnet đó. Pool Docker không được chồng các dải này (§14.1) |
| 20 | Resolver của LAN không chặn tên công khai trỏ về IP private |
| 21 | VM 105 `mg-ci-runner` — không dùng làm runner của GitHub vì repo public (D-12); máy build/thử cục bộ |
