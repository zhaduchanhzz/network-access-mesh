# Khởi tạo hạ tầng trước G0 (2026-11-16)

> **File viết tay — không sinh từ master.** Nhật ký các thay đổi trên Proxmox và VPS thực hiện ngày 2026-11-16 theo chỉ đạo trực tiếp của chủ dự án, **trước** khi G0 đạt — một ngoại lệ có chủ đích so với trình tự §19 của [bản master](../implementation-master-plan.md). Kết quả discovery nằm ở Appendix A.4 của master (sinh ra [ubuntu-server-inventory.md](../../deployment/ubuntu-server-inventory.md)). Quy ước: [README](README.md).

| Mục | Giá trị |
|---|---|
| Ngày | 2026-11-16 (giờ UTC khi có ghi) |
| Người thực hiện | Agent (Claude Code) theo chỉ đạo của chủ dự án |
| Môi trường | staging: Proxmox `hanh` (192.168.1.14) + VPS 116.118.3.46 |
| Chỉ đạo của chủ dự án | "vào VPS tạo key và xóa khỏi mem mật khẩu"; Proxmox "vào tạo key và không lưu mật khẩu"; "tự tạo các VM liên quan ưu tiên sử dụng nvme 2TB"; với 3 dự án cũ trên VPS: "Bỏ 3 dự án đó và tiếp tục thực hiện"; đăng nhập SSH bằng mật khẩu trên VPS: "Chưa tắt" |

## 1. Cách xử lý mật khẩu

Chủ dự án gửi mật khẩu root của VPS và của Proxmox trong hội thoại. Mỗi mật khẩu được dùng **đúng một lần**, chỉ để cài SSH public key: mật khẩu nằm trong một biến môi trường chỉ sống trong lệnh `ssh` đó và được một script askpass in ra; script này không chứa mật khẩu. Không mật khẩu nào được ghi vào file, log, tài liệu, memory hay gửi tới dịch vụ bên ngoài. Mọi thao tác sau đó chỉ dùng SSH key.

**Quyết định của chủ dự án (2026-11-16):** không đổi hai mật khẩu; thay vào đó xóa các bản sao. Đã quét `~/.claude` (transcript, lịch sử lệnh, memory), thư mục tạm của Claude Code, repo, lịch sử PowerShell và Bash, dữ liệu extension của VS Code: chỉ transcript của phiên làm việc còn bản sao dạng rõ — 13 lần xuất hiện trên 9 dòng (trong tin nhắn của chủ dự án và trong lệnh `ssh` đã chạy). Cả 13 đã được thay bằng `[REDACTED-PASSWORD]`; quét lại: 0 bản; transcript vẫn hợp lệ. Script quét và xóa đọc mật khẩu từ transcript lúc chạy, không chứa và không in ra mật khẩu.

**Giới hạn:** bản đã đi qua dịch vụ AI khi mật khẩu nằm trong hội thoại không xóa được từ máy này, nên hai mật khẩu vẫn đăng nhập được vào VPS và Proxmox. Rủi ro này được chủ dự án chấp nhận (D-10, R-23, T-19); biện pháp bù là tắt đăng nhập SSH bằng mật khẩu trên VPS ở P1-T15.

## 2. Khóa SSH của dự án

| Mục | Giá trị |
|---|---|
| Khóa | ed25519, comment `meshguard-ops`, fingerprint `SHA256:vpg135vGPaJT/xGwxPql6BtMzNrJV3Y+54pPf8mQT48` |
| Private key | Chỉ ở máy vận hành của chủ dự án (thư mục `.ssh` của user); không có trong repo |
| Host key Proxmox | ED25519 `SHA256:kRHmbI8da5wrXqfLppcAkmfbiCk34uvssVlemwKED74` |
| Host key VPS | RSA `SHA256:T/GpWMyAmx9kJOEWkQYbQkyTonxsMEMCwJgzjsK0oLQ` |

## 3. Thay đổi đã thực hiện và cách hoàn tác

| # | Máy | Thay đổi | Hoàn tác |
|---|---|---|---|
| 1 | Proxmox | Thêm public key `meshguard-ops` vào `/root/.ssh/authorized_keys` (symlink tới `/etc/pve/priv/authorized_keys`) | `sed -i '/ meshguard-ops$/d' /etc/pve/priv/authorized_keys` |
| 2 | VPS | Tạo user `mgdeploy` (uid 1000) với public key `meshguard-ops`; thêm `/etc/sudoers.d/90-mgdeploy` (NOPASSWD toàn quyền — tạm thời, thu hẹp ở P1-T15). `authorized_keys` của root **không** đổi | `sudo userdel -r mgdeploy && sudo rm /etc/sudoers.d/90-mgdeploy` (chạy bằng user khác có quyền root) |
| 3 | Proxmox | Tải cloud image Ubuntu 24.04 (noble) vào `/var/lib/vz/import/meshguard/`: `SHA256SUMS` kiểm chữ ký GPG với khóa `D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`, ảnh khớp sha256 `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94` | `rm -r /var/lib/vz/import/meshguard` |
| 4 | Proxmox | Tạo VM 104–109 trên storage `nvme01` (bảng ở §4); script từ chối mọi VMID đã tồn tại; VM có sẵn (100–103) không bị động tới | Với từng VM: `qm stop <id> && qm destroy <id> --purge` |
| 5 | VPS | Dừng 15 container của 3 dự án `vnflashlearner-production`, `viettrimarket-production`, `house-studio` (10:37 UTC), đặt restart policy `no`. **Giữ nguyên** container, image, volume, `/opt/<dự án>`, các bản dump PostgreSQL và dịch vụ thư. Cả hai PostgreSQL tắt sạch (exit 0, "database system is shut down"). Trạng thái trước khi dừng: `/root/meshguard-decommission-2026-11-16/state.txt` | `sudo bash /root/meshguard-decommission-2026-11-16/undo.sh` — đặt lại `unless-stopped` và khởi động lại theo thứ tự kho dữ liệu → ứng dụng → Caddy/LiveKit |

| 6 | VM 105 `mg-ci-runner`, VM 104 `mg-staging` | Theo yêu cầu "thực hiện các lệnh install" của chủ dự án: cài Docker Engine 29.9.3 + Compose 5.7.1 (containerd 2.4.2, buildx 0.39.0) từ kho apt chính thức của Docker — khóa kho kiểm theo fingerprint `9DC858229FC7DD38854AE2D88D81803C0EBFCD88` trước khi dùng, chỉ cài đúng phiên bản trong `versions.lock`, giữ phiên bản bằng `apt-mark hold`. `/etc/docker/daemon.json` ghi trước lần khởi động đầu: pool tự động `172.24.0.0/13` chia /24 (không chồng LAN, `100.64.0.0/10`, `fd7a:115c:a1e0::/48`); `"ip": "127.0.0.1"` — cổng publish không ghi IP chỉ nghe loopback, kể cả IPv6 (V-35); log json-file 10 MB × 5; `live-restore` | `sudo apt-get purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin && sudo rm -rf /var/lib/docker /var/lib/containerd /etc/docker /etc/apt/sources.list.d/docker.list /etc/apt/keyrings/docker.asc` |
| 8 | VM 105 `mg-ci-runner` | Cài GitHub Actions runner 2.338.2 vào `/opt/actions-runner` (tarball kiểm SHA-256 theo release notes), user hệ thống `ghrunner` (uid 999) thuộc nhóm `docker` — tương đương root trên VM riêng này (R-28). **Chưa đăng ký** với GitHub | `sudo /opt/actions-runner/svc.sh uninstall` (nếu đã cài service); `sudo rm -rf /opt/actions-runner && sudo userdel -r ghrunner` |
| 9 | VPS | Theo yêu cầu "tắt pipeline deploy ở VPS" (2026-11-16): gỡ 3 key deploy của GitHub Actions khỏi `/root/.ssh/authorized_keys`, đối chiếu đúng fingerprint — `github-actions-vnflashlearner-production` (đăng nhập từ `74.249.78.161`, dải Azure), `viettrimarket-github-actions`, `house-studio-github-actions`. **Giữ** `deploy@VNFlashLearner`: hơn 600 lần đăng nhập từ IP dân dụng và 4G Việt Nam ⇒ key của chủ dự án, không phải pipeline. Bản sao trước khi gỡ: `/root/meshguard-decommission-2026-11-16/root_authorized_keys.before-key-removal` | `sudo cp -p /root/meshguard-decommission-2026-11-16/root_authorized_keys.before-key-removal /root/.ssh/authorized_keys` |
| 10 | Host staging | Token Cloudflare do chủ dự án gửi trong hội thoại: ghi thẳng qua stdin của SSH thành `/opt/meshguard/secrets/edge/cloudflare_dns_token` (`0440 root:mg-sec-edge`), không ghi ở nơi khác; 6 bản sao trong transcript cục bộ đã được xóa. Kiểm trên host: token cấp account, còn hiệu lực; đọc/ghi DNS của `gta5web.online` được (bản ghi TXT thử tạo rồi xóa) ⇒ dùng được cho DNS-01. **Rộng hơn yêu cầu của D-1**: thấy thêm 1 zone khác và đọc được Workers của account | `sudo rm /opt/meshguard/secrets/edge/cloudflare_dns_token` (và thu hồi token trên dashboard) |
| 7 | Máy vận hành (Windows) | Cài `pre-commit` 4.7.0 cho user hiện tại và bật hook trong repo (`.git/hooks/pre-commit`: gitleaks + docs-check) | `pre-commit uninstall` (trong repo) và `python -m pip uninstall pre-commit` |

Kiểm sau bước 6 (cả hai VM): engine 29.9.3, Compose v5.7.1, storage overlayfs, cgroup systemd, `live-restore` bật; container thử từ image Alpine pin theo digest chạy được; `dockerd` không nghe cổng TCP nào.

Kiểm sau bước 5: không còn container nào chạy; không còn tiến trình nghe ở 80/443/3478/7881/7882; RAM khả dụng của VPS tăng từ 873 MiB lên 1,3 GiB.

## 4. VM đã tạo

Mọi VM: Ubuntu 24.04.5 LTS từ cloud image ở bước 3, cloud-init tạo user `mgdeploy` chỉ với public key của dự án (không mật khẩu), `qemu-guest-agent` chạy, gắn tag `meshguard`. IP do DHCP cấp.

| VMID | Tên | vCPU / RAM / đĩa | Bridge | IP | `onboot` | Vai trò |
|---|---|---|---|---|---|---|
| 104 | `mg-staging` | 8 / 24 GB / 250 GB | `vmbr0` | 192.168.1.8 | 1 | Host LAN staging |
| 105 | `mg-ci-runner` | 6 / 16 GB / 150 GB | `vmbr0` | 192.168.1.19 | 1 | Runner GitHub Actions tự host (D-12) |
| 106 | `mg-client-a1` | 2 / 2 GB / 20 GB | `vmbr0` | 192.168.1.21 | 0 | Client tenant A trong LAN |
| 107 | `mg-client-b1` | 2 / 2 GB / 20 GB | `vmbr0` | 192.168.1.22 | 0 | Client tenant B trong LAN |
| 108 | `mg-client-a2` | 2 / 2 GB / 20 GB | `lan10` | 192.168.10.11 | 0 | Client tenant A sau NAT của OPNsense |
| 109 | `mg-client-b2` | 2 / 2 GB / 20 GB | `lan10` | 192.168.10.12 | 0 | Client tenant B sau NAT của OPNsense |

Storage `nvme01` đã dùng 1,69% sau khi tạo.

## 5. Script đã chạy

Lưu nguyên văn trong [infrastructure-bootstrap/](infrastructure-bootstrap/) (không chứa secret; public key trong script tạo VM được thay bằng chỗ giữ chỗ):

| Script | Máy | Việc |
|---|---|---|
| `pve_fetch_image.sh` | Proxmox | Bước 3 |
| `pve_create_vms.sh` | Proxmox | Bước 4 |
| `pve_find_ips.sh` | Proxmox | Tìm IP của VM theo MAC (chỉ đọc + ping) |
| `vps_snapshot.sh` | VPS | Ghi trạng thái 3 dự án trước khi dừng (chỉ đọc + ghi `state.txt`) |
| `vps_stop_projects.sh` | VPS | Bước 5 (ghi `undo.sh` trước khi dừng) |
| `discovery_readonly.sh` | VM 104, VPS | Checklist A.2/A.3 (chỉ đọc) |
| `install_docker.sh` | VM 105, VM 104 | Bước 6 |
| `install_runner.sh` | VM 105 | Bước 8 |

## 6. Việc còn mở

| # | Việc | Ai | Chặn gì |
|---|---|---|---|
| 1 | ~~Đổi mật khẩu root của VPS và của Proxmox~~ — **đã đóng 2026-11-16**: chủ dự án quyết định không đổi, chấp nhận rủi ro; bản sao trên máy vận hành đã xóa (§1). Còn lại biện pháp bù: tắt đăng nhập SSH bằng mật khẩu trên VPS | Chủ dự án duyệt ở P1-T15 | — |
| 2 | ~~Tắt pipeline deploy của 3 dự án cũ~~ — **đã làm 2026-11-16** (bước 9: gỡ 3 key của GitHub Actions; workflow ở các repo đó sẽ báo lỗi xác thực SSH — chủ dự án có thể tắt hẳn workflow trên GitHub cho gọn). Trước đó: — nếu còn bật, một lần push có thể dựng lại các dự án và chiếm lại cổng 80/443/3478 | Chủ dự án | P1-T15 (gateway cần các cổng này) |
| 3 | Dịch vụ thư `mail.vnflashlearner.click` (postfix, dovecot, opendkim) vẫn chạy; timer `vnflash-mail-certs` lấy chứng chỉ từ volume Caddy của dự án cũ nên **không gia hạn được nữa** — chứng chỉ hiện tại hết hạn 2027-01-02. Giữ hay dừng dịch vụ thư | Chủ dự án | Không chặn |
| 4 | Cron `vnflashlearner-docker-cleanup` và `vnflashlearner-postgres-backup` vẫn chạy mỗi đêm: đã đọc mã — không khởi động lại container nào, không xóa volume hay bản dump (script backup có `set -eu` nên dừng trước bước xóa dump cũ); chỉ ghi lỗi vào log. Có thể gỡ khi dọn hẳn các dự án | Chủ dự án quyết định | Không chặn |
| 5 | DHCP reservation trên router cho VM 104 (192.168.1.8) và VM 105 (192.168.1.19) | Chủ dự án | Phase 1 (bản ghi DNS, tunnel) |
| 6 | ~~API token Cloudflare~~ — **đã có 2026-11-16** (bước 10). Còn: thay bằng token chỉ có quyền "Edit zone DNS" cho đúng `gta5web.online` (token hiện tại thấy 2 zone và đọc được Workers; đã đi qua dịch vụ AI trong hội thoại) rồi thu hồi token cũ | Chủ dự án | Không chặn |
| 7 | Các VM 104–107 có IPv6 công khai (SLAAC); chưa biết router có chặn IPv6 chiều vào không | Agent ở P1-T02 | V-35 (G1) |
| 8 | Thu hẹp `sudo` NOPASSWD của `mgdeploy` | Agent | P1-T02, P1-T15 |
| 10 | Repo GitHub của dự án đang **public** (kiểm 2026-11-16). Commit đầu đã công khai bản plan cũ, IP VPS và việc mật khẩu root của VPS bị lộ. GitHub khuyến cáo không gắn self-hosted runner vào repo public (PR từ fork có thể chạy code trên máy runner) ⇒ chưa đăng ký runner. Sau đó chủ dự án quyết định **giữ repo public và push** (2026-11-16): không gắn self-hosted runner vào repo này, CI chạy trên runner của GitHub (D-12); rủi ro công khai thông tin ghi ở R-29. Runner 2.338.2 trên VM 105 để nguyên, không đăng ký | — | — |
| 9 | Máy Windows dùng làm client thứ hai tới LAN của Proxmox qua tailnet riêng của chủ dự án: thử MeshGuard trên máy này cắt đường đó cho tới khi chuyển lại profile | Chủ dự án + agent | Lên lịch ở P1-T12 |
