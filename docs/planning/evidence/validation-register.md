# Sổ đăng ký kiểm chứng

> **File viết tay — không sinh từ master.** Đầu ra của task **P0-T06**: theo dõi **kết quả** của từng mục kiểm chứng ở §22.4 của [bản master](../implementation-master-plan.md). Nội dung cần kiểm chứng, task và gate lấy nguyên từ §22.4 ngày 2026-11-16 — khi §22.4 đổi thì cập nhật bảng này.
>
> Cột *Kết quả*: `chưa chạy` · `đạt (functional)` · `đạt (network E2E verified)` · `không đạt` · `ngoại lệ (văn bản)`. Cột *Bằng chứng* trỏ tới file trong thư mục này. Quy ước: [README](README.md).

| Mã | Điều cần kiểm chứng | Task | Gate | Kết quả | Bằng chứng |
|---|---|---|---|---|---|
| V-01 | DERP + control upgrade qua Caddy | P1-T05a, P1-T12 | G1 | **đạt — network E2E verified (LAN NAT)** ở spike P1-T05a: 2 client thật (một sau NAT), ép relay, 20 MiB TCP qua `DERP(mg-spike)`, sha256 khớp; đường qua VPS gateway: P1-T18 | [P1-T05a.md](P1-T05a.md) |
| V-02 | STUN dùng chung (`stund` tại điểm vào công khai) trả đúng IP/port công khai và được client của mọi tenant dùng | P1-T18, P5-T02a | G1 | chưa chạy | — |
| V-03 | Upstream động theo nhãn + attach network lúc chạy | P1-T12d, P1-T10a | G1 | **đạt (functional)**: gắn/gỡ network lúc chạy 0 stream bị đóng, không reload; reload với `stream_close_delay 5m` hoãn 299 s rồi đóng đồng loạt; 1 000 nhãn ngẫu nhiên + tenant đang dừng đều 404, **0** truy vấn DNS ra khỏi host (DNS nhúng của Docker trả lời tại chỗ tên một nhãn rooted) | [P1-T08.md](P1-T08.md), [P1-T12d.md](P1-T12d.md) |
| V-04 | Headscale chạy non-root, read-only | P1-T11 | G1 | đạt (functional) | [P1-T11.md](P1-T11.md) |
| V-05 | Chặn `/verify` không ảnh hưởng embedded DERP | P1-T05a | G1 | **đạt — network E2E verified (LAN NAT)**: `/verify` ⇒ 404 ở edge, relay với `verify_clients: true` vẫn chạy | [P1-T05a.md](P1-T05a.md) |
| V-06 | Key tạo không kèm `expiration`; policy rỗng; mã lỗi HTTP của `SetPolicy`; `/key` cần `?v=`; decoder policy với khóa khác kiểu chữ, khóa `#`, giá trị `null` | P2-T10 | G2 | chưa chạy | — |
| V-07 | Chuyển hướng `/register/<auth_id>` về Portal | P4-T07 | G4a | chưa chạy | — |
| V-08 | Client 1.104.x trên 5 hệ điều hành | P1-T12e (sơ bộ), P5-T03 | G5 | chưa chạy | — |
| V-09 | Độ trễ thu hồi và lan truyền policy; hành vi peer offline | P5-T04, P5-T07 | G5 | chưa chạy | — |
| V-10 | Tunnel direct khi control plane của tenant ngừng | P1-T13 | G1/G5 | **đạt (network E2E verified, LAN NAT)** cho restart có kiểm soát: control của A ngừng ~2,7 s, luồng TCP trên tunnel direct gián đoạn tối đa 52 ms (nhịp 50 ms); ngừng hẳn: P6-T09 | [P1-T13.md](P1-T13.md) |
| V-11 | Hành vi client khi Noise key đổi / restore bản cũ | P3-T11 | G3/G6 | **dữ liệu sơ bộ (P1-T19)**: Noise key đổi (dựng lại instance) ⇒ client cũ vẫn `Running` bằng netmap cache, mọi lời gọi control thất bại, không tự chuyển sang cần đăng nhập — phải đăng ký lại; phần restore bản cũ: P3-T11/P6 | [P1-T19.md](P1-T19.md) |
| V-12 | `VACUUM INTO` trên DB đang hoạt động + restore | P3-T11, P6-T04 | G3/G6 | chưa chạy | — |
| V-13 | Tài nguyên/instance, mật độ/host, chi phí polling (bcrypt) | P6-T08 | G6 | chưa chạy | — |
| V-14 | CrowdSec không khóa nhầm NAT của tenant | P6-T07b | G6 | chưa chạy | — |
| V-15 | Quy mô số realm của IdP | P6-T08 | Trước mốc 100 tenant | chưa chạy | — |
| V-16 | Control upgrade + DERP qua chuỗi VPS `l4proxy` (TCP, PROXY v2) → tunnel → Caddy | P1-T18 | G1 | chưa chạy | — |
| V-17 | Edge nhận đúng IP client qua PROXY protocol và chỉ chấp nhận PROXY header từ peer tunnel | P1-T17, P1-T18 | G1 | chưa chạy | — |
| V-18 | Stream dài (control long-poll, DERP) không bị `l4proxy`/tunnel cắt khi nhàn rỗi | P1-T18 | G1 | chưa chạy | — |
| V-19 | CAA giới hạn cấp chứng chỉ về `dns-01` + đúng tài khoản ACME | P1-T18 | G1 / G6 | chưa chạy | — |
| V-20 | Thông lượng và độ trễ của đường relay qua VPS + uplink của LAN | P5-T06 | G5 / G6 | chưa chạy | — |
| V-21 | `node.expiry` chỉ là mặc định (hạn do client yêu cầu được ưu tiên) ⇒ kiểm cả việc client thật thực thi hạn lẫn việc nền tảng kẹp hạn | P2-T10, P2-T13 (ii); P5-T07a (i) | G2 (ii); G5 (i) | chưa chạy | — |
| V-22 | Nhận diện NAT với một STUN endpoint duy nhất (§10.4) | P5-T06 | G5 | chưa chạy | — |
| V-23 | Offboarding phía IdP: user bị vô hiệu ở IdP không đăng nhập lại được Portal và node bị expire | P4-T09 | G4b | chưa chạy | — |
| V-24 | `tests` của policy có khẳng định được quyền chỉ đến từ `via`/`autogroup:self` hay không | P5-T01 | G5 | chưa chạy | — |
| V-25 | Đếm được số stream nâng cấp đang mở theo hostname tại edge (§10.6) | P6-T01 | G6 | chưa chạy | — |
| V-26 | `AuthRegister` với Auth ID không đến từ luồng `/register/` (phiên SSH-check) không làm Headscale lỗi nghiêm trọng; `AuthApprove` trên Auth ID đăng ký (§7.4); trạng thái policy khi `SetPolicy` trả lỗi sau khi đã hoán đổi trong bộ nhớ (§7.3) | P2-T10 | G2 | chưa chạy | — |
| V-27 | Official client liên lạc những host nào của Tailscale Inc. khi dùng Headscale (CL-16), và `TS_NO_LOGS_NO_SUPPORT` có chặn được việc gửi log hay không | P1-T12e (sơ bộ, Linux), P5-T03 | G5 | chưa chạy | — |
| V-28 | Hành vi adapter nêu theo đọc source của reviewer, chưa chạy thử: `GetNode` so với `ListNodes` (`subnet_routes`, user của tagged node); `SetTags` với danh sách rỗng; `AuthRegister` trên machine key đã có node — của chính user (re-auth, không tạo node mới) và của user khác (§7.4, §13.4) | P2-T10 | G2 | chưa chạy | — |
| V-29 | Peer relays với client stable hiện hành (CL-13, §10.5) | P5-T11 (tùy chọn) | Không chặn gate (chỉ khi người dùng yêu cầu) | chưa chạy | — |
| V-30 | Site public của edge chỉ `bind` IP trên `mg-edge` mà mọi cổng publish (LAN-direct, tunnel-facing) vẫn hoạt động; từ network tenant không tới được site hay listener nào của edge (§14.3) | P1-T10, P1-T12c | G1 | **đạt một phần**: site public chỉ bind 10.249.0.2 vẫn nhận DNAT từ cổng publish LAN-direct; từ network tenant không tới được listener nào của edge (IT-14 30/30 ở cả hai chế độ, sau khi thêm bộ lọc tầng bridge); còn listener tunnel-facing (P1-T16/T17) | [P1-T06.md](P1-T06.md), [P1-T12c.md](P1-T12c.md) |
| V-31 | cAdvisor không có Docker socket vẫn ghép được nhãn tenant: nhãn `id` chứa container ID và join được với `meshguard_instance_info` (§16.1) | P6-T01 | G6 | chưa chạy | — |
| V-32 | Edge trả tĩnh `/bootstrap-dns` không ảnh hưởng client (§14.6) | P1-T12 | G1 | **đạt (network E2E verified, LAN NAT)**: client đăng ký, direct và relay bình thường khi edge trả JSON tĩnh; client không gọi `/bootstrap-dns` khi DNS hệ thống hoạt động | [P1-T12.md](P1-T12.md) |
| V-33 | Edge gắn ~100–300 network tenant lúc chạy (thời gian attach, restart/recreate, phân giải tên upstream) và nền tảng tự phục hồi sau reboot host / restart `dockerd` | P1-T20, P1-T21, P3-T14, P6-T08 | G1 (sơ bộ) / G3 / G6 | **đạt sơ bộ (functional, P1-T20)**: 100 network — restart edge 11,0 s, recreate + gắn lại 15,9 s; 300 network — 33,1 s / 47,6 s; phân giải tên < 1 ms; reboot host / restart `dockerd` (P1-T21) chờ chấp thuận | [P1-T20.md](P1-T20.md) |
| V-34 | STUN publish trực tiếp theo tenant qua Docker, gồm IPv6 (EG-10, §2.7) — **chỉ** khi dùng phương án dự phòng (a) ở §10.3 | Chỉ mở khi V-02 không đạt (P1-T18) | G1 | chưa chạy | — |
| V-35 | Host staging không lộ cổng nào ra Internet qua IPv6 công khai của LAN (thêm 2026-11-16 sau discovery, Appendix A.4) | P1-T02, P1-T06 | G1 | đạt (functional) phía host — chưa thử từ mạng IPv6 bên ngoài | [P1-T02.md](P1-T02.md), [P1-T06.md](P1-T06.md) (cổng 80/443 của edge chỉ bind 192.168.1.8) |
| V-36 | derper riêng của tenant sau proxy tầng 4 SNI passthrough dùng chung cổng 443 (DP-09) — **chỉ** khi dùng phương án lùi (e) ở §10.3 (thêm 2026-11-16 khi `docs-check` phát hiện REQUIRES VALIDATION chưa có mã) | Chỉ mở khi V-01 không đạt (P1-T05a) | G1 | chưa chạy | — |
