# Runbook — Nghi thức khóa (key ceremony)

> **File viết tay — không sinh từ master.** Runbook của task **P2-T04a** (§20 của [bản master](../planning/implementation-master-plan.md)): sinh hai KEK (`kek-app`, `kek-ops` — §7.6), khóa khôi phục backup (đường DR — §17.1) và khóa ký manifest backup (§14.2, §17.1); chủ dự án giữ **2 bản offline**; diễn tập nạp lại KEK và giải mã thử một secret bằng KEK khôi phục. Bộ công cụ: [`infrastructure/host/key-ceremony/`](../../infrastructure/host/key-ceremony/ceremony.sh). Bằng chứng: [P2-T04a](../planning/evidence/P2-T04a.md). Định dạng keyring: [P2-T04](../planning/evidence/P2-T04.md).

Thời lượng dự kiến cho chủ dự án: **khoảng 25 phút** (chủ yếu là chép tay và gõ lại).

## 1. Vai trò

| Vai trò | Ai | Làm gì | Không bao giờ |
|---|---|---|---|
| **Chủ dự án** | Người giữ khóa | Có mặt suốt buổi. Chạy hai bước có vật liệu khóa (`show-offline`, `verify-offline`) trong **terminal của chính mình** (`ssh -t`). Chép 2 bản giấy, cất ở 2 nơi | Chụp ảnh, gõ khóa vào máy/ứng dụng khác, đọc khóa thành tiếng |
| **Người điều phối** | Agent hoặc người vận hành | Chuẩn bị, chạy các bước **không có vật liệu khóa** (`preflight`, `generate`, `drill`, `cleanup`, `status`) qua SSH **không TTY**, ghi giá trị công khai vào repo | Chạy `show-offline`/`verify-offline` (script từ chối khi không có TTY — exit 3), nhìn màn hình của chủ dự án |

Mọi giá trị bí mật sinh **ngay trên host** và chỉ xuất hiện ở hai chỗ: file khóa trên host (KEK, khóa ký manifest) và màn hình của chủ dự án lúc `show-offline`. Identity khôi phục backup chỉ nằm trên **tmpfs riêng** của nghi thức rồi bị `shred` ở bước `cleanup` — sau đó **chỉ còn trên 2 bản giấy**.

## 2. Nghi thức sinh ra những gì

| Khóa | Nơi ở trên host | Quyền | Dùng bởi | Bản offline |
|---|---|---|---|---|
| KEK `kek-app` | `/opt/meshguard/secrets/kek-app/<kek_id>` + `ACTIVE` | thư mục `root:mg-sec-app 0750`, file `0440` | api, worker (nhóm 20001) | **2 bản giấy** |
| KEK `kek-ops` | `/opt/meshguard/secrets/kek-ops/<kek_id>` + `ACTIVE` | thư mục `root:mg-sec-worker 0750`, file `0440` | chỉ worker (nhóm 20003) | **2 bản giấy** |
| Khóa khôi phục backup (age X25519 identity) | **không có** — chỉ tmpfs `/run/mg-key-ceremony` trong lúc làm nghi thức | tmpfs riêng `0700`, file `0400` | người vận hành khi mất host (đường DR) | **2 bản giấy** |
| Recipient khôi phục (`age1…`, công khai) | `/opt/meshguard/core/keys/backup-recovery.age-recipient` | `root:root 0644` | pg-backup, Agent mã hóa tới đây (P2-T03a, P3-T11) | repo: `MG_BACKUP_RECOVERY_RECIPIENT` |
| Khóa ký manifest backup (Ed25519, PKCS#8 PEM) | `/opt/meshguard/secrets/agent/manifest_signing_key` | thư mục `root:root 0700`, file `root:root 0400` | Agent (chạy root — §14.2) | **không** (xem dưới) |
| Khóa công khai ký manifest | `/opt/meshguard/core/keys/manifest-signing.pub.pem` | `0644` | Worker, Agent kiểm chữ ký | repo: `MG_BACKUP_MANIFEST_PUBKEY` |
| Bản ghi KCV | `/opt/meshguard/core/keys/kek.kcv` | `0644` | đối chiếu | repo: bằng chứng P2-T04a |

- `kek_id` = `<MG_ENV>-<app|ops>-<YYYYMMDD-HHMM UTC>`, ví dụ `staging-app-20261117-1432` — mỗi lần sinh một tên mới, nên bản giấy của một lần làm hỏng không bao giờ trùng tên với lần làm lại.
- **Khóa ký manifest không có bản offline** (đúng §17.1: bản offline chỉ cho KEK và khóa giải mã backup): mất nó thì sinh khóa mới; archive cũ vẫn kiểm được bằng khóa **công khai** cũ trong lịch sử repo.
- Định dạng file KEK: đúng 64 ký tự hex + xuống dòng (P2-T04) — chính là thứ chủ dự án chép.

### KCV — key check value

Mỗi KEK có một **KCV** công khai, ghi cạnh bản giấy và trong repo, để kiểm một bản chép/nhập lại mà không lộ khóa:

```text
KCV = hex( HMAC-SHA256( key = KEK 32 byte, message = "meshguard/kek-kcv/v1" ) )[:8]
```

Cùng một định nghĩa trong Go (`secrets.KCVLabel`, `Keyring.KCV`) và trong script (Python `hmac`). Vector thử: khóa = 32 byte `00 01 02 … 1f` ⇒ `1dccd334`; khóa = 32 byte `ff` ⇒ `185483a4`. Không dùng KCV kiểu cổ điển `AES_K(0¹²⁸)`, vì với AES-GCM khối đó chính là khóa GHASH `H`.

## 3. Điều kiện trước buổi nghi thức (người điều phối)

Làm xong **trước** khi mời chủ dự án; không bước nào ở đây chạm vật liệu khóa.

1. Nhánh của P2-T04a đã merge vào `main`; workflow `images` xanh; ghi digest image worker vào `versions.lock` bằng commit riêng (như `[images.mg-idp]`):

   ```toml
   [images.mg-worker]
   image = "ghcr.io/zhaduchanhzz/network-access-mesh/worker"
   tag = "<commit SHA>"
   index = "sha256:<digest từ GHCR>"
   ```

2. Đồng bộ repo lên host (`~/mg`, như các runbook khác; thư mục `bin/` bị `.gitignore` nên không bị ghi đè):

   ```bash
   git archive --format=tar HEAD | ssh mgdeploy@<MG_LAN_IPV4> 'mkdir -p ~/mg && tar -xf - -C ~/mg'
   ```

3. Build `age`/`age-keygen` trên **máy build** (không chạy trên host; chi tiết ở [mục 9](#9-công-cụ-age)) rồi chép sang host:

   ```bash
   # máy build (VM mg-ci-runner), trong bản sao repo: in "OK … sha256 …" cho cả hai binary, exit 1 nếu khác versions.lock
   sudo bash infrastructure/host/key-ceremony/build-age.sh ~/mg-age
   # từ máy điều phối: build → host (ceremony.sh kiểm lại sha256 trước mỗi lần dùng)
   ssh mgdeploy@<IP máy build> 'sudo tar -C ~/mg-age -cf - age age-keygen' |
     ssh mgdeploy@<MG_LAN_IPV4> 'mkdir -p ~/mg/infrastructure/host/key-ceremony/bin && tar -xf - -C ~/mg/infrastructure/host/key-ceremony/bin'
   ```

4. Kéo image worker theo digest lên host: `ssh mgdeploy@<MG_LAN_IPV4> 'sudo docker pull ghcr.io/zhaduchanhzz/network-access-mesh/worker@sha256:<digest>'`.
5. Chạy `preflight` (mục 4, bước B0) — phải **ĐẠT**. Nếu báo swap đang bật: `sudo swapoff -a` trong lúc làm nghi thức (hoàn tác sau `cleanup`: `sudo swapon -a`).
6. Chủ dự án chuẩn bị: 2 tờ giấy (ghi sẵn "Bản 1", "Bản 2"), bút bi mực không phai, 2 phong bì không nhìn xuyên được, phòng không có camera/người khác; terminal **không** ghi log phiên (tắt logging của Windows Terminal/PuTTY, không chạy trong `script`, không chia sẻ màn hình, không ghi hình).

`<MG_LAN_IPV4>` là giá trị trong `infrastructure/environments/staging/staging.env` (`python tools/mgenv.py show infrastructure/environments/staging/staging.env`).

## 4. Trình tự (khoảng 25 phút)

Lệnh của **người điều phối** (SSH không TTY, output không có bí mật — được phép lưu vào bằng chứng):

```bash
SSH="ssh -i ~/.ssh/id_ed25519_meshguard -o IdentitiesOnly=yes -o BatchMode=yes mgdeploy@<MG_LAN_IPV4>"
K="sudo bash ~/mg/infrastructure/host/key-ceremony/ceremony.sh"
```

Lệnh của **chủ dự án** — trong cửa sổ terminal của mình (PowerShell / Windows Terminal), có `-t`:

```powershell
ssh -t -i $HOME\.ssh\id_ed25519_meshguard -o IdentitiesOnly=yes mgdeploy@<MG_LAN_IPV4> "sudo bash ~/mg/infrastructure/host/key-ceremony/ceremony.sh <bước>"
```

| Bước | Ai | Lệnh | Thời gian | Kết quả cần thấy |
|---|---|---|---|---|
| B0 | điều phối | `$SSH "$K preflight"` | < 1 phút | `KẾT QUẢ: ĐẠT`; không thay đổi gì |
| B1 | điều phối | `$SSH "$K generate"` | < 1 phút | danh sách file tạo ra kèm owner/mode, `kek_id` + KCV của hai KEK, recipient, khóa công khai ký manifest; dòng hoàn tác |
| B2 | **chủ dự án** | `… ceremony.sh show-offline` | ~12 phút | 3 màn hình (kek-app, kek-ops, khóa khôi phục); chép mỗi mục lên **cả hai** bản rồi Enter (màn hình bị xóa) |
| B3 | **chủ dự án** | `… ceremony.sh verify-offline --copy 1` | ~4 phút | gõ lại từ **bản 1** (không hiện chữ); mỗi dòng báo `khớp` hoặc số nhóm sai; cuối: `Bản 1: PASS` |
| B4 | **chủ dự án** | `… ceremony.sh verify-offline --copy 2` | ~4 phút | như B3 với **bản 2**; `Bản 2: PASS` |
| B5 | điều phối | `$SSH "$K drill"` | < 1 phút | với mỗi bản: `kek-drill: PASS`, hai đối chứng âm đúng, khóa khôi phục giải mã được tin thử; `KẾT QUẢ: PASS` |
| B6 | điều phối | `$SSH "$K cleanup"` | < 1 phút | `Đã shred … umount`; từ chối nếu chưa có 2 bản PASS + drill PASS |
| B7 | điều phối | `$SSH "$K status"` | < 1 phút | `kek_id` + KCV, hai dòng `MG_BACKUP_*=` để ghi vào repo (mục 8) |
| B8 | chủ dự án | — | ~2 phút | niêm phong 2 phong bì, cất ở 2 nơi khác nhau (mục 6) |

Script giữ một khóa (`flock`) suốt mỗi bước: khi chủ dự án đang ở B2–B4, lệnh của người điều phối bị từ chối ("một bước khác … đang chạy") — đợi chủ dự án báo xong.

### B2 — `show-offline`

- Chỉ chạy khi **stdin và stdout đều là terminal tương tác**; SSH không `-t`, chuyển hướng output vào file hay pipe ⇒ từ chối (exit 3) **trước khi đọc bất kỳ file khóa nào**.
- Mỗi mục một màn hình; Enter xóa màn hình **và lịch sử cuộn** (`ESC[3J`). Ctrl-C bất cứ lúc nào cũng xóa màn hình rồi thoát; chạy lại được (ví dụ để chép lại một bản).
- Không có gì thay đổi trên host.

### B3, B4 — `verify-offline --copy 1|2`

- Echo của terminal **tắt suốt bước** (kể cả phím gõ trước lời nhắc); `kek_id` và KCV (không bí mật) được script in lại sau khi Enter.
- Thứ tự: với mỗi KEK — `kek_id`, 4 dòng giá trị (mỗi dòng 4 nhóm), KCV ghi trên giấy; rồi 3 dòng của khóa khôi phục (chỉ phần sau `AGE-SECRET-KEY-1`).
- Dấu cách, gạch nối được bỏ qua; hoa/thường như nhau. Dòng sai độ dài/ký tự ⇒ hỏi lại (không tính lượt). Dòng khác khóa thật ⇒ báo **số nhóm** sai, cho gõ lại tối đa 3 lần — gõ lại vẫn sai nghĩa là **bản giấy sai**: chạy lại `show-offline`, sửa bản giấy, rồi chạy lại bước này.
- Đạt khi: `kek_id` đúng, cả 4 dòng khớp, KCV trên giấy = KCV của giá trị vừa gõ = KCV khóa đang chạy; khóa khôi phục gõ lại suy ra **đúng** recipient đã lưu (mã kiểm bech32 bắt mọi lỗi một ký tự).
- Bản gõ lại được lưu trên tmpfs (`recovered-<n>/`, cùng owner/mode như keyring thật) cho bước drill, và bị `shred` ở `cleanup`.

### B5 — `drill` (diễn tập nạp lại KEK)

Với mỗi bản đã gõ lại, script chạy `meshguard-worker kek-drill` trong image worker (theo digest) với `--network none`, rootfs chỉ-đọc, `--cap-drop ALL`, `no-new-privileges`, user `65532` + nhóm `20001`/`20003`, mount **chỉ-đọc** keyring thật (`/live`) và keyring dựng lại từ giấy (`/recovered`). `kek-drill` đọc cả hai bằng **đúng** `LoadKeyring` (quy tắc như lúc dịch vụ khởi động) và đạt khi: cùng tập `kek_id`, cùng `ACTIVE`, cùng KCV; với **mọi** `kek_id`, một DEK ngẫu nhiên bọc bằng keyring này (AAD thật `mgdek/v1|…`) mở được bằng keyring kia **theo cả hai chiều**, và một secret thử niêm phong dưới DEK đó (AAD thật `mgsec/v1|…`) giải mã được — đúng tiêu chí "giải mã thử một secret bằng KEK khôi phục" của P2-T04a; `kek-app` và `kek-ops` không được trùng khóa. Output chỉ có `kek_id`, KCV và PASS/FAIL.

Kèm hai đối chứng âm (để drill không thể "luôn đạt"): bản sao sai **1 ký tự hex** ⇒ `kek-drill` phải FAIL; với khóa khôi phục, một tin thử 4096 byte mã hóa tới recipient đã lưu phải giải mã được bằng identity gõ lại và **không** giải mã được bằng một identity khác.

## 5. Ghi gì lên mỗi bản giấy

Mỗi bản (Bản 1 và Bản 2 giống hệt nhau):

```text
MeshGuard — môi trường staging — BẢN 1/2 — ngày ____/____/____ — người chép: ______________
KEK kek-app   kek_id: staging-app-________-____   (ACTIVE)
   dòng 1: ____ ____ ____ ____
   dòng 2: ____ ____ ____ ____
   dòng 3: ____ ____ ____ ____
   dòng 4: ____ ____ ____ ____
   KCV: ________
KEK kek-ops   kek_id: staging-ops-________-____   (ACTIVE)
   dòng 1 … dòng 4 như trên              KCV: ________
Khóa khôi phục backup (age):  AGE-SECRET-KEY-1
   dòng 1: ____ ____ ____ ____ ____
   dòng 2: ____ ____ ____ ____ ____
   dòng 3: ____ ____ ____ ____ __
Đã kiểm bằng verify-offline: ngày ____ — PASS — ký: ______
```

- KEK: 64 ký tự hex `0–9 a–f`; viết rõ `b`/`6`, `a`/`d`, `0`. Khóa khôi phục: bech32 chữ hoa — **không** có `1 B I O`; viết rõ `0/Q/D`, `5/S`, `2/Z`, `6/G`, `U/V`.
- Chép xong mỗi mục: đọc lại **từng nhóm** trên màn hình so với giấy trước khi Enter. Lỗi còn sót sẽ bị B3/B4 bắt và chỉ ra số nhóm.
- Recipient (`age1…`) và khóa công khai **không** cần chép: chúng nằm trong repo.

## 6. Cất giữ

- **Hai nơi khác nhau về vật lý** (ví dụ: két tại nhà và két ngân hàng / két của người được ủy thác ở tòa nhà khác) — một sự cố (cháy, mất trộm) không được mất cả hai.
- Phong bì không nhìn xuyên, niêm phong, ký ngang mép dán; nhãn ngoài chỉ ghi "MeshGuard staging — khóa offline — bản 1/2", không ghi nội dung.
- **Không bao giờ**: chụp ảnh, scan, in (bộ nhớ/hàng đợi máy in), gõ vào máy khác hay điện thoại, lưu cloud, ghi chú, email, chat, trình quản lý mật khẩu; không chép thêm bản thứ ba ngoài nghi thức.
- Ai biết nơi cất: chủ dự án (và người được ủy thác nếu có). Bằng chứng trong repo chỉ ghi "đã cất ở 2 nơi" — không ghi địa điểm.
- Chia khóa (Shamir, M-of-N) là tùy chọn của §17.1 — chưa dùng ở staging; cân nhắc cho production.

## 7. Thất bại và hoàn tác

| Tình huống | Làm gì |
|---|---|
| `preflight` KHÔNG ĐẠT | Sửa đúng mục báo lỗi (nhóm, thư mục, swap, ghi log sudo/`pam_tty_audit`, age, image); chạy lại. Không có gì thay đổi |
| `generate` lỗi giữa chừng | Script tự gỡ mọi thứ vừa tạo (shred khóa, umount tmpfs) và in danh sách đã gỡ; sửa nguyên nhân rồi chạy lại từ B0 |
| Chép sai / `verify-offline` FAIL | Chạy lại `show-offline`, sửa bản giấy, chạy lại `verify-offline --copy <n>` (ghi đè bản gõ lại trước) |
| `drill` FAIL | Đọc dòng `FAIL —` (chỉ có `kek_id`/KCV): thường là bản giấy sai ⇒ như dòng trên. Nếu chính keyring thật sai (không xảy ra với `generate`) ⇒ bỏ dở và làm lại |
| `cleanup` từ chối | Chưa có 2 bản PASS + một drill PASS — hoàn thành B3–B5. Muốn bỏ dở: `cleanup --abort` |
| Bỏ dở cả buổi (**trước khi** dịch vụ nào dùng khóa) | `$SSH "$K cleanup --abort"` rồi `$SSH "$K undo --keys-never-used"` (shred và gỡ mọi file vừa tạo; từ chối nếu có container từng mount keyring hoặc thư mục khóa của Agent); **hủy** mọi bản giấy của lần này; làm lại từ B0 |
| Sau khi api/worker đã dùng khóa (P2-T16 trở đi) | **Không bao giờ** `undo` — mất KEK là mất mọi secret. Đổi khóa = xoay KEK (P6-T05) |
| Mất kết nối giữa B2–B4 | Bước đang chạy dừng và xóa màn hình/bật lại echo; khóa `flock` được nhả; chạy lại bước đó |

Mỗi bước in ra "Thay đổi: …" và cách hoàn tác của chính nó. `status` (không thay đổi gì) cho biết đang ở đâu.

## 8. Ghi vào repo sau buổi nghi thức (người điều phối)

Chỉ giá trị **công khai** (kiểm bởi `tools/test_mgenv.py` và gitleaks):

1. `infrastructure/environments/staging/staging.env`: hai dòng `MG_BACKUP_RECOVERY_RECIPIENT=…`, `MG_BACKUP_MANIFEST_PUBKEY=…` lấy từ `status`.
2. [Bằng chứng P2-T04a](../planning/evidence/P2-T04a.md), mục "Nghi thức (chờ chủ dự án)": ngày giờ, digest image worker, `kek_id` + KCV của hai KEK, recipient, khóa công khai ký manifest, output của B0/B1/B5/B6/B7 (không có bí mật), xác nhận của chủ dự án về 2 bản đã cất.
3. `current.md` (mục 2 và nhật ký thay đổi), `ROADMAP.md`, cột trạng thái của P2-T04a trong master §20.

Không bao giờ ghi: giá trị KEK, identity khôi phục, khóa ký manifest, ảnh/scan bản giấy, nơi cất.

## 9. Công cụ age

Host không có `age`. Chọn **build từ mã nguồn** thay vì gói Ubuntu:

- `build-age.sh` chạy `go install filippo.io/age/cmd/{age,age-keygen}@v1.3.2` trong image golang **pin theo digest**, `CGO_ENABLED=0`, `-trimpath`; Go tải mã qua proxy.golang.org và kiểm từng module với **checksum DB** (sum.golang.org) — `GOPROXY`/`GOSUMDB` đặt tường minh. Không chạy script bên thứ ba nào.
- Build **tái lập**: 3 lần build (cache trống, 2 cách gọi) cho cùng sha256; giá trị ghi ở `versions.lock` `[sources.age]` cùng commit tag và hash module `h1:`.
- Binary tĩnh được chép sang host qua SSH; `ceremony.sh` kiểm sha256 + phiên bản ở `preflight` và chép vào tmpfs (đã kiểm lại sha256) trước mỗi lần dùng.
- Không dùng gói `age` của Ubuntu 24.04: bản 1.1.1 build bằng Go 1.22 của distro, và cài gói lên host là loại thay đổi cần duyệt riêng (quy tắc dự án); bản build của ta dùng toolchain Go 1.27.4 đã pin, giống phần còn lại của nền tảng.

## 10. Khi mất host (đường DR — tóm tắt)

1. Dựng host mới theo `current.md` mục 3 (tới `layout.sh`).
2. Dựng lại keyring từ một bản giấy: chủ dự án, trong terminal của mình, ghi từng KEK vào `/opt/meshguard/secrets/kek-app/<kek_id>` (`kek-ops` tương tự) **không qua echo** — ví dụ `sudo bash -c 'umask 077; read -rs v; printf "%s\n" "${v//[ -]/}" > /opt/meshguard/secrets/kek-app/<kek_id>'`, rồi `ACTIVE`, owner/mode như mục 2. `ceremony.sh status` in KCV của file vừa ghi — phải trùng KCV trên giấy và trong bằng chứng. Sau khi dịch vụ chạy, `/readyz` (Probe của SecretStore, P2-T16) xác nhận keyring mở được DEK trong DB đã khôi phục.
3. Giải mã backup bằng khóa khôi phục trên một máy offline: ghi identity vào file trên tmpfs (`AGE-SECRET-KEY-1` + 3 dòng), `age -d -i <file> <backup>.age`; xong thì `shred`.

Công cụ dựng lại keyring từ giấy (thay bước 2 làm tay) và diễn tập mất host đầy đủ thuộc **P6-T04a** (dựng lại trên máy sạch từ offsite + KEK offline).

## 11. Production (P7-T11)

- Làm nghi thức **mới** cho production — không bao giờ dùng lại khóa staging.
- Khóa khôi phục backup nên sinh trên một **máy offline** (laptop không mạng, khởi động từ live USB): `age-keygen` vào tmpfs, chép 2 bản giấy, `age-keygen -y` lấy recipient — chỉ **recipient** được đưa sang host/repo; host production không bao giờ thấy identity. (Ở staging, identity sinh trên host trong tmpfs và bị shred — chấp nhận được cho môi trường không có dữ liệu thật.)
- Cân nhắc recipient post-quantum lai ML-KEM-768 + X25519 (`age-keygen -pq`, có từ age v1.3) vì backup sống lâu; định dạng identity khác nên bộ kit cần thử lại trước khi dùng.
- KEK và khóa ký manifest vẫn sinh trên host (dịch vụ dùng chúng trực tuyến).

## 12. Xoay khóa

Xoay KEK (hằng năm hoặc khi có sự cố — §7.6): thêm file KEK mới vào keyring, `ACTIVE` trỏ tới nó, khởi động lại api/worker, job `Rewrap`, gỡ file cũ khi `KEKUsage` không còn `kek_id` cũ (quy trình ở [P2-T04](../planning/evidence/P2-T04.md)). KEK mới cần bản offline mới theo cùng nghi thức; bản giấy của KEK cũ chỉ hủy sau khi không còn DEK và backup nào phụ thuộc. Runbook và diễn tập: **P6-T05**.

## 13. Thử bộ kit (máy build, không phải host)

```bash
# cần: sudo không mật khẩu, Docker, image worker có kek-drill (build từ repo), age/age-keygen từ build-age.sh
sudo bash infrastructure/host/key-ceremony/build-age.sh ~/mg-age
sudo docker build -f infrastructure/docker/app/Dockerfile --build-arg APP=worker -t mg-worker:test .
python3 -I infrastructure/host/key-ceremony/test_ceremony.py --worker-image "$(sudo docker image inspect -f '{{.Id}}' mg-worker:test)" \
  --age-dir ~/mg-age --create-groups
```

`test_ceremony.py` dựng một gốc giả lập (`MGKC_ROOT`) với khóa dùng một lần, chạy mọi bước — `show-offline`/`verify-offline` qua pseudo-terminal — kể cả các ca từ chối, ca nhập sai, đối chứng âm và hoàn tác; nó không bao giờ in vật liệu khóa. Kết quả gần nhất: [P2-T04a](../planning/evidence/P2-T04a.md).
