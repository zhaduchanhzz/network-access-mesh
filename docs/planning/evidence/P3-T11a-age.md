# P3-T11a — `age` build lại với `golang.org/x/crypto` v0.56.0 (phát hiện chuỗi cung ứng)

> **File viết tay — không sinh từ master.** Việc phát sinh từ [P3-T11](P3-T11.md) mục 11 (grype báo 2 High trong `age` của image agent). Không chạm host staging, VPS hay DNS. Quy ước: [README](README.md).

| Mục | Giá trị |
|---|---|
| Ngày | 2026-11-18 (UTC+7) |
| Người thực hiện | Agent (Claude Code), worktree nhánh `fix-age` (từ `main` @ `8689c47`) |
| Môi trường | dev/CI — VM build `mgdeploy@192.168.1.19` (VM 105, dùng chung): Go trong `golang:1.27.4-trixie` pin digest (`[images.golang]`), syft 1.56.0 + grype 0.121.1 (đúng bản và SHA-256 của `images.yml`, cùng một DB grype cho mọi lần quét bên dưới), govulncheck v1.9.0 (như `go.yml`); mọi tài nguyên tiền tố `fixage` |
| Phiên bản mới (pin) | `golang.org/x/crypto` **v0.56.0** trong `age` (trước: v0.55.0); `filippo.io/age` giữ **v1.3.2** (bản mới nhất) |
| Nhãn kết quả | **functional** (dev/CI, §22.1) — chưa triển khai |
| Commit | `45a0dab` (code) + commit bằng chứng này |

## 1. Phát hiện

- grype (workflow `images`, đường SBOM syft → grype) báo **2 High** trong `/usr/local/bin/age` của image agent (P3-T11) và image backup (P2-T03a): **GO-2026-6354** (CVE-2026-78662) và **GO-2026-6355** (CVE-2026-56855) — DoS do kênh SSH bị khóa chết trong `golang.org/x/crypto/ssh` (symbol `Dial`, `NewClientConn`, `NewServerConn`, `channel.handlePacket` …), sửa ở **v0.56.0**. `filippo.io/age` v1.3.2 khai báo `golang.org/x/crypto v0.55.0`; chưa có bản age nào mới hơn.
- **Không gọi tới được**: age chỉ dùng `x/crypto/ssh` để phân tích khóa SSH (recipient `ssh-ed25519`/`ssh-rsa`), không mở kết nối/kênh. `govulncheck -mode=binary` trên binary cũ: *No vulnerabilities found* (0 symbol); mức package/module báo GO-2026-6354/6355 + GO-2026-5932. Vẫn sửa để image quét sạch (đã hứa ở P3-T11) và vì nghi thức khóa cũng dùng binary này.
- Phiên bản sửa: `golang.org/x/crypto` v0.56.0 phát hành **2026-09-02** (proxy.golang.org `.info`) ⇒ **77 ngày tuổi** — thỏa quy tắc ≥ 14 ngày; là bản đầu tiên có bản sửa (Go vuln DB: `fixed 0.56.0`). Không có lỗ hổng `x/crypto` nào khác có bản sửa > 0.56.0 trong Go vuln DB, trừ GO-2026-5932 (mục 4). Chọn bản sửa nhỏ nhất: `x/sys` v0.47.0 và `x/term` v0.45.0 giữ đúng như v1.3.2 khai báo (go.mod của x/crypto v0.56.0 cũng yêu cầu đúng hai bản đó) ⇒ thay đổi duy nhất trong cây phụ thuộc của binary là `x/crypto`.

## 2. Sửa — một công thức dùng chung

`go install filippo.io/age/cmd/age@v1.3.2` không ghi đè được phụ thuộc, nên (như tiền lệ `[sources.docker-compose]` — [P3-T02](P3-T02.md) mục 6) build lại từ mã nguồn của bản phát hành với phụ thuộc đã vá, nhưng bằng **module bọc** pin trong repo thay cho `go get` lúc build:

| Thành phần | Thay đổi |
|---|---|
| `infrastructure/host/key-ceremony/age-build/go.mod` + `go.sum` (mới) | Module bọc, không có mã Go: chỉ thị `tool filippo.io/age/cmd/{age,age-keygen}`, `require filippo.io/age v1.3.2`, `golang.org/x/crypto v0.56.0` (+ các phụ thuộc gián tiếp như v1.3.2); `go 1.27.4` như go.mod gốc. `go mod tidy -diff` sạch, `go mod verify`: *all modules verified*. Thư mục có go.mod riêng nên nằm ngoài module gốc (`./...` của go.yml không đổi) |
| `infrastructure/host/key-ceremony/build-age.sh` | Mount `age-build/` chỉ-đọc vào image golang pin, kiểm `go list -m filippo.io/age` = `version` của versions.lock, rồi `go build -ldflags "-X main.Version=v1.3.2" -o /out/ filippo.io/age/cmd/age filippo.io/age/cmd/age-keygen` với `CGO_ENABLED=0`, `GOFLAGS=-trimpath -mod=readonly`, `GOPROXY`/`GOSUMDB` tường minh (go.sum trong repo + checksum DB). `-X main.Version` để `age --version` vẫn in `v1.3.2` (biến do age cung cấp cho build ngoài `go install`) — `ceremony.sh preflight` và `images.yml` kiểm chuỗi này |
| `infrastructure/docker/backup/Dockerfile`, `infrastructure/docker/agent/Dockerfile` (stage `age`) | Cùng công thức: `COPY` đúng `age-build/go.mod` + `go.sum`, cùng biến môi trường và cờ build; kiểm `AGE_SHA256` (mới) và `age --version` ngay trong build |
| `versions.lock [sources.age]` | sha256 mới, trường `overrides` (x/crypto v0.56.0 + lý do), `build` mô tả công thức mới, `note` ghi lý do và **sha256 cũ** |
| `.github/workflows/images.yml` | Thêm `infrastructure/host/key-ceremony/age-build/**` vào `paths` (đổi go.mod/go.sum của age ⇒ build lại image backup + agent). Bước kiểm nội dung không đổi: vẫn đọc sha256 từ versions.lock |
| `docs/operations/key-ceremony.md` §9 | Mô tả công thức mới; binary cũ trên host bị từ chối |

Mọi chỗ kiểm sha256 của age đều đọc từ `versions.lock` hoặc dùng `AGE_SHA256` vừa cập nhật: `ceremony.sh` (`preflight`, `stage_age`), `tests/backup/drill.sh` (`setup`), `images.yml` (backup + agent), hai Dockerfile. Binary cũ (`e442c7bc…`) giờ bị cả ba script từ chối (fail-closed).

**Buildinfo** (`go version -m`): như trước, `path filippo.io/age/cmd/age`, `mod filippo.io/age v1.3.2 h1:r6RS…` — module bọc không xuất hiện trong binary nên syft/grype vẫn thấy `filippo.io/age v1.3.2`; khác duy nhất `dep golang.org/x/crypto v0.56.0` và không còn `DefaultGODEBUG=cryptocustomrand=1,…` (chế độ tương thích go1.25 do go.mod của age khai báo `go 1.25.0`; module bọc khai báo `go 1.27.4`). Các GODEBUG đó (TLS, HTTP, URL, x509, `cryptocustomrand` — hàm crypto bỏ qua `io.Reader` tự truyền, age vốn dùng `crypto/rand`) không đổi định dạng hay hành vi của age — mục 4 chứng minh tương thích hai chiều.

## 3. Hash

| Binary | sha256 mới (x/crypto v0.56.0) | sha256 cũ (x/crypto v0.55.0) |
|---|---|---|
| `age` | `571136ee8b7cbb0f67cd8ddd2e46ed834b933c62d59500b631a82af6c627e44d` | `e442c7bc47bb52e08ccb02dfa5fc09ecf58ce6bce5de0cdda8443b918ae7055e` |
| `age-keygen` | `2a6187ca43bb4a36e0f41629142f5f4230f40a31a2a341f6019596d903323bed` | `580c1a61d19c129cbdfa1c97689a061a91d27f22371eee9b30123afcde0a71a4` |

**Tái lập**: `build-age.sh` 3 lần (cache trống mỗi lần; lần 1 từ cây làm việc, lần 2 từ `git archive` của `45a0dab`, lần 3 từ bản sao cây đó ở đường dẫn khác) + stage `age` của image backup và image agent (build trong BuildKit, chạy root, `-o /out/age` chỉ một package) ⇒ **cùng sha256** ở cả 5 lần. Công thức cũ chạy lại trên `main` vẫn ra đúng hash cũ (đối chứng).

## 4. Kiểm chứng

Chạy trên `git archive` của `45a0dab` (cây mới) và của `8689c47` (`main`, cây cũ), VM build, 2026-11-18.

| Phép thử | Kết quả |
|---|---|
| `govulncheck -mode=binary` v1.9.0 trên `age`, `age-keygen` mới | **No vulnerabilities found** (exit 0, 0 symbol); mức module chỉ còn **GO-2026-5932** (`x/crypto/openpgp` "không còn bảo trì" — cảnh báo cả package, bản sửa chỉ là pseudo-version `v0.58.1-0.20261009181718-2f1f834330b2`; age không import `openpgp`, govulncheck không thấy ở mức package). Binary cũ: 0 symbol; module: GO-2026-6354, GO-2026-6355, GO-2026-5932 |
| grype — image **agent**, đường SBOM như `images.yml` (syft spdx-json → grype `--fail-on critical`) | **Trước** (`main`): 2 High — GO-2026-6354, GO-2026-6355 (`golang.org/x/crypto v0.55.0`, nguồn `/usr/local/bin/age`). **Sau: 0 High, 0 Critical**; exit 0. Còn GO-2026-5932 (Unknown) cho x/crypto của `age` (v0.56.0) và của `docker-compose` (v0.58.0) — như P3-T02 mục 6 |
| grype — image **backup**, cùng cách | Trước: 43 dòng High = 41 gói Debian (krb5, libc6, libssl3t64, libsasl2 — thư viện của `pg_dump` 18.7 và base distroless, không liên quan age; workflow chỉ chặn Critical) + **2 của `age`** (GO-2026-6354/6355). **Sau: 41 — 0 từ `age`**, 0 Critical; exit 0 |
| grype trên riêng binary (syft `dir:` + `go-module-binary-cataloger`) | `age` cũ: GO-2026-6355 High, GO-2026-6354 High, GO-2026-5932 Unknown ⇒ mới: chỉ GO-2026-5932 Unknown |
| Bước "Kiểm nội dung image" của `images.yml` — case `backup` (trích tự động từ images.yml của cây mới, đổi tên container/network sang `fixage-*`) | **Đạt**: user `10007:20007`; `pg_dump`/`pg_dumpall`/`pg_restore` 18.7; `age --version` = `v1.3.2`; sha256 của `/usr/local/bin/age` trong rootfs = `age_linux_amd64_sha256` mới; đúng 6 file thực thi; thiếu recipient ⇒ exit 2; `pg_dump` thật tới PostgreSQL 18.7 ⇒ 2 file `age-encryption.org/v1` + `status.json` |
| Bước "Kiểm nội dung image" — case `agent` | **Đạt**: user `0:0`; `docker-compose` đúng `build_sha256`; `sqlite3` + `age` đúng sha256 (age = hash mới), `age --version` = `v1.3.2` với UID tenant, rootfs chỉ đọc, không network; `noise-fingerprint` (vector RFC 7748); healthcheck `driver compose`; UID lạ bị từ chối; 0 socket TCP/UDP |
| Tương thích hai chiều cũ ↔ mới (`age` cũ `e442c7bc…` / mới `571136ee…`; khóa dùng một lần) | **18/18 PASS**: `age-keygen -y` cho cùng recipient từ cùng identity; archive tar và 3 MiB ngẫu nhiên (nhiều chunk 64 KiB) mã hóa **hai recipient X25519** (như archive của agent: data key tenant + recovery key) bằng bản cũ ⇒ bản mới giải mã đúng từng byte với **cả hai** identity, và ngược lại; header `age-encryption.org/v1` + 2 stanza X25519 ở cả hai; armor cũ ↔ mới; recipient `ssh-ed25519` (đi qua `x/crypto/ssh` — đúng package được vá) cũ ↔ mới; khóa lai hậu lượng tử (`age-keygen -pq`, `age1pq1…`) cũ ↔ mới; đối chứng âm: identity khác không giải mã được file nào bằng bản nào |
| `ceremony.sh preflight` (cây mới, chỉ đọc — "Thay đổi trên host: không có"; VM build không phải host nghi thức nên các mục khác như image worker báo lỗi, không liên quan) | `MGKC_AGE_DIR` = output mới: `OK age v1.3.2, sha256 khớp versions.lock` và `OK age-keygen v1.3.2, sha256 khớp versions.lock`; = binary cũ: `LỖI age: sha256 e442c7bc… hoặc phiên bản khác versions.lock [sources.age] (v1.3.2, 571136ee…)` (tương tự age-keygen) — fail-closed |
| agent-it (`tests/integration/agent/run.sh`, `AGENTIT_PREFIX=fixage`) — gồm **TestBackupRestoreEndToEnd** (sqlite3 + age thật của image agent) | Lần 1 (04:03–04:07 UTC): **TestBackupRestoreEndToEnd PASS** (92 s) — V-12: 3 backup online (VACUUM INTO) dưới tải ghi; archive A (`sqlite 3.54.1`, `headscale 0.29.7`) mã hóa hai recipient bằng `age` mới; đường DR: identity khôi phục giải mã được archive của A bằng `age` của image, data key của B thì không, không byte nào của B trong archive; T-15 (archive A vào B, data key của B, manifest sửa / ký khóa khác ⇒ từ chối trước khi giải mã); restore + `PostRestoreReconcile` (IT-16), B không đổi; IT-15 (5 thư mục data độc ⇒ fail-closed); restore bản lấy dưới tải ghi. TestReconcileReportsForeignObjectsUntouched PASS, TestReconfigureEndToEnd PASS. TestComposeDriverEndToEnd và TestAgentOperationsEndToEnd **FAIL vì VM dùng chung**: hai test này chụp toàn bộ `docker ps -a` của host và coi mọi thay đổi là lỗi — thay đổi bị bắt là container của agent khác (`+ container p3t17e2e-probe-call`, `- container practical_goldwasser`, `p3t17e2e-probe-e2e32-client running → dead`), không liên quan age (hai test không gọi age). Lần 2 (04:30–04:35 UTC, sau khi host không đổi 3 phút): **TestBackupRestoreEndToEnd PASS** (79 s), Reconcile PASS, Reconfigure PASS; TestComposeDriverEndToEnd chạy hết các bước (`end to end: ok; 9 refused calls audited; the throwaway tenant, its network and its directory are gone`) và TestAgentOperationsEndToEnd cũng vậy (`operations end to end: ok; 6 Critical start-guard events; 2 API keys created, none in the log`), rồi chỉ trượt ở phép so host cuối: `+ container nifty_ptolemy`, `+ container amazing_northcutt`, `- container peaceful_austin` — container `go run` không tên (image golang) của stack e2e của agent khác chạy cùng lúc; snapshot trước/sau của `run.sh` cũng chỉ khác ở hai container golang đó, không còn tài nguyên `fixage` nào. Kết luận: phần dùng age đạt ở cả hai lần; hai lỗi còn lại do VM dùng chung, cần chạy lại trên runner riêng (workflow `agent-driver`) |
| `tests/backup/drill.sh` (P2-T03a/P2-T05b: PostgreSQL + IdP + edge, image backup mới, `AGE_DIR` = output của `build-age.sh` mới — drill tự kiểm sha256 với versions.lock) | **45 PASS, 0 FAIL** (exit 0; `PREFIX=fixagebk`, `NET_BASE=10.243`; image IdP build từ `infrastructure/docker/idp` của cây — VM không có quyền kéo digest `[images.mg-idp]` từ GHCR — truyền bằng `IDP_IMAGE=<image ID>`, như `render_idp.py --image` cho phép): `setup` chấp nhận age/age-keygen mới theo versions.lock; **PostgreSQL** — pg-backup (lịch + `once --label pre-migration`) ghi ciphertext age, giải mã bằng `age` mới → restore vào cụm tạm và rollback tại chỗ: số hàng + băm 44 bảng/partition, catalog 193 dòng, RLS, thu hồi session khớp; identity sai ⇒ `age: error: no identity matched any of the recipients`; **IdP** — Keycloak đang chạy và đã dừng ⇒ idp-backup, restore vào idp-db mới (101 + 106 dòng khớp), Keycloak khởi động lại với realm/user/discovery như trước; **edge** — edge-backup + giải nén khớp từng file (35 dòng); âm tính và hardening đạt; dọn: 0 container, 0 network, 0 volume |

## 5. Bàn giao

- **Image**: commit vào `main` sẽ chạy workflow `images` (bộ lọc `paths` khớp Dockerfile + `age-build/`) ⇒ image backup và agent mới; digest đưa vào `versions.lock` bằng commit riêng như thường lệ. Image backup/agent đã triển khai trước đó (nếu có) vẫn mang age cũ (`e442c7bc…`) — cùng định dạng, archive hai bên đọc được của nhau; thay khi người điều phối cập nhật digest.
- **Nghi thức khóa**: nếu host có sẵn `infrastructure/host/key-ceremony/bin/age*` bản cũ, `ceremony.sh preflight` sẽ báo sai sha256 ⇒ chạy lại `build-age.sh` trên máy build và chép sang (runbook [key-ceremony.md](../../operations/key-ceremony.md) §9). Identity khôi phục và mọi archive đã mã hóa không phải làm lại (mục 4: tương thích hai chiều).
- **Còn theo dõi**: GO-2026-5932 (`x/crypto/openpgp`, chỉ có bản sửa pseudo-version; không có trong đồ thị gọi của age) — nâng khi `x/crypto` gắn tag bản có bản sửa ≥ 14 ngày; nâng `filippo.io/age` khi có bản mới (khi đó gỡ `x/crypto` khỏi `require` nếu age đã khai báo ≥ v0.56.0).
- VM: tài nguyên `fixage*` đã dọn — mục 6.

## 6. Dọn VM

Sau cùng (04:37 UTC): **0 container, 0 network, 0 volume, 0 image** mang tiền tố `fixage` (kể cả `mg-t-fixage-*`, `mg-hs-fixage-*`, `mg-helper-fixage-*`, `fixagebk-*` của drill); `~/fixage` (cây, binary, log, khóa dùng một lần) và `/tmp/fixage-root.*` đã xóa; không prune gì của người khác. Còn lại: các bản ghi build cache BuildKit dùng chung sinh ra khi build image (không mang tiền tố; `docker builder prune --filter id=…` không chọn được từng bản ghi nên không xóa để khỏi đụng cache của người khác).
