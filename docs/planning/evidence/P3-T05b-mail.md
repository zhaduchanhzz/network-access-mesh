# P3-T05b-mail — Relay thư ra qua Cloudflare Email Service: Worker Cloudflare + cầu SMTP `mailrelay`

> **File viết tay — không sinh từ master.** Bằng chứng của phần "relay SMTP thật" mà [P3-T05b.md](P3-T05b.md) mục 4 để
> chủ dự án quyết định. Quyết định (chủ dự án 2026-11-18): *"SMTP sử dụng cloudflare worker paid theo token trên máy
> này"* — Cloudflare Email Service gửi bằng một Worker trả phí; zone của `MG_BASE_DOMAIN` (staging) đã onboard Email
> Sending (SPF `cf-bounce`, DMARC `p=reject`) — **không đổi DNS**. Phần này dựng Worker, cầu SMTP và nối triển khai; việc
> `wrangler deploy` và đổi staging là của người điều phối (mục 6). Không chạm host staging, VPS, DNS hay Cloudflare.
> Quy ước: [README](README.md).

| Mục | Giá trị |
|---|---|
| Ngày | 2026-11-18 (UTC+7) |
| Người thực hiện | Agent (Claude Code), worktree nhánh `mailrelay` (từ `main` @ `8689c47`) |
| Môi trường | dev/CI — VM build 110 (tiền tố `mailr`, stack E2E `mailre2e`, mạng `10.238`/`10.250.238.0/28`); **Worker giả** = mã thật của Worker chạy bằng node (`test/devserver.mjs`) với binding `EMAIL` giả. Không gọi Cloudflare |
| Dependency mới | Không. Go: thư viện chuẩn (`net/textproto`, `crypto/hmac`, `crypto/tls`). Worker: JavaScript thuần, **0 dependency** runtime lẫn dev (test = `node --test` của image node pin trong versions.lock) |
| Nhãn kết quả | **functional** (dev/CI, §22.1) |
| Commit | chuỗi kiểm trên `git archive` của **`a43daf2` (nhánh `55645a6` + gộp `main` @ `08b5e09`)** (mục 4) |

## 1. Đầu ra

| Thành phần | Nội dung |
|---|---|
| `infrastructure/mail/cf-worker/` (mới) | `src/index.js` (Worker: `POST /v1/send`, HMAC, gửi raw qua binding `EMAIL`), `wrangler.toml.tmpl` (binding `send_email` giới hạn `allowed_sender_addresses`, không secret, không domain), `package.json` (không dependency), `test/worker.test.mjs` (8 test, `node --test`), `test/register.mjs` + `test/fake-email.mjs` (`cloudflare:email` giả qua `module.registerHooks`), `test/devserver.mjs` (Worker giả của stack E2E) |
| `internal/mailrelay` (mới) | Cầu SMTP: `server.go` (EHLO/HELO, STARTTLS, MAIL, RCPT ≤ 10, DATA ≤ 1 MiB, RSET, NOOP, QUIT, VRFY, HELP), `forward.go` (POST ký HMAC, thử lại có giới hạn, phân loại 250/451/554), `listen.go` (chỉ nghe trên địa chỉ của network `mail`, chứng chỉ nạp lại khi đổi), `metrics.go` (`meshguard_mailrelay_*`) + 4 file test |
| `apps/worker` | Lệnh `meshguard-worker mailrelay` (`mailrelay.go` — chạy thành container riêng từ image worker, không image mới) và `meshguard-worker admin mail-test --to <địa chỉ>` (`mailtest.go` — thư thử qua đúng client của `notification.send`) |
| `apps/internal/runner` | `NewSMTPMailer(config.SMTP)` dùng chung cho `notification.send` và `mail-test` (không đổi hành vi) |
| `internal/config` | `LoadMailRelay` (`MG_MAILRELAY_*`; secret chỉ dạng `*_FILE`; TLS + `MG_MAILRELAY_SMTP_CIDR` bắt buộc ngoài dev/ci; URL `https://…/v1/send`, `http` chỉ ở dev/ci); kiểm biến secret tách thành `secretEnvErrors` (dùng chung với `Load`) |
| `internal/archtest` | Module `mailrelay`: chỉ `kit`, cấm module nghiệp vụ (§13.6 thêm hàng) |
| `tools/render_mail.py` (mới) + `tools/test_render_mail.py` | `wrangler.toml` từ env file; luật chung: người gửi (`MG_SMTP_FROM` — cùng biến với `render_monitoring.py` của P3-T16, mặc định `MeshGuard <no-reply@<MG_BASE_DOMAIN>>`, địa chỉ chỉ trong domain), URL Worker, network `mail`, file trên host |
| `tools/render_app.py` (template 3) + test | Có `MG_MAILRELAY_URL` ⇒ service `mail-bridge` (máy SMTP `mailrelay` = alias chỉ trên `mail`; networks mail + mg-obs + mg-egress) và `MG_SMTP_*` + network `mail` + CA cho worker; không có ⇒ không đổi gì |
| `tools/render_idp.py` + test | `MG_IDP_MAIL_SINK=mailrelay`: `smtpServer` → `mailrelay:587` STARTTLS, không auth; idp vào network `mail`; `KC_TRUSTSTORE_PATHS` = CA nội bộ; `check_realm` chỉ nhận `mailsink:1025` hoặc `mailrelay:587`+STARTTLS |
| `infrastructure/idp/realm-update.sh` | Đồng bộ thêm `smtpServer` của realm đang chạy với bản render (Mailpit ⇄ mailrelay; không bao giờ mật khẩu) |
| `infrastructure/host/` | `mail-secrets.sh` (mới: khóa HMAC, CA nội bộ + chứng chỉ, không in giá trị), `check-secrets.sh` (+2 file), `networks.sh` (`mail` 10.249.8.0/24 internal), `layout.sh` (nhóm `mg-sec-mail` 20009), `RUNBOOK.md` |
| `versions.lock` | `[ids] mg-sec-mail = 20009` |
| `internal/platform`, `internal/provisioning/agentspec` | 20009 vào `ReservedIDs`/`reservedIDs`: `run_uid` của tenant không bao giờ là GID này (tiến trình tenant chạy `run_uid:run_uid` sẽ đọc được khóa HMAC và khóa TLS) — `TestReservedIDsCoverVersionsLock` bắt được ở lượt kiểm đầu |
| `compose.app.yaml.tmpl`, `compose.yaml` (stack dev/CI), `ci.env`, `.env.example`, `.gitignore` | Placeholder của relay; stack ci: relay thật + `fakeworker`; `wrangler.toml` render và `.wrangler/` không commit |
| E2E | `tests/e2e/harness/mailrelay.py` — **E2E-82, E2E-83**; `stack.py` (network `mail`, image node, file của relay bằng chính `mail-secrets.sh`), `test_stack.py` |
| CI | `ci.yml`: `test_render_mail.py` + bước `npm test` của Worker trong image node pin (job `api-types`, không thêm job); `Makefile render-test` |
| Master | §7.6 (2 hàng secret mới, ghi chú SMTP), §13.6 (`mailrelay`), §14.2 (`mg-sec-mail`), §14.3 (`mail`, `mailrelay` trên `mg-egress`), §16.2 (health), §16.3 (kênh email của cảnh báo), §21.3 (SMTP đã giải quyết); `docs/` sinh lại |

## 2. Thiết kế

### 2.1 Đường đi của một thư

```text
worker (notification.send) ─┐
Keycloak (smtpServer)       ├─SMTP mailrelay:587, STARTTLS (CA nội bộ), network mail (internal)───▶ mailrelay
Alertmanager (P3-T16)       ─┘                                                                         │
     HTTPS POST /v1/send, X-MG-Timestamp + X-MG-Signature (HMAC-SHA256), qua mg-egress  ◀──────────────┘
                                         ▼
               Worker Cloudflare ──env.EMAIL.send(new EmailMessage(from, to, raw)) mỗi người nhận──▶ Email Service
```

Relay **đồng bộ, không hàng đợi**: câu trả lời cho DATA chính là câu trả lời của Worker, nên logic thử lại của client giữ
nguyên — `notification.send` (thử lại 4xx với backoff của framework, dừng ở 5xx), Alertmanager (tự gửi lại), Keycloak
(báo lỗi cho thao tác gọi nó).

### 2.2 Hợp đồng của Worker và bảo mật

| Điểm | Thiết kế |
|---|---|
| Endpoint | Chỉ `POST /v1/send`; mọi thứ khác ⇒ `404 not_found` |
| Xác thực | `X-MG-Timestamp` (giây Unix) + `X-MG-Signature` = `hex(HMAC-SHA256(RELAY_HMAC_KEY, timestamp + "\n" + hex(sha256(body))))`. Kiểm **trước** khi parse body, bằng `crypto.subtle.verify` (so sánh thời gian hằng). Timestamp lệch > ±300 s ⇒ `401 auth_timestamp`; thiếu/sai dạng ⇒ `auth_missing`; sai chữ ký ⇒ `auth_signature`. Khóa < 32 byte, thiếu `RELAY_ALLOWED_FROM` hay binding ⇒ `500 not_configured` (fail closed) |
| Chống phát lại | Cửa sổ ±300 s + cache trong isolate theo **digest của body**: body đã gửi ⇒ `200 duplicate` (không gửi lần hai), body đang gửi ⇒ `409 in_progress`. Cache theo digest chứ không theo chữ ký vì hai lần thử của cầu trong cùng một giây có cùng chữ ký mà lần đầu có thể đã thất bại. Cache là best effort (một isolate): phần còn lại được chặn bởi cửa sổ thời gian và HTTPS, và một bản phát lại chỉ có thể gửi lại **đúng** thư đó tới **đúng** người nhận đó — không thể đổi nội dung khi không có khóa |
| Body | JSON đúng 3 khóa `{from, to: [1..10], raw_b64}`; `from` ∈ `RELAY_ALLOWED_FROM` (⇒ `403 sender_not_allowed`), người nhận ASCII `local@domain` có dấu chấm, không CR/LF/`<>` (⇒ `422 bad_recipient`), trùng thì gộp; raw ≤ 1 MiB (⇒ `413 too_large`), UTF-8 hợp lệ (⇒ `400 bad_message`); `Content-Type` JSON (⇒ `415`); body đọc có giới hạn kể cả khi `Content-Length` sai |
| Gửi | Một `EmailMessage(from, to, raw)` (API raw của `cloudflare:email`) **mỗi người nhận**. Chọn raw thay vì builder có cấu trúc: thư của worker/Keycloak/Alertmanager là RFC 5322 hoàn chỉnh (MIME, mã hóa, Message-ID của hàng outbox) phải tới nguyên vẹn; Bcc chỉ có trong envelope; dựng lại bằng builder cần parser MIME (một dependency) và làm mất dữ liệu. Binding vẫn giới hạn `allowed_sender_addresses` ở tầng Cloudflare |
| Lỗi của Email Service | Mã `E_*` vĩnh viễn (`E_SENDER_NOT_VERIFIED`, `E_RECIPIENT_SUPPRESSED`, `E_CONTENT_TOO_LARGE`, `E_FIELD_MISSING`, …) ⇒ `retryable:false`; `E_RATE_LIMIT_EXCEEDED`/`E_DAILY_LIMIT_EXCEEDED`/không mã ⇒ thử lại được; `TypeError` ⇒ vĩnh viễn. Không gửi được ai: toàn rate ⇒ `429`, có lỗi thử lại được ⇒ `503`, toàn vĩnh viễn ⇒ `422`; gửi được ≥ 1 ⇒ `200 sent|partial` |
| Trả lời | `{"ok","code","sent","failed","retryable","results":[{"status","id"?,"error"?,"retryable"?}]}` — không bao giờ có địa chỉ, header, nội dung hay thông điệp lỗi gốc (có thể chứa địa chỉ); `Cache-Control: no-store` |
| Log | Một dòng JSON mỗi request: `code`, số người nhận, `sent`, `failed`, danh sách mã `E_*`, số byte — không địa chỉ, không header, không khóa; `wrangler.toml` tắt invocation log (URL, metadata) |

### 2.3 Cầu SMTP `mailrelay` (`internal/mailrelay`)

| Điểm | Thiết kế |
|---|---|
| Lắng nghe | `:587` trên **đúng địa chỉ của container trong network `mail`** (`MG_MAILRELAY_SMTP_CIDR`, bắt buộc ngoài dev/ci — không có hoặc có hai địa chỉ trong dải ⇒ không khởi động); không nghe trên `mg-egress`/`mg-obs` (E2E-82 kiểm). `/healthz`, `/readyz` (`smtp_listener`, `hmac_key`, `tls_certificate`), `/metrics` trên `:9090` |
| Lệnh | EHLO/HELO (bắt buộc trước MAIL), STARTTLS, MAIL FROM (`SIZE`, `BODY` — tham số khác `555`), RCPT TO (≤ 10, thứ 11 ⇒ `452 4.5.3`), DATA, RSET, NOOP, QUIT, VRFY (`252`), HELP; AUTH và lệnh lạ ⇒ `502` |
| Chính sách | MAIL FROM chỉ địa chỉ trong `MG_MAILRELAY_ALLOWED_FROM` (không phân biệt hoa thường; null path `<>` bị từ chối) ⇒ `550 5.7.1`; header `From` phải đúng **một** địa chỉ được phép ⇒ không mạo danh; thiếu `Message-ID` ⇒ thêm `<random@domain-gửi>` (Email Service đòi — `E_FIELD_MISSING`); không AUTH: network internal + địa chỉ gửi cố định + giới hạn tốc độ (60 thư/phút, token bucket ⇒ `451 4.7.0`) + tối đa 32 phiên (thêm ⇒ `421`) + 20 lệnh lỗi/phiên |
| TLS | STARTTLS khi có chứng chỉ, và khi đó **bắt buộc** trước MAIL (`530 5.7.0`); TLS ≥ 1.2; lệnh gửi dồn sau STARTTLS trước handshake ⇒ đóng kết nối (lớp lỗi CVE-2011-0411); sau TLS client phải EHLO lại (RFC 3207). Cặp chứng chỉ nạp lại khi file đổi (gia hạn không restart; bản ghi dở thì giữ cặp cũ). Plain text chỉ khi không có chứng chỉ — `config` chỉ cho ở dev/ci |
| DATA | ≤ 1 MiB (SIZE quảng bá; vượt ⇒ đọc hết rồi `552 5.3.4`, phiên vẫn dùng được), bỏ dấu chấm đầu dòng, LF trần ⇒ CRLF; không quảng bá 8BITMIME (client gửi 7-bit — Worker giải mã UTF-8 chặt) |
| Chuyển tiếp | JSON `{from, to, raw_b64}` ký HMAC, khóa đọc từ file **ở mỗi thư** (xoay không restart; file ghi tại chỗ giữ inode của bind mount); tối đa 3 lần, mỗi lần ≤ 5 s, backoff 250 ms/1 s, tổng ngân sách `MG_MAILRELAY_TIMEOUT` = 8 s (dưới timeout 10 s của Keycloak và 30 s của worker); không theo redirect |
| Trả lời SMTP | Worker 200 ⇒ `250` (kể cả `partial`: thử lại sẽ gửi trùng người đã nhận — log WARN + metric); 429/5xx/408/mạng/timeout ⇒ thử lại rồi `451 4.3.0 … (<mã>)`; 401/404/3xx (khóa, đồng hồ, URL sai — lỗi triển khai, không phải của thư) ⇒ `451` ngay, không thử lại; 4xx khác ⇒ `554 5.6.0 … (<mã>)`. Mã trong câu trả lời là mã ổn định của Worker (regex `[a-z][a-z0-9_]{0,39}`), mã lạ ⇒ `http_<status>` |
| Log, metric | Mỗi thư một dòng: người gửi **che** (`n***@domain`), số người nhận, byte, kết quả, mã, HTTP status, số lần thử, thời lượng — không thân, subject, khóa hay địa chỉ đầy đủ. `meshguard_mailrelay_{sessions_total, sessions_active, starttls_total{result}, rejected_total{reason}, messages_total{result}, recipients_total{result}, forward_attempts_total{status}, forward_duration_seconds}` (nhãn khởi tạo sẵn = 0) |

### 2.4 TLS nội bộ (`infrastructure/host/mail-secrets.sh`)

CA EC P-256 riêng của relay (3 năm, `nameConstraints=critical,permitted;DNS:mailrelay` — chỉ ký được đúng tên này, khóa
CA bị xóa ngay sau lần ký duy nhất) ký chứng chỉ `mailrelay` (SAN `DNS:mailrelay`, `serverAuth`, 825 ngày). `tls_key` và
`relay_hmac_key` là `root:mg-sec-mail 0440` (chỉ `mailrelay` có nhóm 20009 — worker, Keycloak, Alertmanager không đọc được:
`check-secrets.sh`); `tls_cert`, `ca.crt` công khai `0444`. Client tin CA: worker `MG_SMTP_TLS=starttls` +
`MG_SMTP_CA_FILE`, Keycloak `KC_TRUSTSTORE_PATHS` (+ kho CA mặc định của JVM; kiểm tên `mailrelay`), Alertmanager
`tls_config.ca_file`. Script chạy lại an toàn; `--rotate-tls`, `--rotate-hmac` ghi **tại chỗ** (cùng inode).

### 2.5 Keycloak

`MG_IDP_MAIL_SINK=mailrelay` (giá trị mới; `mailpit` giữ nguyên cho dev/staging thử): mọi realm `smtpServer =
{host: mailrelay, port: 587, from: <địa chỉ gửi>, fromDisplayName, auth: false, ssl: false, starttls: true}` — không
mật khẩu (`check_realm` vẫn cấm). Compose `mg-idp`: idp vào network `mail` (external, do `networks.sh` tạo — dùng chung với `mg-app`
và project monitoring), secret `idp_mailrelay_ca` → `/run/secrets/mailrelay-ca.pem`, `KC_TRUSTSTORE_PATHS` trỏ vào đó
(tùy chọn runtime của Keycloak 26 — image `--optimized` không cần build lại: E2E chứng minh Keycloak khởi động và gửi qua
STARTTLS). Realm **đã tồn tại** không được import lại ⇒ `realm-update.sh` nay đồng bộ cả `smtpServer` (E2E-31 xác nhận 0 thay
đổi trên realm vừa import). Realm do driver tạo cho tenant mới (`internal/idp/keycloak/realm.json.tmpl`) **chưa** có
`smtpServer` — chưa luồng nào của Phase 3 nhờ Keycloak gửi thư (`Invite.SendEmail` chưa dùng); khi cần, thêm cấu hình relay
vào driver (mục 7).

### 2.6 Triển khai (`mg-app`)

Service `mail-bridge`: image worker pin, `command: ["mailrelay"]`, `65532` + nhóm `20009` duy nhất, rootfs chỉ-đọc,
`cap_drop ALL`, 128 MiB, không cổng publish, healthcheck `/readyz`; networks `mail` (alias `mailrelay`), `mg-obs`
(`mail-bridge:9090/metrics`), `mg-egress` (`gw_priority`). Máy SMTP `mailrelay` là alias **chỉ** trên network `mail`, khác
tên service: tên service là alias trên **mọi** network của service, nên nếu service tên `mailrelay`, client cũng ở
`mg-egress` (worker, idp, alertmanager) có thể nhận địa chỉ `mg-egress` của cầu, nơi không có listener — lượt E2E đầu tiên
bắt được đúng lỗi này (Keycloak `Connection refused`, hàng outbox kẹt `pending`). Worker thêm `MG_SMTP_ADDR=mailrelay:587`, `MG_SMTP_TLS=starttls`, `MG_SMTP_CA_FILE`, `MG_SMTP_FROM="<tên>
<địa chỉ>"` và network `mail`. Tất cả chỉ render khi env file có `MG_MAILRELAY_URL` — trước khi người điều phối điền URL,
bản render staging **không đổi** (test `relay: no MG_MAILRELAY_URL ⇒ …`).

### 2.7 Firewall / đường ra

Host staging hiện không chặn chiều ra của container (`mg-staging-firewall.nft`: chain `forward` policy accept, chỉ chặn kết
nối **mới từ ngoài vào** qua `eth0`/`mg-wg0`; chưa có allow-list `DOCKER-USER` — P6-T07) ⇒ **không cần đổi firewall** để
`mailrelay` gọi `https://<worker>.workers.dev` qua NAT của `mg-egress` (DNS qua resolver nhúng của Docker như mọi container
trên `mg-egress`). `mail` là network internal: không đường ra, không cần rule. Cho P6-T07 (allow-list đường ra): nguồn =
địa chỉ của `mailrelay` trên `mg-egress`, đích TCP 443 tới dải IP Cloudflare (`https://www.cloudflare.com/ips-v4` — Worker
workers.dev/custom domain đều anycast trên các dải này; nftables không lọc theo tên miền), cộng DNS 53 tới resolver của host.

## 3. Kiểm chứng

| # | Tiêu chí | Test | Kết quả |
|---|---|---|---|
| 1 | Worker: chỉ `POST /v1/send` (GET/HEAD/PUT/đường khác ⇒ 404); một `EmailMessage` raw mỗi người nhận (gộp trùng, chữ thường), raw không đổi, trả lời không chứa `@`/Subject/thân/khóa | `worker.test.mjs` (2 test) | đạt — 8/8 test |
| 2 | Worker: thiếu/sai dạng header ⇒ `auth_missing`; khóa khác, chữ ký của body khác ⇒ `auth_signature`; lệch ±302 s ⇒ `auth_timestamp`, 295 s ⇒ nhận; body rác + chữ ký sai bị từ chối trước khi parse; thiếu cấu hình ⇒ 500 | `worker.test.mjs` | ″ |
| 3 | Worker: 16 body sai (JSON, khóa lạ, mảng, `to` không phải mảng, sender lạ ⇒ 403, 0/11 người nhận, CRLF/`<>`/`localhost`/số, base64 sai, rỗng, không UTF-8, raw > 1 MiB, Content-Type), body > giới hạn ⇒ 413; đúng 1 MiB ⇒ nhận | `worker.test.mjs` | ″ |
| 4 | Worker: lỗi Email Service ⇒ 429/422/503/200 partial đúng bảng 2.2; thông điệp lỗi (có địa chỉ) không bao giờ bị trả lại; body đã gửi ⇒ `duplicate` (cả bản phát lại y hệt), body lỗi ⇒ gửi lại được, body đang gửi ⇒ 409; log chỉ đếm/mã | `worker.test.mjs` | ″ |
| 5 | Cầu SMTP (plain text, dev): thứ tự lệnh, 550 sender lạ, `<>`, thiếu `<>`, tham số lạ 555, SIZE 552, chữ hoa/khoảng trắng, MAIL lồng, RCPT sai cú pháp/`localhost`/quoted, 10 + trùng + thứ 11 ⇒ 452, dot-unstuffing + LF trần ⇒ CRLF, Message-ID được thêm, header From lạ/hai From ⇒ 550 và không chuyển tiếp, metric theo lý do | `TestConversationPlainText` | đạt — 13 test (`internal/mailrelay`), `-race`, cả `-count=20` và `-cpu 1,4` |
| 6 | STARTTLS: quảng bá, MAIL trước TLS ⇒ 530, EHLO lại sau TLS, STARTTLS lần hai ⇒ 503, client không tin CA ⇒ handshake hỏng; lệnh dồn sau STARTTLS ⇒ 554 + đóng | `TestStartTLSRequired`, `TestStartTLSPipelinedCommandsRefused` | ″ |
| 7 | Kết quả ⇒ 451/554/250 (partial); thư > 1 MiB ⇒ 552 và phiên dùng tiếp; giới hạn tốc độ ⇒ 451; quá số phiên ⇒ 421; dòng lệnh quá dài ⇒ 500 + đóng; shutdown đóng phiên rảnh, `Serve` trả về | `TestOutcomesAndLimits`, `TestBusyLongLineAndShutdown` | ″ |
| 8 | `readData` (bộ đệm 16 byte: dòng dài, CR tách khỏi LF, không đọc quá dấu kết thúc, EOF), địa chỉ, `Mask`, `parsePath`, `ListenAddr` (đúng một địa chỉ trong dải), chứng chỉ nạp lại khi đổi và giữ cặp cũ khi file hỏng; log không có địa chỉ đầy đủ, subject, thân | `TestReadData`, `TestAddressesAndMask`, `TestListenAddr`, `TestCertFilesReload`, `TestLogsHoldNoAddressOrContent` | ″ |
| 9 | Chuyển tiếp với Worker giả **kiểm HMAC y như Worker thật**: body JSON, partial, 5xx rồi 200 (2 lần), 429 ×3, 422/400 vĩnh viễn không thử lại, 404/302 tạm thời không thử lại, mã lạ không bị dội lại, metric theo nhóm; cùng giây ⇒ cùng chữ ký; khóa sai ⇒ 401 tạm thời; khóa xoay trong file dùng ngay; file thiếu/ngắn ⇒ không gửi gì; timeout và ngân sách | `TestForwardSignsAndClassifies`, `TestForwardTimeoutAndBudget` | ″ |
| 10 | Hội thoại thật: **client `internal/notifications`** (`starttls` + CA nội bộ, ServerName `mailrelay`) → cầu → Worker giả: thư tới nguyên vẹn (From, Message-ID của client không bị nhân đôi, subject RFC 2047, dấu chấm đầu dòng); Worker 422 ⇒ lỗi **vĩnh viễn** 554; Worker 503 (sau 3 lần) ⇒ **tạm thời** 451; client plain text ⇒ 530; sender lạ ⇒ 550; thư bị từ chối không tới Worker | `TestNotificationsClientThroughTheBridge` | ″ |
| 11 | Cấu hình: mặc định, 17 giá trị sai (http ngoài dev/ci, credential/query/path của URL, khóa tương đối, thiếu TLS/CIDR ngoài dev/ci, IPv6, display name, rate, timeout, listener trùng, hostname, secret trong env, MG_ENV) — lỗi không lặp lại giá trị; ci cho plain text + http, production thì không | `internal/config` `TestMailRelayConfig` | ″ |
| 12 | Lệnh `mailrelay`: tham số/cấu hình sai ⇒ 2; chạy thật: lời chào `220 mailrelay ESMTP`, `/readyz` 200, dừng sạch ⇒ 0, log không có khóa; `admin mail-test`: 5 cách dùng sai + không relay ⇒ 2 và không gửi gì; gửi ⇒ 0, địa chỉ che, Message-ID; lỗi tạm thời ⇒ 1 | `apps/worker` `TestMailRelayCommand`, `TestMailTest` | ″ |
| 13 | Render: `wrangler.toml` (TOML hợp lệ, binding `EMAIL` + `allowed_sender_addresses` = đúng địa chỉ gửi, vars, invocation log tắt, không secret/placeholder, template không có domain); địa chỉ gửi (mặc định, tùy chỉnh, subdomain, ngoài domain/look-alike/display name/non-ASCII/tiêm header bị từ chối); URL; staging.env render được | `tools/test_render_mail.py` | đạt — 36 / 81 / 136 kiểm |
| 14 | mg-app: không URL ⇒ không gì đổi; có URL ⇒ `mailrelay` hardened, chỉ nhóm 20009, đúng 3 secret, đúng 3 network (alias, egress mặc định), healthcheck; worker → `mailrelay:587` STARTTLS + CA, **không** thấy khóa HMAC/TLS; api không có SMTP; 4 file dưới `secrets/mail`; `mail` = network external `mail`; http chỉ ở ci | `tools/test_render_app.py` | ″ |
| 15 | mg-idp: 3 realm → `mailrelay:587` STARTTLS, khác bản mặc định đúng `smtpServer`; `check_realm` từ chối STARTTLS tắt/cổng khác/host khác; idp vào `mail` (vẫn không `mg-edge`), `KC_TRUSTSTORE_PATHS` + CA; compose = mặc định + đúng 5 đoạn chèn | `tools/test_render_idp.py` | ″ |
| 16 | `mail-secrets.sh` (container dùng một lần): quyền `root:mg-sec-mail 0440` / `0444`, khóa 48 ký tự, name constraint `DNS:mailrelay`, chạy lại giữ nguyên, `--rotate-*` đổi giá trị **cùng inode**, tham số lạ ⇒ 2 | chạy tay trên VM + mỗi lượt E2E (`stack.make_mail_secrets`) | đạt |
| 17 | **E2E-82** — xem mục 3.1 | `tests/e2e/harness/mailrelay.py` | **PASS** |
| 18 | **E2E-83** — xem mục 3.1 | ″ | **PASS** |
| 19 | E2E-31 (có sẵn): `realm-update.sh` trên realm vừa import (giờ có `smtpServer` → mailrelay) ⇒ 0 thay đổi, `check_realm` đạt trên bản export của Keycloak | `asvs2.py` | PASS |

### 3.1 E2E trên stack dev/CI

Relay của stack là thật (image worker build từ cây, render bằng `render_app.py`, file bằng `mail-secrets.sh`, realm bằng
`render_idp.py` với `MG_IDP_MAIL_SINK=mailrelay`); chỉ Worker là giả nhưng chạy **mã thật** `src/index.js` (devserver,
binding `EMAIL` ghi lại header/kích thước/digest — không thân thư vì thư Keycloak chứa link có token).

- **E2E-82**: cổng 587 trả lời trên địa chỉ của `mailrelay` ở network `mail` (220, EHLO có STARTTLS, MAIL trước TLS ⇒ 530)
  và **không** trên địa chỉ ở `mg-egress`; `policy-apply` (baseline) của tenant-a ⇒ mọi hàng email `policy.applied` của lần
  áp thành `sent`, mỗi hàng tới Worker với `Message-ID: <id hàng@domain>`, đúng người nhận, đúng địa chỉ gửi; thư Keycloak
  (`execute-actions-email` của một user tenant-b) ⇒ 204 và tới Worker từ địa chỉ gửi của relay; `admin mail-test` trong
  worker ⇒ exit 0, tới Worker với đúng Message-ID; mọi request 200 mang HMAC hợp lệ (harness tự kiểm bằng bản khóa của nó);
  metric: STARTTLS ok, delivered tăng, `rejected{tls_required}` tăng.
- **E2E-83**: gọi thẳng Worker: timestamp cũ 400 s ⇒ `401 auth_timestamp`, khóa khác ⇒ `401 auth_signature`, GET ⇒ 404, một
  request hợp lệ ⇒ `sent`, phát lại y hệt ⇒ `200 duplicate` và chỉ **một** thư; ghi khóa sai **tại chỗ** vào file của cầu
  (không restart) ⇒ Keycloak báo lỗi gửi, Worker ghi `401 auth_signature`, không thư nào, `messages_total{temporary}` tăng;
  ghi lại khóa đúng ⇒ gửi được ngay.

Kết quả (lượt của chuỗi kiểm trên `a43daf2`): E2E-82 — listener chỉ trên network `mail` (egress: `ConnectionRefused`), 9 hàng email `policy.applied` của lần áp đều `sent` với `attempts = 1` và tới Worker đúng Message-ID + người gửi, thư Keycloak HTTP 204 → 1 thư (From `MeshGuard <no-reply@meshguard-ci.test>`), `mail-test` exit 0, **114/114** request được Worker nhận mang HMAC hợp lệ, metric STARTTLS ok +11 / delivered +11 / MAIL trước TLS bị từ chối +1. E2E-83 — timestamp cũ ⇒ `401 auth_timestamp`, khóa khác ⇒ `401 auth_signature`, GET ⇒ 404, phát lại ⇒ `duplicate` (1 thư), khóa sai trên cầu ⇒ Keycloak 500, Worker `[(401, auth_signature)]`, 0 thư, `temporary` +1; khóa đúng lại ⇒ 204, 1 thư.

Lỗi do E2E bắt được khi phát triển (đã sửa trước commit): tên service `mailrelay` là alias trên mọi network ⇒ Keycloak/worker phân giải ra địa chỉ `mg-egress` của cầu (`Connection refused`, hàng outbox kẹt `pending`) ⇒ service `mail-bridge` + alias `mailrelay` chỉ trên `mail`; token Admin API của harness hết hạn khi VM tải cao (E2E-24 dây chuyền).

## 4. Chuỗi kiểm

Chuỗi tương đương CI (`scratchpad/mailr-verify.sh`, bản sao của `mainv-verify.sh` + bước `npm test` của Worker và `test_render_mail.py`/`test_render_agent.py`) trên `git archive` của commit, VM build 110, image pin digest:

| Bước | `55645a6` (nhánh trước khi gộp) | `a43daf2` (sau khi gộp `main` @ `08b5e09`) |
|---|---|---|
| go-ci: mod verify, tidy, gofmt, generate (api.gen.go không đổi), vet, sqlc diff, `go test -race` | 69 package ok, 828 test cấp cao nhất | **71** package ok, **854** test cấp cao nhất |
| golangci-lint v2.15.0 / govulncheck v1.9.0 | 0 issue / sạch | **0 issue / sạch** |
| test có tag `mgtestfixture` | 14 package, 39 test | **15 package, 40 test** |
| module lồng `tests/integration/headscale` | đạt | **đạt** |
| contract Headscale thật | 36 PASS / 0 FAIL | **36 / 0** |
| `make isolation` / isolation-headscale | 11 package / 13 PASS | **11 / 13** |
| Python (docs-check, docs/ khớp master, mgenv, render instance/edge/idp/backup/app/agent/mail, host migrate, test_stack, openapi lint) | 632 dòng PASS, 0 FAIL | **647** dòng PASS, 0 FAIL |
| `make e2e-functional` (mạng 10.238) | **58/58** PASS | **63/63** PASS (thêm E2E-76…78 của P3-T16) |
| api-types (node pin) | đạt | **đạt** |
| Worker `npm test` (node 26.13.1 pin) | 8/8 | **8/8** |
| ổn định `go test -race -count=3 ./...` (1 lượt, cụm PostgreSQL mới) | 69 package ok, 0 FAIL | **71** package ok, 0 FAIL |

Sau khi gộp còn chạy cục bộ các test Python mới của `main`: `test_render_monitoring.py` 202 PASS, `tests/g3/test_g3.py` 35 PASS. Hai lượt chuỗi trước đó dừng ở go-ci và được sửa bằng commit riêng: `TestReservedIDsCoverVersionsLock` (GID 20009 phải là ID dành riêng) và một test có thể chập chờn (TCP reset khi đóng kết nối còn dữ liệu chưa đọc).

VM: mọi container/network/volume/image/thư mục tiền tố `mailr`/`mailre2e` đã gỡ bằng `mailr-cleanup.sh` (mục 7).

## 5. Khác biệt so với yêu cầu và quyết định khi hiện thực

1. **Network `mail` là network của host** (`networks.sh`, 10.249.8.0/24, internal, tên đúng `mail` — không tiền tố `mg-`
   để khớp khóa `mail: {external: true}` mà P3-T16 đã dùng cho Alertmanager): relay, worker, idp, alertmanager nằm ở
   **ba project** khác nhau nên network phải tạo trước như các network dùng chung khác; network `mail` cục bộ của
   project `mg-idp` (Mailpit) giữ nguyên ở chế độ `mailpit`. Cũng để khớp P3-T16: CA ở `secrets/mail/ca.crt`, người gửi
   là biến `MG_SMTP_FROM` của env file.
2. **Lệnh thêm `admin mail-test`** — cách gửi thư thử tới địa chỉ chủ dự án chọn bằng đúng client của `notification.send`
   (container `mailrelay`/worker là distroless, không có client SMTP nào khác).
3. **Cache chống phát lại theo digest của body**, không theo chữ ký (lý do ở 2.2); kèm `duplicate` làm cho lần thử lại sau
   một câu trả lời bị mất không gửi trùng (trong cùng isolate).
4. **401/404 của Worker ⇒ 451 (tạm thời)**: khóa/đồng hồ/URL sai là lỗi triển khai, thư vẫn hợp lệ — client giữ và gửi lại
   sau khi người vận hành sửa; metric `forward_attempts_total{status="4xx"}` làm lộ ra.
5. **`partial` ⇒ 250**: một phần người nhận đã nhận; SMTP chỉ có một mã cho DATA, trả 4xx sẽ khiến client gửi trùng cho họ.
   Hiếm (worker và Keycloak gửi 1 người nhận/thư). Log WARN + `recipients_total{failed}`.
6. **Không AUTH ở cầu** (yêu cầu cho phép "optional"): network internal + một địa chỉ gửi + header From bị kiểm + giới hạn
   tốc độ/phiên; AUTH buộc mỗi client giữ thêm một mật khẩu (Keycloak: qua Admin API, không được trong template).
7. **Một khóa HMAC**, xoay ghi tại chỗ: khoảng giữa lúc đổi file trên host và `wrangler secret put` thư nhận 451 và được gửi
   lại; hai khóa song song không đáng độ phức tạp ở MVP.
8. **Worker bằng JavaScript thuần** (không TypeScript): wrangler triển khai trực tiếp, `node --test` chạy trực tiếp — không
   bước build, không dependency.
9. `MG_IDP_MAIL_SINK` nhận thêm giá trị `mailrelay` thay vì một biến mới: một biến duy nhất chọn đích SMTP của Keycloak.
10. **Tên service `mail-bridge`, máy SMTP `mailrelay`** (yêu cầu ghi "service `mailrelay`"): xem 2.6 — cần để `mailrelay:587`
    luôn phân giải ra địa chỉ có listener trên network `mail`.
11. **Sửa harness ngoài phạm vi:** `KeycloakAdmin` (tests/e2e/harness/backend.py) lấy lại token khi Admin API trả 401 —
    token của realm master sống 60 s và trên VM tải cao (load ~25) E2E-21 kéo dài 59 s làm E2E-24 hỏng dây chuyền (E2E-25,
    E2E-41, E2E-56); `asvs2.kc_call` vốn gọi `kc.__init__(kc.st)` nay có thuộc tính `st` thật.

## 6. Thủ tục cho người điều phối (theo thứ tự)

Điều kiện: nhánh đã gộp, workflow `images` build commit đó, `[images.mg-api]`/`[images.mg-worker]` pin cùng commit (image
worker có lệnh `mailrelay`). Lệnh host chạy từ gốc repo trên host staging; lệnh wrangler chạy trên **máy này** (đăng nhập
OAuth sẵn có), trong **Git Bash** (ống của PowerShell 5.1 có thể đổi byte/thêm CRLF).

1. **Host — nhóm, network, file** (chạy lại an toàn):
   ```bash
   sudo bash infrastructure/host/layout.sh          # nhóm mg-sec-mail 20009 (mail-secrets.sh cũng tự tạo)
   sudo bash infrastructure/host/networks.sh        # tạo network mail 10.249.8.0/24 internal; giữ các network khác
   sudo bash infrastructure/host/mail-secrets.sh    # khóa HMAC + CA nội bộ + chứng chỉ mailrelay; chỉ in quyền, dấu vân tay, hạn
   sudo bash infrastructure/host/check-secrets.sh   # mail/relay_hmac_key, mail/tls_key: chỉ 65532+20009 đọc được
   ```
2. **Máy này — render và triển khai Worker**:
   ```bash
   python3 tools/render_mail.py infrastructure/environments/staging/staging.env infrastructure/mail/cf-worker
   cat infrastructure/mail/cf-worker/wrangler.toml   # name meshguard-mailrelay-staging, allowed_sender_addresses = no-reply@<domain>
   cd infrastructure/mail/cf-worker && npx wrangler@4.158.0 deploy   # in ra URL https://meshguard-mailrelay-staging.<subdomain>.workers.dev
   ```
3. **Máy này — đặt khóa cho Worker từ file của host, không in, không ghi đĩa** (vẫn trong `infrastructure/mail/cf-worker`):
   ```bash
   ssh -i ~/.ssh/id_ed25519_meshguard -o IdentitiesOnly=yes mgdeploy@<IP LAN staging> \
     'sudo cat /opt/meshguard/secrets/mail/relay_hmac_key' | npx wrangler@4.158.0 secret put RELAY_HMAC_KEY
   ```
   (Muốn giữ bản sao theo quy ước Phase 3: thêm `| tee config/secrets/staging/mail_relay_hmac_key` trước `| npx …` — thư
   mục gitignored, không đồng bộ lên đâu khác.)
4. **Env file** `infrastructure/environments/staging/staging.env` (+ ghi `current.md`):
   ```text
   MG_MAILRELAY_URL=https://meshguard-mailrelay-staging.<subdomain>.workers.dev/v1/send
   MG_IDP_MAIL_SINK=mailrelay        # thay mailpit — Keycloak gửi qua relay thật (Mailpit bị gỡ khi up --remove-orphans)
   ```
   (Tùy chọn: `MG_SMTP_FROM="Tên <địa chỉ>"` — mặc định `MeshGuard <no-reply@<MG_BASE_DOMAIN>>`, dùng chung cho worker,
   Keycloak, Alertmanager và Worker; đổi người gửi ⇒ render + deploy lại Worker ở bước 2.)
5. **Render + chạy** (host):
   ```bash
   python3 tools/render_app.py infrastructure/environments/staging/staging.env /tmp/mg-app   # → /opt/meshguard/core/compose.app.yaml
   python3 tools/render_idp.py infrastructure/environments/staging/staging.env /tmp/mg-idp   # → /opt/meshguard/core/ (compose.idp.yaml, idp/realms)
   APP="sudo docker compose -p mg-app -f /opt/meshguard/core/compose.app.yaml"
   IDP="sudo docker compose -p mg-idp -f /opt/meshguard/core/compose.idp.yaml"
   $APP up -d --wait mail-bridge worker          # mail-bridge healthy; worker log "notification relay configured … tls starttls"
   $IDP up -d --wait --remove-orphans idp        # idp vào network mail, tin CA (KC_TRUSTSTORE_PATHS); mailsink bị gỡ
   sudo bash infrastructure/idp/realm-update.sh --check && sudo bash infrastructure/idp/realm-update.sh   # smtpServer của realm đang chạy
   ```
6. **Thư thử tới địa chỉ chủ dự án chọn**:
   ```bash
   $APP exec -T worker /usr/local/bin/meshguard admin mail-test --to <địa chỉ chủ dự án chọn>   # exit 0, result "sent"
   $APP logs --since 5m mailrelay | grep 'message relayed'                                       # result delivered, status 200
   ```
   Kiểm hộp thư (SPF/DKIM/DMARC pass trong header), dashboard Email Sending của Cloudflare. Thư Keycloak: console quản trị
   (phiên 2P — P3-T15) → realm platform → Realm settings → Email → *Test connection* (gửi tới email của admin đang đăng nhập).
7. **Alertmanager (P3-T16)**: `smtp_smarthost: mailrelay:587`, `smtp_from` = địa chỉ gửi của relay, `smtp_require_tls: true`,
   `tls_config: {ca_file: <mount của /opt/meshguard/secrets/mail/ca.crt>, server_name: mailrelay}`, network `mail`
   (external) — đúng như nhánh `p3-t16` đã render (`MG_ALERT_EMAIL_TO`, `MAIL_CA_DEFAULT`); scrape `mailrelay:9090/metrics` qua `mg-obs`.
8. **Hoàn tác**: bỏ `MG_MAILRELAY_URL` (và `MG_IDP_MAIL_SINK` về giá trị cũ), render lại, `$APP up -d --remove-orphans api
   worker`, `$IDP up -d --remove-orphans`, `realm-update.sh`; `npx wrangler@4.158.0 delete` (trong thư mục Worker);
   `sudo rm -rf /opt/meshguard/secrets/mail`; `sudo docker network rm mail` khi không còn container gắn.

## 7. Bàn giao và xung đột gộp dự kiến

| Việc | Ai / task |
|---|---|
| Bước 1–6 của mục 6 trên staging (deploy Worker, khóa, URL, render, thư thử) | Người điều phối |
| Alertmanager gửi qua `mailrelay:587` (mục 6 bước 7), rule `meshguard_mailrelay_messages_total{result=~"temporary|permanent"}` | P3-T16 / P6-T01 |
| Allow-list đường ra của `mailrelay` (TCP 443 tới dải Cloudflare) | P6-T07 |
| `smtpServer` → relay cho realm do driver tạo (khi một luồng cần Keycloak gửi thư) | task dùng `Invite.SendEmail` |
| **Quan sát (ngoài phạm vi, chưa điều tra):** trên stack E2E (lượt dev thứ hai), 3 hàng `tenant.invitation` do API lời mời của E2E-37 (P3-T05a) tạo vẫn `pending`, `attempts = 0` sau ~1 phút và không thấy hàng `provisioning_jobs` nào mang dedupe `notification:<id>` của chúng — trong khi mọi hàng email khác (`policy.applied`, `idp.admin_change`, `idp.console_login`: 117 hàng) đều `sent` qua relay với `attempts = 1`. Nếu đúng là đường của API không enqueue `notification.send` thì thư mời không bao giờ đi | P3-T05a / người điều phối |

Xung đột gộp dự kiến (các agent song song): `tools/render_app.py` + `compose.app.yaml.tmpl` (TEMPLATE_VERSION 3, các
placeholder `${worker_mail_*}`, `${mailrelay_service}`, `${mail_*_def}`), `tools/render_idp.py`, `infrastructure/host/
networks.sh` (dải `10.249.8.0/24`), `versions.lock [ids]` (GID 20009), `compose.yaml`/`stack.py`/`e2e.py` của harness,
`ci.yml`, master §7.6/§14.3/§16.3 — đều là thêm dòng, giải bằng cách giữ cả hai. Nếu P3-T16 đã khai báo network `mail`
khác thì thống nhất về network `mail` của `networks.sh` (đã khớp ở nhánh `p3-t16` hiện tại: tên `mail`, `ca.crt`,
`MG_SMTP_FROM`).

Kết luận: **đạt** (functional, dev/CI) — cầu SMTP thật + Worker (mã thật, binding giả): thông báo của worker, thư Keycloak và thư thử đi qua `mailrelay:587` (STARTTLS, CA nội bộ) tới Worker với HMAC hợp lệ, đúng người gửi duy nhất; khóa sai, timestamp cũ, phát lại bị từ chối / không gửi lại; chuỗi CI đầy đủ xanh trên commit sau khi gộp `main`. Gửi thật qua Cloudflare Email Service **chờ người điều phối** triển khai Worker và điền `MG_MAILRELAY_URL` (mục 6).
