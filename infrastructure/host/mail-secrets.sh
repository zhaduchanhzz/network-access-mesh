#!/bin/bash
# P3-T05b-mail — file của relay thư ra (service `mail-bridge` của mg-app, máy SMTP `mailrelay`; worker, Keycloak, Alertmanager gửi qua nó) theo
# §14.2. Giá trị sinh NGAY trên host, KHÔNG BAO GIỜ in ra (chỉ in đường dẫn, quyền, dấu vân tay và hạn của chứng chỉ):
#   mail/relay_hmac_key  root:mg-sec-mail 0440  khóa HMAC chung với Worker Cloudflare (secret RELAY_HMAC_KEY) — 48 ký tự
#                                               [A-Za-z0-9]; mailrelay đọc lại ở MỖI thư
#   mail/tls_key         root:mg-sec-mail 0440  khóa EC P-256 của chứng chỉ STARTTLS của mailrelay
#   mail/tls_cert        root:root 0444         chứng chỉ "mailrelay" (SAN DNS:mailrelay, serverAuth, 825 ngày)
#   mail/ca.crt          root:root 0444         CA nội bộ ký chứng chỉ trên (nameConstraints: CHỈ DNS:mailrelay; 3 năm) —
#                                               khóa của CA bị xóa ngay sau khi ký, không bao giờ nằm trên đĩa lâu hơn
# Hai chứng chỉ là dữ liệu công khai (0444): worker (MG_SMTP_CA_FILE), Keycloak (KC_TRUSTSTORE_PATHS), Alertmanager tin CA.
# Nhóm mg-sec-mail (GID 20009 — versions.lock [ids]) được tạo nếu chưa có (layout.sh cũng tạo).
#
# Dùng:      sudo bash infrastructure/host/mail-secrets.sh                (chạy lại an toàn: file đã có thì giữ nguyên)
#            sudo bash infrastructure/host/mail-secrets.sh --rotate-tls   CA + chứng chỉ mới, ghi đè TẠI CHỖ; mailrelay tự nạp
#              chứng chỉ mới, còn các client phải khởi động lại để tin CA mới: mailrelay, worker, idp, alertmanager
#            sudo bash infrastructure/host/mail-secrets.sh --rotate-hmac  khóa mới, ghi TẠI CHỖ (mailrelay dùng ngay, không
#              restart) — rồi đặt ngay khóa đó cho Worker: ssh … 'sudo cat …/relay_hmac_key' | npx wrangler secret put
#              RELAY_HMAC_KEY (thư trong khoảng giữa nhận 401 ⇒ SMTP 451, client gửi lại)
# Kiểm:      sudo bash infrastructure/host/check-secrets.sh
# Hoàn tác:  sudo rm -rf /opt/meshguard/secrets/mail   (rồi bỏ MG_MAILRELAY_URL khỏi env file và render lại mg-app, mg-idp)
# MG_SECRETS_ROOT đổi gốc (mặc định /opt/meshguard/secrets) — stack dev/CI chạy script này trong container dùng một lần.
set -euo pipefail
R=${MG_SECRETS_ROOT:-/opt/meshguard/secrets}
D=$R/mail
GID=20009
rotate_tls=0
rotate_hmac=0
for a in "$@"; do
  case "$a" in
    --rotate-tls) rotate_tls=1 ;;
    --rotate-hmac) rotate_hmac=1 ;;
    *) echo "tham số không hợp lệ (--rotate-tls, --rotate-hmac)"; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "cần chạy bằng root (sudo)"; exit 1; }
command -v openssl >/dev/null || { echo "thiếu openssl"; exit 1; }
have=$(getent group mg-sec-mail | cut -d: -f3 || true)
if [ -z "$have" ]; then
  if getent group "$GID" >/dev/null; then echo "GID $GID đã thuộc nhóm khác — dừng"; exit 1; fi
  groupadd --system --gid "$GID" mg-sec-mail
elif [ "$have" != "$GID" ]; then
  echo "nhóm mg-sec-mail phải có GID $GID (versions.lock [ids]) — dừng"; exit 1
fi
umask 077
[ -d "$R" ] || install -d -o root -g root -m 0700 "$R"
install -d -o root -g root -m 0700 "$D"

gen() {   # 48 ký tự [A-Za-z0-9] từ /dev/urandom (pipefail tắt cục bộ: head đóng ống trước tr)
  (set +o pipefail; tr -dc 'A-Za-z0-9' </dev/urandom | head -c 48)
}
put() {   # put <nguồn> <đích> <owner:group> <mode>: ghi TẠI CHỖ khi đích đã có (cùng inode — bind mount của container
          # đang chạy thấy giá trị mới), tạo mới thì qua file tạm + mv
  if [ -e "$2" ]; then cat "$1" > "$2"; else cp "$1" "$2.tmp" && mv "$2.tmp" "$2"; fi
  chown "$3" "$2"
  chmod "$4" "$2"
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
if [ ! -s "$D/relay_hmac_key" ] || [ "$rotate_hmac" = 1 ]; then
  gen > "$tmp/hmac"
  put "$tmp/hmac" "$D/relay_hmac_key" root:mg-sec-mail 0440
  echo "khóa HMAC mới: đặt NGAY cho Worker — wrangler secret put RELAY_HMAC_KEY (giá trị qua stdin, không in)"
fi
chown root:mg-sec-mail "$D/relay_hmac_key"
chmod 0440 "$D/relay_hmac_key"

if [ ! -s "$D/tls_key" ] || [ ! -s "$D/tls_cert" ] || [ ! -s "$D/ca.crt" ] || [ "$rotate_tls" = 1 ]; then
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  ec=(-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes)
  openssl req -x509 "${ec[@]}" -keyout "$tmp/ca.key" -out "$tmp/ca.crt" -days 1095 \
    -subj "/O=MeshGuard/CN=MeshGuard mail relay internal CA $stamp" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "nameConstraints=critical,permitted;DNS:mailrelay" 2>/dev/null
  openssl req -new "${ec[@]}" -keyout "$tmp/tls.key" -out "$tmp/tls.csr" -subj "/CN=mailrelay" 2>/dev/null
  printf 'subjectAltName=DNS:mailrelay\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' \
    > "$tmp/ext"
  openssl x509 -req -in "$tmp/tls.csr" -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" -set_serial "0x$(openssl rand -hex 16)" \
    -days 825 -extfile "$tmp/ext" -out "$tmp/tls.crt" 2>/dev/null
  rm -f "$tmp/ca.key"                                    # khóa CA không sống quá lần ký duy nhất
  openssl verify -CAfile "$tmp/ca.crt" "$tmp/tls.crt" >/dev/null
  put "$tmp/tls.key" "$D/tls_key" root:mg-sec-mail 0440
  put "$tmp/tls.crt" "$D/tls_cert" root:root 0444
  put "$tmp/ca.crt" "$D/ca.crt" root:root 0444
  echo "CA nội bộ + chứng chỉ mailrelay mới — khởi động lại client để tin CA mới (worker, idp, alertmanager)"
fi
openssl verify -CAfile "$D/ca.crt" "$D/tls_cert" >/dev/null || { echo "tls_cert không do ca.crt ký — dừng"; exit 1; }
find "$D" -mindepth 1 -printf '%M %u:%g %p\n' | sort -k3
openssl x509 -in "$D/tls_cert" -noout -subject -enddate -fingerprint -sha256 | sed 's/^/tls_cert: /'
openssl x509 -in "$D/ca.crt" -noout -subject -enddate -fingerprint -sha256 | sed 's/^/ca.crt:   /'
