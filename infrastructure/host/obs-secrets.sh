#!/bin/bash
# P3-T16 — secret dạng file của kênh cảnh báo (project mg-obs, Alertmanager — §14.2 nhóm mg-sec-obs 20006): giá trị do
# chủ dự án cung cấp (relay SMTP, bot Telegram, webhook ngoài), KHÔNG sinh ngẫu nhiên, KHÔNG bao giờ in ra, không nằm
# trong repo, biến môi trường hay file compose. Mỗi secret một file root:mg-sec-obs 0440 trong /opt/meshguard/secrets/obs/
# — Alertmanager (65534 + nhóm 20006) đọc qua /run/secrets/<tên> (auth_password_file, bot_token_file, url_file).
#
#   smtp_password        mật khẩu của MG_ALERT_SMTP_USERNAME trên relay SMTP (MG_ALERT_SMTP_SMARTHOST)
#   telegram_bot_token   token bot Telegram (MG_ALERT_TELEGRAM_CHAT_ID)
#   alert_webhook_url    URL đầy đủ của webhook ngoài (có thể chứa token) — MG_ALERT_WEBHOOK=on
#
# Dùng (root):
#   sudo bash infrastructure/host/obs-secrets.sh set <tên> < /đường/dẫn/file-tạm     giá trị từ stdin (một dòng; không echo)
#   sudo bash infrastructure/host/obs-secrets.sh remove <tên>                         gỡ (tắt kênh trong file tham số trước)
#   sudo bash infrastructure/host/obs-secrets.sh check                                liệt kê owner/mode/kích thước, không in giá trị
# Sau set/remove: render lại mg-obs (tools/render_monitoring.py) rồi `up -d alertmanager` (RUNBOOK mục P3-T16). Token của
# listener metrics (obs/edge_metrics_token) do layout.sh sinh — không quản lý ở đây.
set -euo pipefail
R=${MG_SECRETS_ROOT:-/opt/meshguard/secrets}/obs
NAMES="smtp_password telegram_bot_token alert_webhook_url"
[ "$(id -u)" = 0 ] || { echo "cần chạy bằng root (sudo)"; exit 1; }
have=$(getent group mg-sec-obs | cut -d: -f3 || true)
[ "$have" = 20006 ] || { echo "nhóm mg-sec-obs phải có GID 20006 (layout.sh, P1-T03) — dừng"; exit 1; }
[ -d "$R" ] || { echo "thiếu $R (layout.sh) — dừng"; exit 1; }
valid() { case " $NAMES " in *" $1 "*) return 0;; esac; echo "tên secret phải là một trong: $NAMES"; exit 2; }

case "${1:-}" in
  set)
    [ $# -eq 2 ] || { echo "dùng: obs-secrets.sh set <tên> < file"; exit 2; }
    valid "$2"
    [ -t 0 ] && { echo "đưa giá trị qua stdin (chuyển hướng từ file tạm), không gõ trên terminal"; exit 2; }
    umask 077
    tmp=$(mktemp "$R/.$2.XXXXXX")
    trap 'rm -f "$tmp"' EXIT
    head -c 4096 | tr -d '\r\n' > "$tmp"
    n=$(wc -c < "$tmp")
    [ "$n" -ge 1 ] || { echo "giá trị rỗng — không ghi"; exit 1; }
    if [ "$2" = alert_webhook_url ]; then
      grep -Eq '^https://[^[:space:]]+$' "$tmp" || { echo "alert_webhook_url phải là một URL https:// — không ghi"; exit 1; }
    fi
    chown root:mg-sec-obs "$tmp" && chmod 0440 "$tmp" && mv "$tmp" "$R/$2"
    trap - EXIT
    echo "đã ghi $R/$2 ($n byte, root:mg-sec-obs 0440)"
    ;;
  remove)
    [ $# -eq 2 ] || { echo "dùng: obs-secrets.sh remove <tên>"; exit 2; }
    valid "$2"
    rm -f "$R/$2" && echo "đã gỡ $R/$2"
    ;;
  check)
    for n in edge_metrics_token $NAMES; do
      if [ -s "$R/$n" ]; then
        echo "$n: $(stat -c '%U:%G %a' "$R/$n"), $(wc -c < "$R/$n") byte"
      else
        echo "$n: không có"
      fi
    done
    ;;
  *) echo "dùng: obs-secrets.sh set <tên> < file | remove <tên> | check"; exit 2 ;;
esac
