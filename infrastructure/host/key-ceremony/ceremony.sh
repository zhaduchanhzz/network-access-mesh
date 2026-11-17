#!/bin/bash
# P2-T04a — nghi thức khóa (key ceremony) của một môi trường MeshGuard. Runbook: docs/operations/key-ceremony.md.
#
#   sudo bash ceremony.sh <bước> [tùy chọn]
#
#   preflight                   kiểm điều kiện; không thay đổi gì                          (người điều phối, không TTY)
#   generate                    sinh kek-app, kek-ops, khóa ký manifest, khóa khôi phục     (người điều phối, không TTY)
#   show-offline                hiện vật liệu khóa để chép tay — CHỈ trên TTY tương tác      (chủ dự án, ssh -t)
#   verify-offline --copy 1|2   nhập lại từ bản giấy (không hiện chữ) và đối chiếu           (chủ dự án, ssh -t)
#   drill [--copy 1|2]          nạp lại KEK từ bản nhập lại + giải mã thử bằng khóa khôi phục (người điều phối)
#   cleanup [--abort]           hủy (shred) vật liệu tạm trên tmpfs rồi umount              (người điều phối)
#   status                      trạng thái + giá trị công khai (kek_id, KCV, recipient, khóa công khai ký manifest)
#   undo --keys-never-used      gỡ mọi khóa vừa sinh — CHỈ khi chưa dịch vụ nào dùng chúng
#
# Biến môi trường (không bí mật; để trống trên host thật — chỉ dùng khi thử trên máy build):
#   MGKC_ROOT          gốc của hệ thống file giả lập: <gốc>/opt/meshguard, <gốc>/etc, <gốc>/proc/swaps (mặc định rỗng)
#   MGKC_TMP           điểm mount tmpfs làm việc (mặc định /run/mg-key-ceremony)
#   MGKC_AGE_DIR       thư mục chứa age, age-keygen build bằng build-age.sh (mặc định <thư mục này>/bin)
#   MGKC_WORKER_IMAGE  image worker có lệnh kek-drill: <tên>@sha256:… hoặc ID image cục bộ (mặc định
#                      [images.mg-worker] trong versions.lock)
#   MGKC_ENV_FILE      file tham số môi trường (mặc định infrastructure/environments/staging/staging.env)
#
# Không giá trị bí mật nào nằm trên dòng lệnh, trong biến môi trường hay log: vật liệu khóa chỉ đi qua file (0400/0440
# trên đĩa cho khóa dùng lâu dài, tmpfs riêng cho vật liệu tạm), stdin và builtin của bash (printf, read). Không bao
# giờ bật `set -x`. Mã thoát: 0 đạt, 1 lỗi/không đạt, 2 sai cú pháp, 3 từ chối vì không có TTY.
set -Eeuo pipefail
set +x
umask 077
ulimit -c 0
export LC_ALL=C

STEP=${1:-help}
if [ $# -gt 0 ]; then shift; fi

KIT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO=$(cd -- "$KIT/../../.." && pwd -P)
VERSIONS=$REPO/versions.lock
ROOT=${MGKC_ROOT:-}
TMPD=${MGKC_TMP:-/run/mg-key-ceremony}
AGE_DIR=${MGKC_AGE_DIR:-$KIT/bin}
ENV_FILE=${MGKC_ENV_FILE:-$REPO/infrastructure/environments/staging/staging.env}

MG=$ROOT/opt/meshguard
SECRETS=$MG/secrets
KR_APP=$SECRETS/kek-app                          # §7.6, §14.2: root:mg-sec-app 0750, file 0440 — api, worker
KR_OPS=$SECRETS/kek-ops                          # root:mg-sec-worker 0750, file 0440 — chỉ worker
AGENT_DIR=$SECRETS/agent
SIGN_KEY=$AGENT_DIR/manifest_signing_key         # §14.2: root:root 0400 — chỉ agent (chạy root)
PUB=$MG/core/keys                                # giá trị công khai: root 0755 / 0644
RECIPIENT=$PUB/backup-recovery.age-recipient     # recipient của khóa khôi phục (đường DR — §17.1)
SIGN_PUB=$PUB/manifest-signing.pub.pem
KCV_REC=$PUB/kek.kcv
IDENTITY=$TMPD/recovery.agekey                   # private key khôi phục: CHỈ trên tmpfs, tới bước cleanup
LOCK=$TMPD.lock
SELF="sudo bash $KIT/ceremony.sh"
KCV_LABEL=meshguard/kek-kcv/v1                   # = secrets.KCVLabel (Go)
B32=qpzry9x8gf2tvdw0s3jn54khce6mua7l             # bộ ký tự bech32 (age)
KEKID_RE='^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'     # = CHECK của tenant_keys.kek_id và tên file keyring

say() { printf '[%s] %s\n' "$STEP" "$*"; }
die() { printf '[%s] LỖI: %s\n' "$STEP" "$*" >&2; exit 1; }
# shellcheck disable=SC2016 # $LINENO phải được tính lúc trap chạy
trap 'printf "[%s] LỖI không mong đợi ở dòng %s (không có giá trị nào được in)\n" "$STEP" "$LINENO" >&2' ERR

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$KIT/ceremony.sh"; }

case $ROOT in '' | /*) ;; *) die "MGKC_ROOT phải là đường dẫn tuyệt đối" ;; esac
case $TMPD in /?*) ;; *) die "MGKC_TMP phải là đường dẫn tuyệt đối" ;; esac

# ---------------------------------------------------------------- tiện ích

# lock_get <bảng> <khóa>: giá trị trong versions.lock (TOML), rỗng nếu không có.
lock_get() {
  python3 -I -c 'import sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))
for part in sys.argv[2].split("."):
    d = d.get(part) if isinstance(d, dict) else None
v = d.get(sys.argv[3]) if isinstance(d, dict) else None
print("" if v is None else v)' "$VERSIONS" "$1" "$2"
}

# kcv_stdin: KCV của một KEK — 64 ký tự hex đọc từ stdin (khóa không bao giờ là đối số hay biến môi trường):
# hex(HMAC-SHA256(KEK, "meshguard/kek-kcv/v1"))[:8], cùng định nghĩa với secrets.KCVLabel (Go).
kcv_stdin() {
  python3 -I -c 'import hashlib, hmac, re, sys
h = sys.stdin.read().strip()
if not re.fullmatch("[0-9a-fA-F]{64}", h):
    sys.exit("kcv: cần đúng 64 ký tự hex")
print(hmac.new(bytes.fromhex(h), sys.argv[1].encode(), hashlib.sha256).hexdigest()[:8])' "$KCV_LABEL"
}

kcv_file() { kcv_stdin <"$1"; }

# env_name: MG_ENV của file tham số (tiền tố kek_id); trả 1 nếu không đọc được.
env_name() {
  local e
  e=$(python3 -I "$REPO/tools/mgenv.py" show "$ENV_FILE" 2>/dev/null | sed -n 's/^MG_ENV=//p') || return 1
  [[ $e =~ ^[a-z0-9]{1,16}$ ]] || return 1
  printf '%s' "$e"
}

gid_of() { lock_get ids "$1"; }

# worker_image: image có kek-drill — MGKC_WORKER_IMAGE hoặc [images.mg-worker] của versions.lock, luôn theo digest.
worker_image() {
  local img=${MGKC_WORKER_IMAGE:-} name idx
  if [ -z "$img" ]; then
    name=$(lock_get images.mg-worker image)
    idx=$(lock_get images.mg-worker index)
    if [ -n "$name" ] && [ -n "$idx" ]; then img=$name@$idx; fi
  fi
  [[ $img =~ ^([a-z0-9][a-z0-9._/:-]*@)?sha256:[0-9a-f]{64}$ ]] || return 1
  printf '%s' "$img"
}

mode_of() { stat -c '%U:%G %a' "$1"; }

# run_worker <tên container> <đối số docker run…>: chạy một container worker có giới hạn thời gian. Image cũ không có
# kek-drill sẽ bỏ qua đối số và chạy tiến trình worker mãi mãi — timeout rồi xóa container, không bao giờ treo.
run_worker() {
  local name=$1 rc=0
  shift
  timeout --kill-after=5 60 docker run --name "$name" "$@" || rc=$?
  docker rm -f "$name" >/dev/null 2>&1 || true
  return "$rc"
}

require_root() { [ "$(id -u)" -eq 0 ] || die "cần chạy bằng root: $SELF $STEP"; }

# require_tty: bước hiện hoặc nhận vật liệu khóa chỉ chạy khi stdin VÀ stdout là terminal tương tác. Tự động hóa của
# người điều phối chạy SSH không có TTY nên luôn bị từ chối ở đây — trước khi đọc bất kỳ file khóa nào.
require_tty() {
  if [ ! -t 0 ] || [ ! -t 1 ]; then
    printf '[%s] TỪ CHỐI: bước này chỉ chạy trong terminal tương tác của chủ dự án (stdin và stdout phải là TTY — ssh -t). Không có gì được hiển thị hay thay đổi.\n' "$STEP" >&2
    exit 3
  fi
}

take_lock() {
  exec 9>>"$LOCK"
  flock -n 9 || die "một bước khác của nghi thức đang chạy — đợi bước đó xong rồi chạy lại"
}

in_progress() { mountpoint -q "$TMPD" && [ -s "$IDENTITY" ]; }

require_in_progress() {
  in_progress || die "không có nghi thức đang dở ($TMPD chưa mount hoặc không còn identity khôi phục) — chạy generate trước"
}

# lock_in_progress: bước cần nghi thức đang dở — kiểm trước khi tạo file khóa, giữ khóa, rồi kiểm lại.
lock_in_progress() {
  require_in_progress
  take_lock
  require_in_progress
}

# stage_age: dùng bản age/age-keygen chép vào tmpfs, sau khi kiểm sha256 với versions.lock (kiểm lại ở mọi bước).
stage_age() {
  local b want have
  install -d -o root -g root -m 0700 "$TMPD/bin"
  for b in age age-keygen; do
    want=$(lock_get sources.age "${b//-/_}_linux_amd64_sha256")
    [ -x "$TMPD/bin/$b" ] || install -o root -g root -m 0500 "$AGE_DIR/$b" "$TMPD/bin/$b"
    have=$(sha256sum <"$TMPD/bin/$b" | cut -d' ' -f1)
    if [ -z "$want" ] || [ "$have" != "$want" ]; then die "sha256 của $b ($have) khác versions.lock [sources.age] ($want)"; fi
  done
}

shred_tree() {  # <thư mục>: ghi đè rồi xóa mọi file, sau đó xóa thư mục
  [ -e "$1" ] || return 0
  find "$1" -type f -exec shred -u -z -n 1 -- {} +
  rm -rf -- "$1"
}

# read_line <biến> [-s]: đọc một dòng từ terminal; hết dữ liệu (Ctrl-D) ⇒ dừng hẳn (không bao giờ lặp vô hạn).
read_line() {
  local -n _dst=$1
  if [ "${2:-}" = -s ]; then IFS= read -r -s _dst || die "đã dừng (hết dữ liệu nhập)"; else IFS= read -r _dst || die "đã dừng (hết dữ liệu nhập)"; fi
}

# ---------------------------------------------------------------- preflight

PROBLEMS=()
ok() { printf '[%s]   OK   %s\n' "$STEP" "$*"; }
bad() { printf '[%s]   LỖI  %s\n' "$STEP" "$*"; PROBLEMS+=("$*"); }

run_checks() {
  PROBLEMS=()
  local t missing=() g want have p img out rc avail swaps hits b ver env
  for t in python3 openssl docker shred sha256sum flock mount umount mountpoint getent stat install find cmp awk timeout date; do
    command -v "$t" >/dev/null 2>&1 || missing+=("$t")
  done
  if [ ${#missing[@]} -gt 0 ]; then bad "thiếu công cụ: ${missing[*]}"; return 0; fi
  ok "công cụ: $(python3 -V 2>&1), $(openssl version | cut -d' ' -f1-2), Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '?'), bash $BASH_VERSION"
  python3 -I -c 'import tomllib' 2>/dev/null || bad "python3 cần ≥ 3.11 (tomllib)"
  case $(openssl version) in "OpenSSL 3."*) ;; *) bad "cần OpenSSL 3.x (Ed25519)" ;; esac
  if [ ! -f "$VERSIONS" ]; then bad "không thấy $VERSIONS (bản sao repo trên host chưa đầy đủ)"; return 0; fi

  for g in mg-sec-app mg-sec-worker; do
    want=$(gid_of "$g")
    have=$(getent group "$g" | cut -d: -f3 || true)
    if [ -n "$want" ] && [ "$have" = "$want" ]; then ok "nhóm $g = GID $have"; else bad "nhóm $g: GID '${have:-không có}', cần ${want:-?} (layout.sh — P1-T03)"; fi
  done

  if [ -d "$SECRETS" ] && [ "$(mode_of "$SECRETS")" = "root:root 700" ]; then ok "$SECRETS root:root 0700"; else bad "$SECRETS phải có sẵn, root:root 0700 (layout.sh)"; fi
  if [ -d "$MG/core" ]; then ok "$MG/core có sẵn"; else bad "thiếu $MG/core (layout.sh)"; fi
  have=${#PROBLEMS[@]}
  for p in "$KR_APP" "$KR_OPS" "$SIGN_KEY" "$RECIPIENT" "$SIGN_PUB" "$KCV_REC"; do
    [ ! -e "$p" ] || bad "đã tồn tại: $p — nghi thức chỉ sinh khóa một lần (xoay KEK: P6-T05; gỡ khi CHƯA dùng: undo --keys-never-used)"
  done
  [ "${#PROBLEMS[@]}" != "$have" ] || ok "chưa có khóa nào của nghi thức (kek-app, kek-ops, khóa ký manifest, file công khai)"

  if [ -e "$TMPD" ]; then
    bad "$TMPD đã tồn tại — nghi thức dở dang? (status; bỏ dở: cleanup --abort)"
  elif [ ! -d "$(dirname -- "$TMPD")" ]; then
    bad "thư mục cha của $TMPD không tồn tại"
  else
    avail=$(awk '/^MemAvailable:/ { print int($2 / 1024) }' /proc/meminfo)
    if [ "${avail:-0}" -ge 256 ]; then ok "tmpfs riêng sẽ mount tại $TMPD (64 MiB; RAM trống ${avail} MiB)"; else bad "RAM trống ${avail:-?} MiB < 256 MiB"; fi
  fi
  swaps=/proc/swaps
  if [ -n "$ROOT" ] && [ -f "$ROOT/proc/swaps" ]; then swaps=$ROOT/proc/swaps; fi
  if [ "$(grep -vc '^Filename' "$swaps" || true)" = 0 ]; then
    ok "không có swap đang bật (trang tmpfs không thể bị ghi ra đĩa)"
  else
    bad "swap đang bật — vật liệu trên tmpfs có thể bị ghi ra đĩa: tắt trong lúc làm nghi thức (sudo swapoff -a; hoàn tác: sudo swapon -a)"
  fi
  hits=$(grep -rhsE '^[^#]*(log_(input|output)|LOG_(INPUT|OUTPUT))' "$ROOT/etc/sudoers" "$ROOT/etc/sudoers.d" || true)
  if [ -z "$hits" ]; then ok "sudo không ghi I/O của phiên (log_input/log_output tắt)"; else bad "sudo đang ghi I/O của phiên (log_input/log_output) — màn hình và phím của chủ dự án sẽ bị ghi ra đĩa"; fi
  hits=$(grep -rlsE '^[^#]*pam_tty_audit' "$ROOT/etc/pam.d" || true)
  if [ -z "$hits" ]; then ok "không có pam_tty_audit (phím gõ không bị audit)"; else bad "pam_tty_audit đang bật ($hits) — phím gõ lúc nhập lại bản sao sẽ vào audit log"; fi

  ver=$(lock_get sources.age version)
  for b in age age-keygen; do
    want=$(lock_get sources.age "${b//-/_}_linux_amd64_sha256")
    if [ ! -f "$AGE_DIR/$b" ]; then bad "thiếu $AGE_DIR/$b (build-age.sh trên máy build rồi chép sang — runbook)"; continue; fi
    have=$(sha256sum <"$AGE_DIR/$b" | cut -d' ' -f1)
    if [ -n "$want" ] && [ "$have" = "$want" ] && [ "$("$AGE_DIR/$b" --version 2>/dev/null || true)" = "$ver" ]; then
      ok "$b $ver, sha256 khớp versions.lock"
    else
      bad "$b: sha256 $have hoặc phiên bản khác versions.lock [sources.age] ($ver, $want)"
    fi
  done

  if img=$(worker_image); then
    if docker image inspect "$img" >/dev/null 2>&1; then
      rc=0
      out=$(run_worker "mgkc-preflight-$$" --rm --pull never --network none --read-only --cap-drop ALL \
        --security-opt no-new-privileges --log-driver none "$img" kek-drill 2>&1) || rc=$?
      if [ "$rc" = 2 ] && [[ $out == *"usage: meshguard-worker kek-drill"* ]]; then ok "image worker có kek-drill: $img"; else bad "image $img không có lệnh kek-drill (exit $rc)"; fi
    else
      bad "image worker chưa có trên host: docker pull $img"
    fi
  else
    bad "chưa có image worker theo digest: [images.mg-worker] trong versions.lock (hoặc MGKC_WORKER_IMAGE)"
  fi
  if env=$(env_name); then ok "môi trường: $env ($ENV_FILE)"; else bad "không đọc được MG_ENV (chữ thường/số) từ $ENV_FILE"; fi
}

do_preflight() {
  run_checks
  say "Thay đổi trên host: không có."
  if [ ${#PROBLEMS[@]} -gt 0 ]; then say "KẾT QUẢ: KHÔNG ĐẠT (${#PROBLEMS[@]} lỗi)"; exit 1; fi
  say "KẾT QUẢ: ĐẠT — sẵn sàng cho bước generate"
}

# ---------------------------------------------------------------- generate

CREATED=()
GEN_DONE=0

# gen_rollback (trap EXIT của generate): generate thất bại giữa chừng ⇒ gỡ mọi thứ vừa tạo (chưa dịch vụ nào dùng).
gen_rollback() {
  local i p
  [ "$GEN_DONE" = 0 ] || return 0
  printf '[generate] THẤT BẠI — gỡ những gì vừa tạo (chưa dịch vụ nào dùng):\n' >&2
  for ((i = ${#CREATED[@]} - 1; i >= 0; i--)); do
    p=${CREATED[i]}
    if [ -d "$p" ]; then shred_tree "$p"; elif [ -e "$p" ]; then shred -u -z -n 1 -- "$p"; fi
    printf '  đã gỡ %s\n' "$p" >&2
  done
  if mountpoint -q "$TMPD"; then
    find "$TMPD" -type f -exec shred -u -z -n 1 -- {} + || true
    umount "$TMPD"
  fi
  if [ -d "$TMPD" ]; then rmdir -- "$TMPD"; fi
  rm -f -- "$LOCK"
  printf '  đã shred, umount và xóa %s\n' "$TMPD" >&2
}

gen_kek() {  # <thư mục keyring> <gid> <kek_id>
  local dir=$1 gid=$2 id=$3
  install -d -o root -g "$gid" -m 0750 "$dir"
  CREATED+=("$dir")
  openssl rand -hex 32 >"$dir/$id"
  if [ "$(wc -l <"$dir/$id")" != 1 ] || ! grep -Eqx '[0-9a-f]{64}' "$dir/$id"; then die "KEK $id sinh ra sai định dạng"; fi
  chown "root:$gid" "$dir/$id"
  chmod 0440 "$dir/$id"
  printf '%s\n' "$id" >"$dir/ACTIVE"
  chown "root:$gid" "$dir/ACTIVE"
  chmod 0440 "$dir/ACTIVE"
}

do_generate() {
  local env stamp app_id ops_id gid_app gid_ops kcv_app kcv_ops recipient spki now
  run_checks
  [ ${#PROBLEMS[@]} -eq 0 ] || die "preflight chưa đạt (${#PROBLEMS[@]} lỗi) — không sinh khóa nào"
  env=$(env_name) || die "không đọc được MG_ENV"
  gid_app=$(gid_of mg-sec-app)
  gid_ops=$(gid_of mg-sec-worker)
  now=$(date -u '+%Y-%m-%d %H:%M')
  stamp=$(date -u +%Y%m%d-%H%M)
  app_id=$env-app-$stamp
  ops_id=$env-ops-$stamp
  if [[ ! $app_id =~ $KEKID_RE ]] || [[ ! $ops_id =~ $KEKID_RE ]]; then die "kek_id sai định dạng"; fi
  trap gen_rollback EXIT

  # tmpfs riêng cho vật liệu tạm: không bao giờ chạm đĩa (swap tắt — đã kiểm); shred + umount ở cleanup
  install -d -o root -g root -m 0700 "$TMPD"
  mount -t tmpfs -o size=64m,mode=0700,uid=0,gid=0,nosuid,nodev,noatime mg-key-ceremony "$TMPD"
  [ "$(stat -f -c %T "$TMPD")" = tmpfs ] || die "$TMPD không phải tmpfs"
  stage_age

  gen_kek "$KR_APP" "$gid_app" "$app_id"
  gen_kek "$KR_OPS" "$gid_ops" "$ops_id"
  kcv_app=$(kcv_file "$KR_APP/$app_id")
  kcv_ops=$(kcv_file "$KR_OPS/$ops_id")
  [ "$kcv_app" != "$kcv_ops" ] || die "kek-app và kek-ops trùng khóa"

  if [ ! -d "$AGENT_DIR" ]; then
    install -d -o root -g root -m 0700 "$AGENT_DIR"
    CREATED+=("$AGENT_DIR")
  fi
  CREATED+=("$SIGN_KEY")
  openssl genpkey -algorithm ed25519 -out "$SIGN_KEY" 2>/dev/null
  chown root:root "$SIGN_KEY"
  chmod 0400 "$SIGN_KEY"
  if [ ! -d "$PUB" ]; then
    install -d -o root -g root -m 0755 "$PUB"
    CREATED+=("$PUB")
  fi
  CREATED+=("$SIGN_PUB")
  openssl pkey -in "$SIGN_KEY" -pubout -out "$SIGN_PUB" 2>/dev/null
  chmod 0644 "$SIGN_PUB"
  spki=$(grep -v '^-----' "$SIGN_PUB" | tr -d '\n')
  [[ $spki =~ ^MCowBQYDK2VwAyEA[A-Za-z0-9+/]{43}=$ ]] || die "khóa công khai ký manifest không phải Ed25519 SPKI"

  "$TMPD/bin/age-keygen" -o "$IDENTITY" 2>/dev/null
  chmod 0400 "$IDENTITY"
  recipient=$("$TMPD/bin/age-keygen" -y "$IDENTITY" 2>/dev/null)
  [[ $recipient =~ ^age1[$B32]{58}$ ]] || die "recipient khôi phục sai định dạng"
  CREATED+=("$RECIPIENT")
  printf '# MeshGuard %s — recipient của khóa khôi phục backup (đường DR, §17.1), P2-T04a %s UTC. Công khai.\n%s\n' \
    "$env" "$now" "$recipient" >"$RECIPIENT"
  chmod 0644 "$RECIPIENT"
  CREATED+=("$KCV_REC")
  printf '# MeshGuard %s — key check value của KEK, P2-T04a %s UTC: hex(HMAC-SHA256(KEK, "%s"))[:8]. Công khai.\nkek-app %s %s\nkek-ops %s %s\n' \
    "$env" "$now" "$KCV_LABEL" "$app_id" "$kcv_app" "$ops_id" "$kcv_ops" >"$KCV_REC"
  chmod 0644 "$KCV_REC"
  GEN_DONE=1
  trap - EXIT

  say "Đã tạo (khóa sinh ngay trên host; không giá trị bí mật nào được in):"
  printf '  %-60s %s\n' \
    "$KR_APP/" "$(mode_of "$KR_APP")" \
    "$KR_APP/$app_id" "$(mode_of "$KR_APP/$app_id")  KCV $kcv_app" \
    "$KR_APP/ACTIVE" "$(mode_of "$KR_APP/ACTIVE")  → $app_id" \
    "$KR_OPS/" "$(mode_of "$KR_OPS")" \
    "$KR_OPS/$ops_id" "$(mode_of "$KR_OPS/$ops_id")  KCV $kcv_ops" \
    "$KR_OPS/ACTIVE" "$(mode_of "$KR_OPS/ACTIVE")  → $ops_id" \
    "$SIGN_KEY" "$(mode_of "$SIGN_KEY")  Ed25519, PKCS#8 PEM" \
    "$SIGN_PUB" "$(mode_of "$SIGN_PUB")  công khai" \
    "$RECIPIENT" "$(mode_of "$RECIPIENT")  công khai" \
    "$KCV_REC" "$(mode_of "$KCV_REC")  công khai" \
    "$TMPD (tmpfs 64 MiB)" "$(mode_of "$TMPD")  identity khôi phục — chỉ tới bước cleanup"
  say "recipient khôi phục: $recipient"
  say "khóa công khai ký manifest (SPKI, base64): $spki"
  say "Hoàn tác — CHỈ khi chưa dịch vụ nào dùng các khóa này: $SELF undo --keys-never-used"
  say "Sau khi api/worker đã dùng khóa (P2-T16 trở đi): KHÔNG BAO GIỜ gỡ — mất KEK là mất mọi secret."
  say "Bước tiếp: chủ dự án chạy show-offline trong terminal của mình (ssh -t)."
}

# ---------------------------------------------------------------- show-offline (chỉ TTY)

clear_screen() { printf '\033[H\033[2J\033[3J'; }

wait_enter() {  # <lời nhắc>
  local _k
  printf '\n%s\n[Enter]> ' "$1"
  read_line _k -s
  printf '\n'
}

# print_groups <chuỗi> <số nhóm mỗi dòng>: in theo dòng đánh số, nhóm 4 ký tự (chỉ builtin, không tiến trình con).
print_groups() {
  local s=$1 per=$2 i j n=0 line
  for ((i = 0; i < ${#s}; i += 4 * per)); do
    n=$((n + 1))
    line=""
    for ((j = i; j < i + 4 * per && j < ${#s}; j += 4)); do line+="${s:j:4} "; done
    printf '      dòng %d:  %s\n' "$n" "${line% }"
  done
}

show_kek() {  # <số mục> <tên keyring> <thư mục> <vai trò>
  local id hex
  IFS= read -r id <"$3/ACTIVE"
  IFS= read -r hex <"$3/$id"
  clear_screen
  printf '=== MeshGuard %s — BẢN SAO OFFLINE — mục %s/3: KEK "%s" ===\n\n' "$ENV" "$1" "$2"
  printf '  dùng cho : %s\n' "$4"
  printf '  kek_id   : %s   (ACTIVE)\n' "$id"
  printf '  giá trị  : 64 ký tự hex = 4 dòng × 4 nhóm\n'
  print_groups "$hex" 4
  hex=""
  printf '  KCV      : %s\n' "$(kcv_file "$3/$id")"
  wait_enter "Chép mục này lên CẢ HAI bản (kek_id, 4 dòng giá trị, KCV), soát lại từng nhóm rồi nhấn Enter — màn hình sẽ bị xóa."
}

do_show_offline() {
  local idl data
  require_tty
  require_root
  lock_in_progress
  ENV=$(env_name) || die "không đọc được MG_ENV"
  trap 'clear_screen; stty echo 2>/dev/null || true' EXIT
  clear_screen
  printf '=== MeshGuard %s — BẢN SAO OFFLINE CỦA KHÓA (P2-T04a) ===\n\n' "$ENV"
  printf '  Chép TAY lên 2 tờ giấy riêng, ghi "Bản 1"/"Bản 2", ngày và môi trường %s.\n' "$ENV"
  printf '  KHÔNG chụp ảnh, KHÔNG gõ vào máy khác, KHÔNG lưu cloud, ghi chú hay trình quản lý mật khẩu.\n'
  printf '  Mỗi mục một màn hình; Enter xóa màn hình rồi sang mục kế; Ctrl-C dừng (màn hình được xóa).\n'
  printf '  Ba mục: KEK kek-app, KEK kek-ops, khóa khôi phục backup (age).\n'
  wait_enter "Sẵn sàng (giấy, bút, không ai nhìn màn hình)? Nhấn Enter để hiện mục 1/3."
  show_kek 1 kek-app "$KR_APP" "api + worker — bọc DEK của tenant và DEK platform"
  show_kek 2 kek-ops "$KR_OPS" "chỉ worker — bọc DEK platform_ops"
  idl=$(grep -m1 '^AGE-SECRET-KEY-1' "$IDENTITY")
  data=${idl#AGE-SECRET-KEY-1}
  idl=""
  clear_screen
  printf '=== MeshGuard %s — BẢN SAO OFFLINE — mục 3/3: khóa khôi phục backup (age X25519) ===\n\n' "$ENV"
  printf '  dùng cho : giải mã backup khi mất host (đường DR — §17.1)\n'
  printf '  identity : AGE-SECRET-KEY-1  rồi 58 ký tự = 3 dòng (5 + 5 + 4½ nhóm)\n'
  print_groups "$data" 5
  data=""
  printf '  (bech32: không có 1, B, I, O — viết rõ 0/Q/D, 5/S, 2/Z, 6/G, U/V)\n'
  printf '  recipient: %s  (công khai, đã lưu — không cần chép)\n' "$(grep -m1 '^age1' "$RECIPIENT")"
  wait_enter "Chép mục này lên CẢ HAI bản rồi nhấn Enter — màn hình và lịch sử cuộn sẽ bị xóa."
  clear_screen
  trap - EXIT
  printf '[show-offline] Xong. Thay đổi trên host: không có. Màn hình đã xóa.\n'
  printf '[show-offline] Bước tiếp: verify-offline --copy 1, rồi --copy 2 (nhập lại từ giấy, không hiện chữ).\n'
}

# ---------------------------------------------------------------- verify-offline (chỉ TTY)

TYPED=""      # dòng vừa nhập (đã chuẩn hóa) — biến toàn cục, không qua tiến trình con
MISMATCH=""   # số thứ tự các nhóm 4 ký tự khác nhau
RECOVERED=""  # giá trị ghép từ các dòng đã nhập
RESULT_LINE=""

# ask_secret_line <nhãn> <độ dài> <bộ ký tự> <lower|upper> <mô tả>: đọc một dòng không hiện chữ (echo của terminal tắt
# suốt bước verify-offline — kể cả phím gõ trước lời nhắc), bỏ dấu cách và gạch nối, đổi hoa/thường; hỏi lại tới khi
# đúng độ dài và bộ ký tự.
ask_secret_line() {
  local line
  while :; do
    printf '%s> ' "$1"
    read_line line -s
    printf '\n'
    line=${line//[[:space:]-]/}
    if [ "$4" = lower ]; then line=${line,,}; else line=${line^^}; fi
    if [ ${#line} -eq "$2" ] && [[ $line =~ ^[$3]+$ ]]; then
      TYPED=$line
      return 0
    fi
    printf '      sai định dạng: cần %d ký tự (%s) — gõ lại dòng này\n' "$2" "$5"
  done
}

# compare_groups <nhập> <chuẩn>: MISMATCH = các nhóm 4 ký tự khác nhau ("" nếu khớp).
compare_groups() {
  local i n=0
  MISMATCH=""
  for ((i = 0; i < ${#2}; i += 4)); do
    n=$((n + 1))
    [ "${1:i:4}" = "${2:i:4}" ] || MISMATCH+="$n "
  done
  MISMATCH=${MISMATCH% }
}

# verify_lines <nhãn> <chuỗi chuẩn> <ký tự mỗi dòng> <bộ ký tự> <lower|upper> <mô tả>: nhập lại từng dòng (tối đa 3
# lần mỗi dòng), báo khớp hoặc số nhóm sai; ghép vào RECOVERED; VERIFY_OK=1 nếu mọi dòng khớp.
VERIFY_OK=0
verify_lines() {
  local want=$2 per=$3 i n=0 tries len
  RECOVERED=""
  VERIFY_OK=1
  for ((i = 0; i < ${#want}; i += per)); do
    n=$((n + 1))
    len=$((${#want} - i < per ? ${#want} - i : per))
    for tries in 1 2 3; do
      ask_secret_line "  [$1] dòng $n" "$len" "$4" "$5" "$6"
      compare_groups "$TYPED" "${want:i:len}"
      if [ -z "$MISMATCH" ]; then printf '      dòng %d: khớp\n' "$n"; break; fi
      printf '      dòng %d: KHÔNG khớp ở nhóm %s (lần %d/3) — soát lại bản giấy\n' "$n" "$MISMATCH" "$tries"
    done
    [ -z "$MISMATCH" ] || VERIFY_OK=0
    RECOVERED+=$TYPED
    TYPED=""
  done
}

ask_plain() {  # <nhãn>: đọc một giá trị KHÔNG bí mật vào TYPED; echo tắt suốt bước nên script tự in lại giá trị
  local v
  printf '%s> ' "$1"
  read_line v
  TYPED=${v//[[:space:]]/}
  printf '%s\n' "$TYPED"
}

verify_kek() {  # <bản> <keyring> <thư mục live> <gid>; kết quả vào RESULT_LINE
  local copy=$1 name=$2 dir=$3 gid=$4 id hex want_kcv got_kcv typed_id ok=PASS rec tries
  IFS= read -r id <"$dir/ACTIVE"
  want_kcv=$(kcv_file "$dir/$id")
  printf '\n--- %s ---\n' "$name"
  for tries in 1 2 3; do
    ask_plain "  [$name] kek_id"
    if [[ ! $TYPED =~ $KEKID_RE ]]; then printf '      kek_id sai định dạng (lần %d/3)\n' "$tries"; continue; fi
    if [ "$TYPED" = "$id" ]; then break; fi
    printf '      kek_id KHÔNG khớp keyring đang chạy (lần %d/3)\n' "$tries"
  done
  typed_id=$TYPED
  [ "$typed_id" = "$id" ] || ok=FAIL
  [[ $typed_id =~ $KEKID_RE ]] || typed_id=invalid-kek-id
  IFS= read -r hex <"$dir/$id"
  verify_lines "$name" "$hex" 16 0-9a-f lower "hex 0-9 a-f"
  hex=""
  [ "$VERIFY_OK" = 1 ] || ok=FAIL
  got_kcv=$(printf '%s' "$RECOVERED" | kcv_stdin)
  ask_plain "  [$name] KCV ghi trên bản sao"
  if [ "${TYPED,,}" != "$got_kcv" ]; then
    printf '      KCV trên giấy (%s) khác KCV của giá trị vừa nhập (%s)\n' "${TYPED,,}" "$got_kcv"
    ok=FAIL
  fi
  [ "$got_kcv" = "$want_kcv" ] || ok=FAIL
  rec=$TMPD/recovered-$copy/$name
  shred_tree "$rec"
  install -d -o root -g "$gid" -m 0750 "$rec"
  printf '%s\n' "$RECOVERED" >"$rec/$typed_id"
  RECOVERED=""
  printf '%s\n' "$typed_id" >"$rec/ACTIVE"
  chown "root:$gid" "$rec/$typed_id" "$rec/ACTIVE"
  chmod 0440 "$rec/$typed_id" "$rec/ACTIVE"
  printf '  => %s: %s (kek_id %s, KCV đang chạy %s, KCV bản nhập lại %s)\n' "$name" "$ok" "$id" "$want_kcv" "$got_kcv"
  RESULT_LINE="$name $ok kek_id=$id kcv_live=$want_kcv kcv_copy=$got_kcv"
}

verify_identity() {  # <bản>; kết quả vào RESULT_LINE
  local copy=$1 idl data ok=PASS recipient got f
  idl=$(grep -m1 '^AGE-SECRET-KEY-1' "$IDENTITY")
  data=${idl#AGE-SECRET-KEY-1}
  idl=""
  recipient=$(grep -m1 '^age1' "$RECIPIENT")
  printf '\n--- khóa khôi phục backup (age) — chỉ gõ 3 dòng nhóm, KHÔNG gõ "AGE-SECRET-KEY-1" ---\n'
  verify_lines "khôi phục" "$data" 20 "${B32^^}" upper "bech32: chữ hoa và số, không có 1 B I O"
  data=""
  [ "$VERIFY_OK" = 1 ] || ok=FAIL
  f=$TMPD/recovered-$copy/recovery.agekey
  if [ -e "$f" ]; then shred -u -z -n 1 -- "$f"; fi
  printf 'AGE-SECRET-KEY-1%s\n' "$RECOVERED" >"$f"
  RECOVERED=""
  chmod 0400 "$f"
  if got=$("$TMPD/bin/age-keygen" -y "$f" 2>/dev/null) && [ "$got" = "$recipient" ]; then
    printf '  => khóa khôi phục: recipient suy ra từ bản nhập lại khớp recipient đã lưu (%s)\n' "$recipient"
  else
    printf '  => khóa khôi phục: KHÔNG suy ra được recipient đã lưu (sai ký tự hoặc mã kiểm bech32)\n'
    ok=FAIL
  fi
  printf '  => khóa khôi phục: %s\n' "$ok"
  RESULT_LINE="recovery $ok recipient=$recipient"
}

do_verify_offline() {
  local copy="" lines=() verdict=PASS l next
  if [ "${1:-}" = --copy ]; then copy=${2:-}; fi
  [[ $copy =~ ^[12]$ ]] || { printf 'cú pháp: %s verify-offline --copy 1|2\n' "$SELF" >&2; exit 2; }
  require_tty
  require_root
  lock_in_progress
  stage_age
  ENV=$(env_name) || die "không đọc được MG_ENV"
  trap 'stty echo 2>/dev/null || true' EXIT
  stty -echo || die "không tắt được echo của terminal"   # tắt suốt bước: phím gõ trước lời nhắc cũng không hiện
  install -d -o root -g root -m 0700 "$TMPD/recovered-$copy"
  rm -f -- "$TMPD/verify-$copy.result" "$TMPD/drill-$copy.result"
  clear_screen
  printf '=== MeshGuard %s — KIỂM BẢN SAO SỐ %s (P2-T04a) ===\n' "$ENV" "$copy"
  printf '  Đọc từ GIẤY, gõ lại từng dòng. Giá trị bí mật KHÔNG hiện khi gõ; dấu cách và gạch nối được bỏ qua,\n'
  printf '  hoa/thường như nhau. Sai ⇒ báo số nhóm để soát bản giấy (tối đa 3 lần mỗi dòng).\n'
  verify_kek "$copy" kek-app "$KR_APP" "$(gid_of mg-sec-app)"
  lines+=("$RESULT_LINE")
  verify_kek "$copy" kek-ops "$KR_OPS" "$(gid_of mg-sec-worker)"
  lines+=("$RESULT_LINE")
  verify_identity "$copy"
  lines+=("$RESULT_LINE")
  for l in "${lines[@]}"; do [[ $l == *" PASS "* ]] || verdict=FAIL; done
  { printf '%s\n' "${lines[@]}"; printf 'RESULT %s\n' "$verdict"; } >"$TMPD/verify-$copy.result"
  stty echo
  printf '\n[verify-offline] Bản %s: %s\n' "$copy" "$verdict"
  printf '[verify-offline] Thay đổi: bản nhập lại lưu trên tmpfs %s (bị hủy ở cleanup; chạy lại bước này để ghi đè).\n' "$TMPD/recovered-$copy"
  if [ "$verdict" != PASS ]; then
    printf '[verify-offline] Sửa bản giấy (show-offline để xem lại) rồi chạy lại verify-offline --copy %s.\n' "$copy"
    exit 1
  fi
  if [ "$copy" = 1 ]; then next="verify-offline --copy 2"; else next="người điều phối chạy drill"; fi
  printf '[verify-offline] Bước tiếp: %s\n' "$next"
}

# ---------------------------------------------------------------- drill

IMAGE=""
GID_APP=""
GID_OPS=""

drill_container() {  # <thư mục chứa kek-app/ và kek-ops/ khôi phục> [đối số thêm cho kek-drill]
  local rec=$1
  shift
  run_worker "mgkc-drill-$$-$RANDOM" --rm --pull never --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --user 65532:65532 --group-add "$GID_APP" --group-add "$GID_OPS" \
    --pids-limit 32 --memory 64m --log-driver none \
    --mount "type=bind,src=$KR_APP,dst=/live/kek-app,readonly" \
    --mount "type=bind,src=$KR_OPS,dst=/live/kek-ops,readonly" \
    --mount "type=bind,src=$rec/kek-app,dst=/recovered/kek-app,readonly" \
    --mount "type=bind,src=$rec/kek-ops,dst=/recovered/kek-ops,readonly" \
    "$IMAGE" kek-drill --live /live --recovered /recovered "$@"
}

DRILL_VERDICT=FAIL
drill_copy() {  # <bản>; kết quả vào DRILL_VERDICT (lỗi bất ngờ ⇒ dừng hẳn, không bao giờ "đạt")
  local copy=$1 rec=$TMPD/recovered-$1 neg=$TMPD/negative out rc verdict=PASS id hex d
  DRILL_VERDICT=FAIL
  if [ ! -s "$rec/recovery.agekey" ] || [ ! -d "$rec/kek-app" ] || [ ! -d "$rec/kek-ops" ]; then
    say "bản $copy: chưa có bản nhập lại (verify-offline --copy $copy) — FAIL"
    return 0
  fi
  say "bản $copy — kek-drill trong container (--network none, rootfs và mount chỉ-đọc, user 65532, nhóm $GID_APP+$GID_OPS):"
  rc=0
  out=$(drill_container "$rec" 2>&1) || rc=$?
  printf '%s\n' "$out" | sed 's/^/    /'
  if [ "$rc" != 0 ] || [[ $out != *"kek-drill: PASS"* ]]; then verdict=FAIL; fi

  # đối chứng âm: bản khôi phục sai 1 ký tự hex ⇒ kek-drill phải FAIL (drill không "luôn đạt")
  shred_tree "$neg"
  cp -a -- "$rec" "$neg"
  IFS= read -r id <"$neg/kek-app/ACTIVE"
  IFS= read -r hex <"$neg/kek-app/$id"
  if [ "${hex:63:1}" = 0 ]; then hex=${hex:0:63}1; else hex=${hex:0:63}0; fi
  chmod 0600 "$neg/kek-app/$id"
  printf '%s\n' "$hex" >"$neg/kek-app/$id"
  hex=""
  chmod 0440 "$neg/kek-app/$id"
  rc=0
  out=$(drill_container "$neg" --keyring kek-app 2>&1) || rc=$?
  shred_tree "$neg"
  if [ "$rc" = 1 ] && [[ $out == *"KCV differs"* ]]; then
    say "bản $copy — đối chứng âm: khóa sai 1 ký tự ⇒ kek-drill FAIL như mong đợi"
  else
    say "bản $copy — đối chứng âm KHÔNG đạt (exit $rc): drill không phát hiện khóa sai"
    verdict=FAIL
  fi

  # khóa khôi phục (age): mã hóa thử tới recipient đã lưu, giải mã bằng identity nhập lại; identity khác ⇒ thất bại
  d=$TMPD/drill-age
  shred_tree "$d"
  install -d -m 0700 "$d"
  head -c 4096 /dev/urandom >"$d/msg"
  if "$TMPD/bin/age" -R "$RECIPIENT" -o "$d/msg.age" "$d/msg" 2>/dev/null &&
    "$TMPD/bin/age" -d -i "$rec/recovery.agekey" -o "$d/out" "$d/msg.age" 2>/dev/null &&
    cmp -s "$d/msg" "$d/out"; then
    say "bản $copy — khóa khôi phục: giải mã được tin thử mã hóa tới recipient đã lưu (4096 byte, khớp)"
  else
    say "bản $copy — khóa khôi phục: KHÔNG giải mã được tin thử"
    verdict=FAIL
  fi
  "$TMPD/bin/age-keygen" -o "$d/other.agekey" 2>/dev/null
  if "$TMPD/bin/age" -d -i "$d/other.agekey" -o "$d/out2" "$d/msg.age" 2>/dev/null; then
    say "bản $copy — đối chứng âm KHÔNG đạt: một identity khác cũng giải mã được"
    verdict=FAIL
  else
    say "bản $copy — đối chứng âm: identity khác không giải mã được (đúng)"
  fi
  shred_tree "$d"
  printf 'RESULT %s\n' "$verdict" >"$TMPD/drill-$copy.result"
  say "bản $copy — DRILL: $verdict"
  DRILL_VERDICT=$verdict
}

do_drill() {
  local copies=() c fail=0
  case ${1:-} in
    --copy) [[ ${2:-} =~ ^[12]$ ]] || { printf 'cú pháp: %s drill [--copy 1|2]\n' "$SELF" >&2; exit 2; }; copies=("$2") ;;
    '') for c in 1 2; do if [ -d "$TMPD/recovered-$c" ]; then copies+=("$c"); fi; done ;;
    *) printf 'cú pháp: %s drill [--copy 1|2]\n' "$SELF" >&2; exit 2 ;;
  esac
  require_root
  lock_in_progress
  stage_age
  [ ${#copies[@]} -gt 0 ] || die "chưa có bản nhập lại nào — chủ dự án chạy verify-offline trước"
  IMAGE=$(worker_image) || die "chưa có image worker theo digest ([images.mg-worker] trong versions.lock)"
  GID_APP=$(gid_of mg-sec-app)
  GID_OPS=$(gid_of mg-sec-worker)
  for c in "${copies[@]}"; do
    drill_copy "$c"
    [ "$DRILL_VERDICT" = PASS ] || fail=1
  done
  say "Thay đổi: không có trên đĩa (container --rm --log-driver none; file thử trên tmpfs đã shred)."
  if [ "$fail" = 0 ]; then say "KẾT QUẢ: PASS"; else say "KẾT QUẢ: FAIL"; exit 1; fi
}

# ---------------------------------------------------------------- cleanup, status, undo

result_of() { if [ -f "$1" ]; then sed -n 's/^RESULT //p' "$1"; fi; }

do_cleanup() {
  local abort=0 n
  case ${1:-} in --abort) abort=1 ;; '') ;; *) printf 'cú pháp: %s cleanup [--abort]\n' "$SELF" >&2; exit 2 ;; esac
  require_root
  take_lock
  if ! mountpoint -q "$TMPD"; then
    if [ -d "$TMPD" ]; then rmdir -- "$TMPD"; fi
    rm -f -- "$LOCK"
    say "không có tmpfs của nghi thức tại $TMPD — không có gì để dọn"
    return 0
  fi
  if [ "$abort" = 0 ]; then
    if [ "$(result_of "$TMPD/verify-1.result")" != PASS ] || [ "$(result_of "$TMPD/verify-2.result")" != PASS ]; then
      die "chưa đủ: cần verify-offline PASS cho CẢ bản 1 và bản 2 (identity khôi phục mất vĩnh viễn sau cleanup). Bỏ dở nghi thức: cleanup --abort"
    fi
    if [ "$(result_of "$TMPD/drill-1.result")" != PASS ] && [ "$(result_of "$TMPD/drill-2.result")" != PASS ]; then
      die "chưa có drill PASS. Bỏ dở nghi thức: cleanup --abort"
    fi
  fi
  n=$(find "$TMPD" -type f | wc -l)
  find "$TMPD" -type f -exec shred -u -z -n 1 -- {} +
  umount "$TMPD"
  rmdir -- "$TMPD"
  rm -f -- "$LOCK"
  say "Đã shred $n file trên tmpfs (identity khôi phục, bản nhập lại, bản chép age), umount và xóa $TMPD."
  if [ "$abort" = 1 ]; then
    say "Đã bỏ dở: identity khôi phục đã hủy (chưa backup nào mã hóa tới recipient của nó); KEK, khóa ký manifest và file công khai vẫn còn."
    say "Hoàn tác: không thể. Làm lại từ đầu: $SELF undo --keys-never-used (hủy luôn mọi bản giấy đã chép), rồi preflight."
  else
    say "Hoàn tác: KHÔNG thể — identity khôi phục giờ chỉ còn trên 2 bản giấy đã kiểm; KEK vẫn ở $SECRETS (keyring đang dùng)."
    say "Bước tiếp (người điều phối): status → ghi MG_BACKUP_* vào file tham số môi trường, kek_id + KCV vào bằng chứng."
  fi
}

do_status() {
  local name dir id f c spki recipient env v d
  require_root
  env=$(env_name) || env='?'
  say "Môi trường: $env; gốc: ${ROOT:-/}"
  for name in kek-app kek-ops; do
    dir=$SECRETS/$name
    if [ ! -d "$dir" ]; then say "$name: chưa có"; continue; fi
    id='?'
    if [ -f "$dir/ACTIVE" ]; then IFS= read -r id <"$dir/ACTIVE"; fi
    say "$name: $dir ($(mode_of "$dir")), ACTIVE=$id"
    for f in "$dir"/*; do
      if [ ! -f "$f" ] || [ "$(basename -- "$f")" = ACTIVE ]; then continue; fi
      say "  kek_id=$(basename -- "$f") ($(mode_of "$f")) KCV $(kcv_file "$f")"
    done
  done
  if [ -f "$SIGN_KEY" ]; then say "khóa ký manifest: $SIGN_KEY ($(mode_of "$SIGN_KEY"))"; else say "khóa ký manifest: chưa có"; fi
  recipient=$(grep -m1 '^age1' "$RECIPIENT" 2>/dev/null || true)
  spki=$(grep -v '^-----' "$SIGN_PUB" 2>/dev/null | tr -d '\n' || true)
  if in_progress; then
    say "nghi thức đang dở: tmpfs $TMPD còn identity khôi phục"
    for c in 1 2; do
      v=$(result_of "$TMPD/verify-$c.result")
      d=$(result_of "$TMPD/drill-$c.result")
      say "  bản $c: verify-offline ${v:-chưa chạy}, drill ${d:-chưa chạy}"
    done
  else
    say "không có nghi thức đang dở (không có tmpfs $TMPD)"
  fi
  if [ -n "$recipient" ] && [ -n "$spki" ]; then
    say "Giá trị công khai cho $(basename -- "$ENV_FILE") (bằng chứng: kek_id + KCV ở trên):"
    printf 'MG_BACKUP_RECOVERY_RECIPIENT=%s\nMG_BACKUP_MANIFEST_PUBKEY=%s\n' "$recipient" "$spki"
  fi
  say "Thay đổi trên host: không có."
}

do_undo() {
  local used p
  [ "${1:-}" = --keys-never-used ] || { printf 'cú pháp: %s undo --keys-never-used  (xác nhận CHƯA dịch vụ nào dùng các khóa)\n' "$SELF" >&2; exit 2; }
  require_root
  take_lock
  used=$(docker ps -aq | xargs -r docker inspect -f '{{.Name}}{{range .Mounts}} {{.Source}}{{end}}' |
    grep -F -e "$KR_APP" -e "$KR_OPS" -e "$AGENT_DIR" || true)
  [ -z "$used" ] || die "có container đang/đã mount khóa — KHÔNG gỡ (khóa đã được dùng): $used"
  for p in "$KR_APP" "$KR_OPS" "$SIGN_KEY" "$SIGN_PUB" "$RECIPIENT" "$KCV_REC"; do
    if [ -d "$p" ]; then shred_tree "$p"; say "đã gỡ $p"; elif [ -e "$p" ]; then shred -u -z -n 1 -- "$p"; say "đã gỡ $p"; fi
  done
  if [ -d "$AGENT_DIR" ] && [ -z "$(ls -A -- "$AGENT_DIR")" ]; then rmdir -- "$AGENT_DIR"; say "đã gỡ $AGENT_DIR"; fi
  if [ -d "$PUB" ] && [ -z "$(ls -A -- "$PUB")" ]; then rmdir -- "$PUB"; say "đã gỡ $PUB"; fi
  if mountpoint -q "$TMPD"; then
    find "$TMPD" -type f -exec shred -u -z -n 1 -- {} +
    umount "$TMPD"
    say "đã shred tmpfs và umount $TMPD"
  fi
  if [ -d "$TMPD" ]; then rmdir -- "$TMPD"; fi
  rm -f -- "$LOCK"
  say "Xong. Bản giấy của lần sinh khóa này vô hiệu — hủy chúng. Làm lại: preflight → generate."
}

# ---------------------------------------------------------------- dispatch

case $STEP in
  preflight) require_root; do_preflight ;;
  generate) require_root; take_lock; do_generate ;;
  show-offline) do_show_offline ;;
  verify-offline) do_verify_offline "$@" ;;
  drill) do_drill "$@" ;;
  cleanup) do_cleanup "$@" ;;
  status) do_status ;;
  undo) do_undo "$@" ;;
  help | -h | --help) usage ;;
  *) usage >&2; exit 2 ;;
esac
