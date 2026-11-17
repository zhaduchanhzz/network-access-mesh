#!/bin/bash
# P2-T03a / P2-T05b — diễn tập backup → restore với khóa age DÙNG MỘT LẦN, trên máy build/CI. KHÔNG chạy trên host
# staging/production: dựng cụm PostgreSQL, Keycloak, volume và network thử riêng (tiền tố $PREFIX) và dọn sạch ở cuối,
# kể cả khi lỗi. Chạy đúng image backup và compose mg-backup đã render (tools/render_backup.py) — chỉ ghép thêm
# tests/backup/compose.backup.test.yaml (đổi tên network/volume và đường dẫn sang thư mục làm việc).
#
#   BACKUP_IMAGE=<image ID hoặc name@sha256> AGE_DIR=<thư mục ra của build-age.sh> bash tests/backup/drill.sh
#
#   1. PostgreSQL: DB nguồn migrate như triển khai thật + fixture mọi bảng (internal/store TestBackupDrillSource);
#      pg-backup chạy như dịch vụ (lịch riêng — chưa có status ⇒ lượt bù ngay) và theo trigger trước migration
#      (`run --rm pg-backup once --label pre-migration`); giải mã bằng identity dùng một lần, plaintext chỉ đi qua pipe →
#      restore vào cụm tạm (globals + pg_restore --create) ⇒ số hàng VÀ băm nội dung từng bảng (gồm partition, schema
#      river) khớp; catalog (role, membership, ACL, RLS, policy, hàm, trigger) khớp; RLS còn hiệu lực; bước runbook
#      thu hồi mọi session.
#   2. IdP: Keycloak (image mg-idp pin digest) + idp-db; tạo user thử; idp-backup lúc Keycloak đang chạy, rồi lúc đã
#      dừng; restore vào idp-db mới ⇒ số hàng/băm khớp; Keycloak khởi động trên DB đã restore, realm/user/discovery
#      như trước (kc_drill.py).
#   3. Edge: volume ACME giả lập (owner 10001, mode 0600/0644/0700, symlink, file 1 MiB) mount CHỈ-ĐỌC; edge-backup;
#      giải nén vào volume mới ⇒ loại, mode, owner, kích thước, mtime, đích symlink, sha256 từng file khớp.
#   4. Âm tính: identity sai không giải mã được; recipient trống/sai/lệch file ⇒ exit 2 và thư mục đích không đổi;
#      mật khẩu DB sai ⇒ exit 1, không giữ file nào, status ghi lỗi; mg_backup không ghi được; edge-backup không đọc
#      được một file ⇒ thất bại, không giữ gì; ghi vào volume ACME bị từ chối; pg_dumpall thiếu /bin/sh thì không chạy
#      (lý do duy nhất image có dash).
#
# Biến: PREFIX (mgbkdrill), WORK (/tmp/$PREFIX), NET_BASE (10.248: hai octet đầu của các subnet thử — chọn dải chưa
# dùng trên máy), IDP_IMAGE (mặc định versions.lock [images.mg-idp]), GO_CACHE (volume Docker sẵn có làm cache module
# Go; mặc định tạo $PREFIX-gomod và xóa khi dọn). Cần: sudo docker + compose, python3. Khóa và secret sinh tại chỗ
# (0600/0440), không bao giờ in ra; identity bị shred khi dọn.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PREFIX=${PREFIX:-mgbkdrill}
W=${WORK:-/tmp/$PREFIX}
NET_BASE=${NET_BASE:-10.248}
[[ $NET_BASE =~ ^10\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$ ]] || { echo "NET_BASE phải có dạng 10.<0-255>"; exit 2; }
: "${BACKUP_IMAGE:?BACKUP_IMAGE (image build từ infrastructure/docker/backup) là bắt buộc}"
: "${AGE_DIR:?AGE_DIR (thư mục ra của infrastructure/host/key-ceremony/build-age.sh) là bắt buộc}"
D="sudo docker"
DOMAIN=$PREFIX.test
ENVFILE=$ROOT/infrastructure/environments/staging/staging.env

lock_get() {
  python3 -I -c 'import sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))
for part in sys.argv[2].split("."):
    d = d.get(part) if isinstance(d, dict) else None
v = d.get(sys.argv[3]) if isinstance(d, dict) else None
print("" if v is None else v)' "$ROOT/versions.lock" "$1" "$2"
}
pinned() { echo "$(lock_get "images.$1" image)@$(lock_get "images.$1" index)"; }
PG_IMAGE=$(pinned postgres)
GO_IMAGE=$(pinned golang)
ALPINE=$(pinned alpine)
IDP_IMAGE=${IDP_IMAGE:-$(pinned mg-idp)}
GO_CACHE=${GO_CACHE:-}
GO_CACHE_OWN=0
AGE=$AGE_DIR/age
KEYGEN=$AGE_DIR/age-keygen

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "PASS $*"; }
ko() { fail=$((fail + 1)); echo "FAIL $*"; }
expect() { local name=$1; shift; if "$@"; then ok "$name"; else ko "$name"; fi; }
say() { printf '\n=== %s\n' "$*"; }
bk() {
  sudo env MGT_WORK="$W" MGT_PREFIX="$PREFIX" docker compose -p "$PREFIX-backup" \
    -f "$W/core/compose.backup.yaml" -f "$ROOT/tests/backup/compose.backup.test.yaml" "$@"
}
idp() {
  sudo env MGT_WORK="$W" MGT_PREFIX="$PREFIX" docker compose -p "$PREFIX-idp" \
    -f "$W/core/compose.idp.yaml" -f "$ROOT/tests/idp/compose.idp.test.yaml" "$@"
}
psql_in() { local c=$1; shift; $D exec -i "$c" psql -X -q -v ON_ERROR_STOP=1 -U postgres "$@"; }
wait_pg() {
  for _ in $(seq 1 90); do $D exec "$1" pg_isready -q -h 127.0.0.1 -U postgres 2>/dev/null && return 0; sleep 1; done
  echo "$1 không sẵn sàng"; return 1
}
decrypt() { sudo cat "$1" | "$AGE" --decrypt --identity "$W/keys/identity"; }   # plaintext chỉ ra stdout (pipe)
latest() { sudo find "$W/backups/$1" -maxdepth 1 -name "*-$2.manifest.json" -printf '%f\n' | sort | tail -n1 | sed 's/\.manifest\.json$//'; }
artifacts() { sudo find "$W/backups/$1" -maxdepth 1 \( -name '*.age' -o -name '*.manifest.json' \) -printf '%f %s\n' | sort; }
status_field() { sudo cat "$W/backups/$1/status.json" | python3 -I -c 'import json, sys
s = json.load(sys.stdin)
for k in sys.argv[1].split("."):
    s = s.get(k) if isinstance(s, dict) else None
print(s)' "$2"; }

# Số hàng + băm nội dung của mọi bảng thường và bảng partition (cha và từng partition), đọc bằng superuser.
COUNTS_SQL="SELECT n.nspname || '.' || c.relname || '|' || c.relkind::text || '|' || x.c || '|' || x.h
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace,
  LATERAL (SELECT (xpath('/row/c/text()', q))[1]::text AS c, (xpath('/row/h/text()', q))[1]::text AS h
             FROM query_to_xml(format('SELECT count(*) AS c, md5(COALESCE(string_agg(t::text, E''\n'' ORDER BY t::text), '''')) AS h FROM %I.%I t',
                                      n.nspname, c.relname), false, true, '') AS q) x
 WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') ORDER BY 1"
# Catalog: role, membership, ACL của DB/schema/quan hệ/hàm, RLS, policy, trigger. ACL bằng đúng mặc định của owner
# (acldefault — vd. owner=arwdDxtm/owner sau REVOKE ALL FROM PUBLIC) được pg_dump bỏ qua và restore thành NULL: tương
# đương về quyền, nên chuẩn hóa thành rỗng ở cả hai phía.
CATALOG_SQL="SELECT * FROM (
 SELECT 'role|' || rolname || '|' || rolsuper || rolinherit || rolcreaterole || rolcreatedb || rolcanlogin || rolreplication
        || rolbypassrls || '|' || COALESCE(array_to_string(rolconfig, ','), '') AS l
   FROM pg_roles WHERE rolname LIKE 'mg\\_%' OR rolname IN ('keycloak', 'idp_backup')
 UNION ALL
 SELECT 'member|' || m.rolname || '<' || r.rolname || '|' || am.admin_option || am.inherit_option || am.set_option
   FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.roleid JOIN pg_roles m ON m.oid = am.member
  WHERE m.rolname LIKE 'mg\\_%' OR r.rolname LIKE 'mg\\_%' OR m.rolname = 'idp_backup'
 UNION ALL
 SELECT 'db|' || datname || '|' || pg_get_userbyid(datdba) || '|'
        || COALESCE((SELECT string_agg(a::text, ',' ORDER BY a::text) FROM unnest(datacl) a
                    WHERE datacl IS DISTINCT FROM acldefault('d', datdba)), '')
   FROM pg_database WHERE datname = current_database()
 UNION ALL
 SELECT 'schema|' || nspname || '|' || pg_get_userbyid(nspowner) || '|'
        || COALESCE((SELECT string_agg(a::text, ',' ORDER BY a::text) FROM unnest(nspacl) a
                    WHERE nspacl IS DISTINCT FROM acldefault('n', nspowner)), '')
   FROM pg_namespace WHERE nspname NOT LIKE 'pg\\_%' AND nspname <> 'information_schema'
 UNION ALL
 SELECT 'rel|' || n.nspname || '.' || c.relname || '|' || c.relkind::text || '|' || pg_get_userbyid(c.relowner) || '|'
        || c.relrowsecurity || c.relforcerowsecurity || '|'
        || COALESCE((SELECT string_agg(a::text, ',' ORDER BY a::text) FROM unnest(c.relacl) a
                    WHERE c.relacl IS DISTINCT FROM CASE WHEN c.relkind = 'S' THEN acldefault('s', c.relowner) ELSE acldefault('r', c.relowner) END), '')
   FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
 UNION ALL
 SELECT 'policy|' || schemaname || '.' || tablename || '|' || policyname || '|' || permissive || '|'
        || array_to_string(roles, ',') || '|' || cmd || '|' || COALESCE(qual, '') || '|' || COALESCE(with_check, '')
   FROM pg_policies
 UNION ALL
 SELECT 'func|' || p.oid::regprocedure || '|' || pg_get_userbyid(p.proowner) || '|' || p.prosecdef || '|'
        || COALESCE((SELECT string_agg(a::text, ',' ORDER BY a::text) FROM unnest(p.proacl) a
                    WHERE p.proacl IS DISTINCT FROM acldefault('f', p.proowner)), '')
   FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
 UNION ALL
 SELECT 'trigger|' || tgrelid::regclass || '|' || tgname || '|' || tgenabled::text FROM pg_trigger WHERE NOT tgisinternal
) s ORDER BY 1"

compare() {   # <tên> <file nguồn> <file sau restore>
  if cmp -s "$2" "$3"; then ok "$1 khớp ($(wc -l < "$2") dòng)"; else ko "$1 lệch"; diff "$2" "$3" | head -20 || true; fi
}

# ------------------------------------------------------------------------------------------------ chuẩn bị
setup() {
  say "chuẩn bị $W — khóa age và secret dùng một lần (không in ra)"
  for b in age age-keygen; do
    want=$(lock_get sources.age "${b//-/_}_linux_amd64_sha256")
    have=$(sha256sum < "$AGE_DIR/$b" | cut -d' ' -f1)
    [ "$have" = "$want" ] || { echo "$b: sha256 khác versions.lock [sources.age]"; exit 2; }
  done
  sudo rm -rf "$W"
  mkdir -p "$W/core" "$W/state"
  chmod 0700 "$W"
  (umask 077; mkdir -p "$W/keys"; "$KEYGEN" -o "$W/keys/identity" 2>/dev/null; "$KEYGEN" -o "$W/keys/other" 2>/dev/null)
  RECIPIENT=$("$KEYGEN" -y "$W/keys/identity")
  OTHER_RECIPIENT=$("$KEYGEN" -y "$W/keys/other")
  printf '# %s — recipient dùng một lần của diễn tập backup (P2-T03a). Công khai.\n%s\n' "$PREFIX" "$RECIPIENT" \
    > "$W/keys/backup-recovery.age-recipient"
  chmod 0644 "$W/keys/backup-recovery.age-recipient"
  sudo install -d -o root -g root -m 0700 "$W/secrets" "$W/secrets/backup" "$W/secrets/pg"
  for f in pg/superuser backup/pg_backup_password; do
    sudo sh -c "umask 077; tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40 > '$W/secrets/$f'"
  done
  sudo chown root:999 "$W/secrets/pg/superuser" && sudo chmod 0440 "$W/secrets/pg/superuser"
  sudo chown root:20007 "$W/secrets/backup/pg_backup_password" && sudo chmod 0440 "$W/secrets/backup/pg_backup_password"
  sudo bash "$ROOT/infrastructure/idp/secrets.sh" "$W/secrets/idp" >/dev/null   # + secrets/backup/idp_backup_password
  sudo install -d -o root -g root -m 0700 "$W/backups"
  sudo install -d -o 10007 -g 20007 -m 0750 "$W/backups/postgres" "$W/backups/idp"
  sudo install -d -o 10001 -g 20007 -m 0750 "$W/backups/edge"
  say "network thử ($NET_BASE.x)"
  while read -r name subnet internal range; do
    flags=(); [ "$internal" = yes ] && flags+=(--internal); [ "$range" != - ] && flags+=(--ip-range "$range")
    $D network create "${flags[@]}" --subnet "$subnet" --label meshguard.role=test "$PREFIX-$name" >/dev/null
    echo "tạo $PREFIX-$name $subnet internal=$internal"
  done <<EOF
edge $NET_BASE.0.0/24 no $NET_BASE.0.128/25
data $NET_BASE.1.0/24 yes -
egress $NET_BASE.5.0/24 no -
idp-data $NET_BASE.6.0/24 yes -
idp $NET_BASE.7.0/24 yes $NET_BASE.7.128/25
prep $NET_BASE.10.0/24 no -
EOF
  if [ -z "$GO_CACHE" ]; then GO_CACHE=$PREFIX-gomod; GO_CACHE_OWN=1; $D volume create "$GO_CACHE" >/dev/null; fi
  say "render (tools/render_backup.py, tools/render_idp.py — recipient của lượt diễn tập qua biến môi trường)"
  MG_BACKUP_RECOVERY_RECIPIENT=$RECIPIENT python3 "$ROOT/tools/render_backup.py" "$ENVFILE" "$W/core" --image "$BACKUP_IMAGE"
  MG_BASE_DOMAIN=$DOMAIN python3 "$ROOT/tools/render_idp.py" "$ENVFILE" "$W/core" --image "$IDP_IMAGE"
}

# ------------------------------------------------------------------------------------------------ 1. PostgreSQL
pg_part() {
  say "1. PostgreSQL — cụm nguồn (như postgres của mg-core: POSTGRES_DB=meshguard, alias postgres trên network data)"
  $D run -d --name "$PREFIX-src-pg" --network "$PREFIX-data" --network-alias postgres -e POSTGRES_DB=meshguard \
    -e POSTGRES_PASSWORD_FILE=/run/secrets/pw -v "$W/secrets/pg/superuser:/run/secrets/pw:ro" "$PG_IMAGE" >/dev/null
  $D network connect "$PREFIX-prep" "$PREFIX-src-pg"
  wait_pg "$PREFIX-src-pg"
  # biến của test Go ở file 0600 (mật khẩu superuser chỉ ở đây, không trên dòng lệnh)
  sudo sh -c "umask 077; printf 'MG_TEST_PG_ADMIN_URL=postgres://postgres:%s@$PREFIX-src-pg:5432/postgres?sslmode=disable\n' \"\$(cat '$W/secrets/pg/superuser')\" > '$W/secrets/pg/test.env'
    printf 'MG_TEST_PG_REQUIRED=1\nMG_BACKUP_DRILL_OUT=/state/srcdb\nMG_BACKUP_DRILL_BACKUP_PASSWORD_FILE=/pw\n' >> '$W/secrets/pg/test.env'"
  say "DB nguồn: bootstrap + migrate (goose, seed, River) + 3 fixture + audit ở 4 partition + River job (TestBackupDrillSource)"
  if $D run --rm --network "$PREFIX-prep" --env-file "$W/secrets/pg/test.env" -e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly \
      -v "$GO_CACHE:/go/pkg/mod" -v "$ROOT:/src:ro" -v "$W/state:/state" -v "$W/secrets/backup/pg_backup_password:/pw:ro" \
      -w /src "$GO_IMAGE" go test -count=1 -run '^TestBackupDrillSource$' -v ./internal/store/ > "$W/state/prep.log" 2>&1; then
    ok "DB nguồn sẵn sàng: $(grep -o 'drill source database.*' "$W/state/prep.log")"
  else
    ko "DB nguồn"; tail -20 "$W/state/prep.log"; return 1
  fi
  srcdb=$(sudo cat "$W/state/srcdb")
  psql_in "$PREFIX-src-pg" -d postgres -c "DROP DATABASE meshguard" -c "ALTER DATABASE \"$srcdb\" RENAME TO meshguard"

  say "pg-backup chạy như dịch vụ (compose up — lịch riêng; chưa có status ⇒ lượt bù ngay)"
  bk up -d pg-backup >/dev/null 2>&1
  for _ in $(seq 1 120); do sudo test -s "$W/backups/postgres/status.json" && break; sleep 1; done
  expect "daemon: lượt đầu thành công, nhãn scheduled" \
    test "$(status_field postgres last_success.label) $(status_field postgres last_attempt.ok)" = "scheduled True"
  cid=$(bk ps -q pg-backup)
  # shellcheck disable=SC2016 # template Go của docker inspect, không phải biến shell
  $D inspect -f 'pg-backup: user={{.Config.User}} read_only={{.HostConfig.ReadonlyRootfs}} cap_drop={{.HostConfig.CapDrop}} cap_add={{.HostConfig.CapAdd}} security_opt={{.HostConfig.SecurityOpt}} pids={{.HostConfig.PidsLimit}} mem={{.HostConfig.Memory}} networks={{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$cid"
  expect "daemon: non-root 10007:20007, rootfs chỉ-đọc, cap_drop ALL, no-new-privileges, chỉ network data" test \
    "$($D inspect -f '{{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}} {{len .NetworkSettings.Networks}}' "$cid")" \
    = "10007:20007 true [ALL] [no-new-privileges:true] 1"
  mounts=$($D inspect -f '{{range .Mounts}}{{.Destination}}:{{.RW}} {{end}}' "$cid")
  echo "mounts: $mounts"
  expect "daemon: chỉ /backups ghi được (recipient, secret chỉ-đọc; /run/mgbackup là tmpfs)" \
    test "$(echo "$mounts" | tr ' ' '\n' | grep -c ':true$')" = 1 -a "$(echo "$mounts" | tr ' ' '\n' | grep ':true$')" = "/backups:true"
  envnames=$($D inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$cid" | cut -d= -f1 | grep -Ei 'PASSWORD|SECRET|TOKEN' | grep -v '_FILE$' || true)
  expect "daemon: không biến môi trường nào mang secret" test -z "$envnames"
  $D logs "$cid" > "$W/state/pg-daemon.log" 2>&1
  expect "daemon: log có 'scheduler started' và 'backup done', không chứa mật khẩu" sh -c \
    "grep -q 'scheduler started' '$W/state/pg-daemon.log' && grep -q 'backup done' '$W/state/pg-daemon.log' && ! sudo grep -q -F -f '$W/secrets/backup/pg_backup_password' '$W/state/pg-daemon.log'"
  bk stop pg-backup >/dev/null 2>&1; bk rm -f pg-backup >/dev/null 2>&1

  say "trigger trước migration: docker compose run --rm pg-backup once --label pre-migration"
  rc=0; bk run --rm -T pg-backup once --label pre-migration > "$W/state/pg-premig.log" 2>&1 || rc=$?
  expect "pre-migration: exit 0" test "$rc" = 0
  set_id=$(latest postgres pre-migration)
  expect "pre-migration: bộ $set_id có manifest + globals + pgdump, status ghi nhãn pre-migration" sh -c \
    "test -n '$set_id' && sudo test -s '$W/backups/postgres/$set_id.globals.sql.age' && sudo test -s '$W/backups/postgres/$set_id.pgdump.age' && test '$(status_field postgres last_success.label)' = pre-migration"
  artifacts postgres
  enc=0
  for f in "$set_id.globals.sql.age" "$set_id.pgdump.age"; do
    head=$(sudo head -c 21 "$W/backups/postgres/$f")
    [ "$head" = "age-encryption.org/v1" ] && enc=$((enc + 1))
    if sudo grep -a -q -e 'PGDMP' -e 'CREATE ROLE' "$W/backups/postgres/$f"; then enc=-99; fi
  done
  expect "file trên đĩa là ciphertext age (header age-encryption.org/v1, không có PGDMP/CREATE ROLE)" test "$enc" = 2
  sudo cat "$W/backups/postgres/$set_id.manifest.json" | python3 -I -c 'import json, sys
for f in json.load(sys.stdin)["files"]:
    print(f["sha256"], f["name"], f["size"])' > "$W/state/sums"
  sums_ok=0
  while read -r sum name size; do
    [ "$(sudo sha256sum "$W/backups/postgres/$name" | cut -d' ' -f1)" = "$sum" ] || sums_ok=-99
    [ "$(sudo stat -c %s "$W/backups/postgres/$name")" = "$size" ] || sums_ok=-99
    sums_ok=$((sums_ok + 1))
  done < "$W/state/sums"
  expect "manifest: sha256 và kích thước của 2 file khớp nội dung trên đĩa" test "$sums_ok" = 2
  sudo find "$W/backups/postgres" -maxdepth 1 -name "$set_id.*" -printf '%M %u:%g %s %f\n'

  say "ảnh chụp DB nguồn (superuser): số hàng + băm từng bảng, catalog"
  psql_in "$PREFIX-src-pg" -d meshguard -At -c "$COUNTS_SQL" > "$W/state/pg-src-counts"
  psql_in "$PREFIX-src-pg" -d meshguard -At -c "$CATALOG_SQL" > "$W/state/pg-src-catalog"
  echo "$(wc -l < "$W/state/pg-src-counts") bảng/partition, $(awk -F'|' '$2 == "r" {s += $3} END {print s}' "$W/state/pg-src-counts") hàng (bảng lá)"

  say "restore vào cụm tạm $PREFIX-restore-pg (giải mã bằng identity dùng một lần, plaintext chỉ qua pipe)"
  $D run -d --name "$PREFIX-restore-pg" --network none -e POSTGRES_DB=meshguard \
    -e POSTGRES_PASSWORD_FILE=/run/secrets/pw -v "$W/secrets/pg/superuser:/run/secrets/pw:ro" "$PG_IMAGE" >/dev/null
  wait_pg "$PREFIX-restore-pg"
  psql_in "$PREFIX-restore-pg" -d postgres -c "DROP DATABASE meshguard"   # DB rỗng do POSTGRES_DB tạo — runbook bước 3
  rc=0
  decrypt "$W/backups/postgres/$set_id.globals.sql.age" | sed '/^CREATE ROLE postgres;$/d' \
    | psql_in "$PREFIX-restore-pg" -d postgres > "$W/state/restore-globals.log" 2>&1 || rc=$?
  expect "restore globals (role, membership, thiết lập role) — psql ON_ERROR_STOP" test "$rc" = 0
  rc=0
  decrypt "$W/backups/postgres/$set_id.pgdump.age" \
    | $D exec -i "$PREFIX-restore-pg" pg_restore -U postgres -d postgres --create --exit-on-error > "$W/state/restore-dump.log" 2>&1 || rc=$?
  expect "pg_restore --create --exit-on-error" test "$rc" = 0
  psql_in "$PREFIX-restore-pg" -d meshguard -At -c "$COUNTS_SQL" > "$W/state/pg-restored-counts"
  psql_in "$PREFIX-restore-pg" -d meshguard -At -c "$CATALOG_SQL" > "$W/state/pg-restored-catalog"
  compare "PostgreSQL: số hàng + băm nội dung từng bảng/partition" "$W/state/pg-src-counts" "$W/state/pg-restored-counts"
  compare "PostgreSQL: catalog (role, membership, ACL, RLS, policy, hàm, trigger)" "$W/state/pg-src-catalog" "$W/state/pg-restored-catalog"
  grep -E '^(public\.(tenants|audit_events|sessions|secrets)|partitions\.|river\.river_job)\|' "$W/state/pg-restored-counts" | cut -d'|' -f1-3

  say "RLS còn hiệu lực sau restore (SET ROLE từ superuser)"
  tid=$(psql_in "$PREFIX-restore-pg" -d meshguard -At -c "SELECT id FROM tenants ORDER BY id LIMIT 1")
  total=$(psql_in "$PREFIX-restore-pg" -d meshguard -At -c "SELECT count(*) FROM tenants")
  one=$(psql_in "$PREFIX-restore-pg" -d meshguard -At -c "SET ROLE mg_api_tenant" \
    -c "SELECT set_config('app.scope', 'tenant', false), set_config('app.tenant_id', '$tid', false)" -c "SELECT count(*) FROM tenants" | tail -n1)
  none=$(psql_in "$PREFIX-restore-pg" -d meshguard -At -c "SET ROLE mg_api_tenant" -c "SELECT count(*) FROM tenants")
  all=$(psql_in "$PREFIX-restore-pg" -d meshguard -At -c "SET ROLE mg_api_platform" \
    -c "SELECT set_config('app.scope', 'platform', false)" -c "SELECT count(*) FROM tenants" | tail -n1)
  expect "RLS: pool tenant thấy 1/$total tenant, không đặt app.* thấy 0, pool platform thấy $all" test "$one $none $all" = "1 0 $total"

  say "runbook: restore vào môi trường đang dùng ⇒ thu hồi MỌI session (Phase 2; từ Phase 3: meshguard admin post-restore-reconcile)"
  live=$(psql_in "$PREFIX-restore-pg" -d meshguard -At -c "SELECT count(*) FROM sessions WHERE revoked_at IS NULL")
  psql_in "$PREFIX-restore-pg" -d meshguard -c "SET ROLE mg_migrator" \
    -c "UPDATE sessions SET revoked_at = now() WHERE revoked_at IS NULL" -c "DELETE FROM auth_requests" > "$W/state/revoke.log"
  left=$(psql_in "$PREFIX-restore-pg" -d meshguard -At -c "SELECT count(*) FROM sessions WHERE revoked_at IS NULL")
  expect "thu hồi session: $live session còn hiệu lực trước, $left sau" test "$live" -gt 0 -a "$left" = 0

  say "restore vào CHÍNH cụm đang dùng (rollback sau migration — runbook mục 6.3): đổi tên DB, globals bỏ CREATE ROLE"
  psql_in "$PREFIX-src-pg" -d postgres -c "ALTER DATABASE meshguard RENAME TO meshguard_before_restore"
  rc=0
  decrypt "$W/backups/postgres/$set_id.globals.sql.age" | sed -E '/^CREATE ROLE [a-z_][a-z0-9_]*;$/d' \
    | psql_in "$PREFIX-src-pg" -d postgres > "$W/state/live-globals.log" 2>&1 || rc=$?
  expect "globals áp lại lên cụm đang chạy (role đã có: chỉ ALTER ROLE/GRANT) — ON_ERROR_STOP" test "$rc" = 0
  rc=0
  decrypt "$W/backups/postgres/$set_id.pgdump.age" \
    | $D exec -i "$PREFIX-src-pg" pg_restore -U postgres -d postgres --create --exit-on-error > "$W/state/live-dump.log" 2>&1 || rc=$?
  expect "pg_restore --create vào cụm đang chạy" test "$rc" = 0
  psql_in "$PREFIX-src-pg" -d meshguard -At -c "$COUNTS_SQL" > "$W/state/pg-live-counts"
  psql_in "$PREFIX-src-pg" -d meshguard -At -c "$CATALOG_SQL" > "$W/state/pg-live-catalog"
  compare "rollback tại chỗ: số hàng + băm từng bảng/partition" "$W/state/pg-src-counts" "$W/state/pg-live-counts"
  compare "rollback tại chỗ: catalog" "$W/state/pg-src-catalog" "$W/state/pg-live-catalog"
  psql_in "$PREFIX-src-pg" -d postgres -c "DROP DATABASE meshguard_before_restore"

  say "âm tính — PostgreSQL"
  rc=0; sudo cat "$W/backups/postgres/$set_id.pgdump.age" | "$AGE" --decrypt --identity "$W/keys/other" > /dev/null 2> "$W/state/wrong-id.err" || rc=$?
  expect "identity sai ⇒ không giải mã được ($(head -c 80 "$W/state/wrong-id.err"))" test "$rc" != 0
  before=$(artifacts postgres; sudo sha256sum "$W/backups/postgres/status.json")
  for case in "trống|" "sai định dạng|age1notarecipient" "recipient hợp lệ nhưng lệch file của host|$OTHER_RECIPIENT"; do
    rc=0; bk run --rm -T -e "MG_BACKUP_RECIPIENT=${case#*|}" pg-backup once --label pre-migration > "$W/state/neg.log" 2>&1 || rc=$?
    after=$(artifacts postgres; sudo sha256sum "$W/backups/postgres/status.json")
    expect "recipient ${case%%|*} ⇒ exit 2 ($rc), thư mục đích không đổi" test "$rc" = 2 -a "$before" = "$after"
  done
  grep -o '"msg":"[^"]*"' "$W/state/neg.log" | head -2 || true
  sudo cp -p "$W/secrets/backup/pg_backup_password" "$W/secrets/backup/pg_backup_password.keep"
  sudo sh -c "umask 077; printf 'wrong-password-for-the-drill\n' > '$W/secrets/backup/pg_backup_password'"
  sudo chown root:20007 "$W/secrets/backup/pg_backup_password" && sudo chmod 0440 "$W/secrets/backup/pg_backup_password"
  before=$(artifacts postgres)
  rc=0; bk run --rm -T pg-backup once --label manual > "$W/state/neg-pw.log" 2>&1 || rc=$?
  sudo mv "$W/secrets/backup/pg_backup_password.keep" "$W/secrets/backup/pg_backup_password"
  expect "mật khẩu DB sai ⇒ exit 1, không giữ file nào, status ghi lỗi (lần thất bại liên tiếp: $(status_field postgres consecutive_failures))" \
    test "$rc" = 1 -a "$before" = "$(artifacts postgres)" -a "$(status_field postgres last_attempt.ok)" = False
  expect "không còn file .partial" test -z "$(sudo find "$W/backups/postgres" -name '*.partial')"
  echo "lỗi ghi trong status: $(status_field postgres last_attempt.error | head -c 160)"
  rc=0; psql_in "$PREFIX-src-pg" -U mg_backup -d meshguard -c "SET default_transaction_read_only = off" \
    -c "INSERT INTO system_settings (key, value) VALUES ('drill.write', '1')" > /dev/null 2> "$W/state/bk-write.err" || rc=$?
  expect "mg_backup (đã tự tắt read-only) không ghi được: $(head -c 70 "$W/state/bk-write.err")" sh -c "test $rc != 0 && grep -q 'permission denied' '$W/state/bk-write.err'"
  rc=0; $D run --rm --network none --read-only --cap-drop ALL -v /dev/null:/usr/bin/dash:ro --entrypoint /usr/local/bin/pg_dumpall \
    "$BACKUP_IMAGE" --globals-only -h 127.0.0.1 -U mg_backup > /dev/null 2> "$W/state/nosh.err" || rc=$?
  $D run --rm --network none --read-only --cap-drop ALL --entrypoint /usr/local/bin/pg_dumpall \
    "$BACKUP_IMAGE" --globals-only -h 127.0.0.1 -U mg_backup > /dev/null 2> "$W/state/withsh.err" || true
  echo "không /bin/sh: $(head -c 140 "$W/state/nosh.err")"
  echo "có /bin/sh:    $(head -c 140 "$W/state/withsh.err")"
  expect "pg_dumpall cần /bin/sh (popen kiểm pg_dump) — lý do image có dash" sh -c \
    "test $rc != 0 && grep -q 'is needed by pg_dumpall' '$W/state/nosh.err' && grep -q 'connection to server' '$W/state/withsh.err'"
}

# ------------------------------------------------------------------------------------------------ 2. IdP
idp_part() {
  say "2. IdP — Keycloak + idp-db (compose mg-idp đã render, image idp pin digest); chờ healthy"
  t0=$(date +%s)
  if idp up -d --wait --wait-timeout 600 > "$W/state/idp-up.log" 2>&1; then ok "Keycloak healthy sau $(( $(date +%s) - t0 )) s"; else ko "Keycloak không healthy"; tail -20 "$W/state/idp-up.log"; return 1; fi
  kcip=$($D inspect -f "{{(index .NetworkSettings.Networks \"$PREFIX-idp\").IPAddress}}" "$(idp ps -q idp)")
  if python3 -I "$ROOT/tests/backup/kc_drill.py" prepare --base "http://$kcip:8080" --domain "$DOMAIN" \
      --admin-conf <(sudo cat "$W/secrets/idp/keycloak.conf") --state "$W/state/kc.json"; then ok "Keycloak: dữ liệu thử đã tạo"; else ko "kc_drill prepare"; fi
  rc=0; bk run --rm -T idp-backup once --label manual > "$W/state/idp-live.log" 2>&1 || rc=$?
  expect "idp-backup lúc Keycloak đang chạy ⇒ exit 0 (pg_dump: snapshot nhất quán)" test "$rc" = 0
  sleep 1
  say "dừng Keycloak (không còn ghi) → ảnh chụp DB keycloak → idp-backup"
  idp stop idp > /dev/null 2>&1
  idpdb=$(idp ps -q idp-db)
  psql_in "$idpdb" -d keycloak -At -c "$COUNTS_SQL" > "$W/state/kc-src-counts"
  psql_in "$idpdb" -d keycloak -At -c "$CATALOG_SQL" > "$W/state/kc-src-catalog"
  rc=0; bk run --rm -T idp-backup once --label manual > "$W/state/idp-once.log" 2>&1 || rc=$?
  expect "idp-backup once ⇒ exit 0" test "$rc" = 0
  kset=$(latest idp manual)
  artifacts idp
  say "idp-db MỚI (initdb tạo role keycloak, idp_backup, DB keycloak rỗng) ← pg_restore"
  idp rm -sf idp-db > /dev/null 2>&1
  $D volume rm "$PREFIX-idp_idp-db-data" > /dev/null
  idp up -d --wait idp-db > /dev/null 2>&1
  idpdb=$(idp ps -q idp-db)
  rc=0; decrypt "$W/backups/idp/$kset.pgdump.age" \
    | $D exec -i "$idpdb" pg_restore -U postgres -d keycloak --exit-on-error > "$W/state/kc-restore.log" 2>&1 || rc=$?
  expect "pg_restore vào idp-db mới" test "$rc" = 0
  psql_in "$idpdb" -d keycloak -At -c "$COUNTS_SQL" > "$W/state/kc-restored-counts"
  psql_in "$idpdb" -d keycloak -At -c "$CATALOG_SQL" > "$W/state/kc-restored-catalog"
  compare "IdP: số hàng + băm nội dung từng bảng của DB keycloak" "$W/state/kc-src-counts" "$W/state/kc-restored-counts"
  compare "IdP: catalog (role keycloak/idp_backup, ACL)" "$W/state/kc-src-catalog" "$W/state/kc-restored-catalog"
  echo "DB keycloak: $(wc -l < "$W/state/kc-src-counts") bảng, $(awk -F'|' '{s += $3} END {print s}' "$W/state/kc-src-counts") hàng"
  t0=$(date +%s)
  if idp up -d --wait --wait-timeout 600 idp > "$W/state/idp-up2.log" 2>&1; then ok "Keycloak khởi động trên DB đã restore sau $(( $(date +%s) - t0 )) s"; else ko "Keycloak sau restore"; return 1; fi
  kcip=$($D inspect -f "{{(index .NetworkSettings.Networks \"$PREFIX-idp\").IPAddress}}" "$(idp ps -q idp)")
  if python3 -I "$ROOT/tests/backup/kc_drill.py" verify --base "http://$kcip:8080" --domain "$DOMAIN" \
      --admin-conf <(sudo cat "$W/secrets/idp/keycloak.conf") --state "$W/state/kc.json"; then ok "Keycloak: realm, user, discovery như trước backup"; else ko "kc_drill verify"; fi
}

# ------------------------------------------------------------------------------------------------ 3. Edge
edge_snapshot() {   # <volume>: loại|mode|uid|gid|size|mtime|đích symlink của mọi mục + sha256 từng file
  $D run --rm --network none -v "$1:/data:ro" --entrypoint sh "$PG_IMAGE" -c \
    'cd /data && find . -printf "%p|%y|%m|%U|%G|%s|%T@|%l\n" | sort && find . -type f -exec sha256sum {} + | sort -k2'
}
edge_part() {
  say "3. Edge — volume ACME giả lập (owner 10001 như edge; mode 0600/0644/0700; symlink; file 1 MiB)"
  $D volume create "$PREFIX-edge-data" > /dev/null
  # shellcheck disable=SC2016 # script chạy trong container alpine, biến của nó
  $D run --rm --network none -v "$PREFIX-edge-data:/data" "$ALPINE" sh -ec '
    cd /data
    a=caddy/acme/acme-v02.api.letsencrypt.org-directory; c=caddy/certificates/acme-v02.api.letsencrypt.org-directory
    mkdir -p "$a/users/default" "$c/wildcard_.mesh.drill.test" "$c/app.drill.test" caddy/locks caddy/ocsp
    head -c 227 /dev/urandom > "$a/users/default/default.key"
    printf "{\"status\":\"valid\"}" > "$a/users/default/default.json"
    for d in "$c/wildcard_.mesh.drill.test" "$c/app.drill.test"; do
      head -c 1500 /dev/urandom > "$d/$(basename "$d").crt"; head -c 227 /dev/urandom > "$d/$(basename "$d").key"
      printf "{}" > "$d/$(basename "$d").json"
    done
    head -c 1048576 /dev/urandom > caddy/ocsp/big.bin
    : > caddy/locks/issue_cert_app.drill.test.lock
    printf "{\"tls\":{}}" > "caddy/last clean.json"
    ln -s certificates/acme-v02.api.letsencrypt.org-directory caddy/current
    chown -R 10001:10001 /data
    chmod 0755 /data caddy; find caddy/acme caddy/certificates caddy/locks -type d -exec chmod 0700 {} +
    find caddy -type f -name "*.key" -exec chmod 0600 {} +; find caddy -type f -name "*.crt" -exec chmod 0644 {} +
    chmod 0640 caddy/ocsp/big.bin
    touch -d "2026-01-02 03:04:05" "caddy/last clean.json"'
  edge_snapshot "$PREFIX-edge-data" > "$W/state/edge-src"
  rc=0; bk run --rm -T edge-backup once --label manual > "$W/state/edge-once.log" 2>&1 || rc=$?
  expect "edge-backup (UID 10001, không network, volume chỉ-đọc) ⇒ exit 0" test "$rc" = 0
  eset=$(latest edge manual)
  artifacts edge
  $D volume create "$PREFIX-edge-restored" > /dev/null
  rc=0; decrypt "$W/backups/edge/$eset.tar.age" \
    | $D run --rm -i --network none -v "$PREFIX-edge-restored:/data" --entrypoint tar "$PG_IMAGE" -x --numeric-owner -p -C /data || rc=$?
  expect "giải nén vào volume mới (tar --numeric-owner -p, root)" test "$rc" = 0
  edge_snapshot "$PREFIX-edge-restored" > "$W/state/edge-restored"
  compare "Edge: loại, mode, owner, kích thước, mtime, đích symlink, sha256 từng file" "$W/state/edge-src" "$W/state/edge-restored"
  grep -E '\|f\|' "$W/state/edge-src" | cut -d'|' -f1-5 | head -5
  say "âm tính — edge"
  rc=0; bk run --rm -T --entrypoint /bin/sh edge-backup -c 'echo x > /source/caddy/x' > /dev/null 2> "$W/state/ro.err" || rc=$?
  expect "ghi vào volume ACME từ edge-backup bị từ chối ($(grep -o 'Read-only file system' "$W/state/ro.err" | head -n1))" \
    sh -c "test $rc != 0 && grep -q 'Read-only file system' '$W/state/ro.err'"
  $D run --rm --network none -v "$PREFIX-edge-data:/data" "$ALPINE" sh -c 'printf secret > /data/caddy/root-only && chmod 0600 /data/caddy/root-only'
  before=$(artifacts edge)
  rc=0; bk run --rm -T edge-backup once --label manual > "$W/state/edge-neg.log" 2>&1 || rc=$?
  expect "file không đọc được trong volume ⇒ exit 1, không giữ archive nào (fail closed)" test "$rc" = 1 -a "$before" = "$(artifacts edge)"
  $D run --rm --network none -v "$PREFIX-edge-data:/data" "$ALPINE" rm -f /data/caddy/root-only
}

# ------------------------------------------------------------------------------------------------ hardening idp/edge
hardening() {
  say "4. idp-backup và edge-backup chạy như dịch vụ — kiểm hardening thực tế"
  bk up -d idp-backup edge-backup > /dev/null 2>&1
  sleep 3
  for s in idp-backup edge-backup; do
    cid=$(bk ps -q "$s")
    $D inspect -f "$s: user={{.Config.User}} read_only={{.HostConfig.ReadonlyRootfs}} cap_drop={{.HostConfig.CapDrop}} security_opt={{.HostConfig.SecurityOpt}} network_mode={{.HostConfig.NetworkMode}} networks={{range \$k, \$v := .NetworkSettings.Networks}}{{\$k}} {{end}}mounts={{range .Mounts}}{{.Destination}}:{{.RW}} {{end}}state={{.State.Status}}" "$cid"
  done
  e=$(bk ps -q edge-backup); i=$(bk ps -q idp-backup)
  expect "edge-backup: 10001:20007, chỉ-đọc, cap_drop ALL, network none, /source chỉ-đọc, chỉ /backups ghi được" test \
    "$($D inspect -f '{{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.NetworkMode}} {{range .Mounts}}{{if .RW}}{{.Destination}} {{end}}{{end}}' "$e")" \
    = "10001:20007 true [ALL] none /backups "
  expect "idp-backup: 10007:20007, chỉ-đọc, cap_drop ALL, chỉ network idp-data, chỉ /backups ghi được" test \
    "$($D inspect -f "{{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{len .NetworkSettings.Networks}} {{range .Mounts}}{{if .RW}}{{.Destination}} {{end}}{{end}}" "$i")" \
    = "10007:20007 true [ALL] 1 /backups "
  expect "edge-backup/idp-backup đang chạy (đã có backup mới ⇒ chờ lịch 02:40/02:50 UTC)" test \
    "$($D inspect -f '{{.State.Status}}' "$e") $($D inspect -f '{{.State.Status}}' "$i")" = "running running"
  bk stop > /dev/null 2>&1
}

# ------------------------------------------------------------------------------------------------ dọn
down() {
  set +e
  say "dọn $PREFIX"
  if [ -f "$W/core/compose.backup.yaml" ]; then bk down -v --remove-orphans > /dev/null 2>&1; fi
  if [ -f "$W/core/compose.idp.yaml" ]; then idp down -v --remove-orphans > /dev/null 2>&1; fi
  for p in "$PREFIX-backup" "$PREFIX-idp"; do
    ids=$($D ps -aq --filter "label=com.docker.compose.project=$p")
    # shellcheck disable=SC2086 # danh sách id container
    [ -z "$ids" ] || $D rm -f $ids > /dev/null
  done
  $D rm -f "$PREFIX-src-pg" "$PREFIX-restore-pg" > /dev/null 2>&1
  for v in "$PREFIX-edge-data" "$PREFIX-edge-restored" "$PREFIX-idp_idp-db-data"; do $D volume rm "$v" > /dev/null 2>&1; done
  [ "$GO_CACHE_OWN" = 1 ] && $D volume rm "$GO_CACHE" > /dev/null 2>&1
  for n in edge data egress idp-data idp prep; do $D network rm "$PREFIX-$n" > /dev/null 2>&1; done
  [ -d "$W/keys" ] && shred -u "$W/keys/identity" "$W/keys/other" 2> /dev/null
  sudo rm -rf "$W"
  echo "còn lại: $($D ps -a --filter "name=$PREFIX" -q | wc -l) container, $($D network ls --filter "name=$PREFIX" -q | wc -l) network, $($D volume ls --filter "name=$PREFIX" -q | wc -l) volume"
}

summary() {
  rc=$?
  down
  printf '\nKẾT QUẢ: %d PASS, %d FAIL%s\n' "$pass" "$fail" "$([ "$rc" = 0 ] || echo " (dừng sớm, exit $rc)")"
  if [ "$fail" = 0 ] && [ "$rc" = 0 ]; then exit 0; fi
  exit 1
}
trap summary EXIT
setup
pg_part
idp_part
edge_part
hardening
