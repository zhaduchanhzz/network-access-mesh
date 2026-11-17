#!/bin/bash
# Kiểm quyền secret dạng file (P1-T03; chạy lại ở mỗi lần deploy mg-core/mg-edge — §14.2).
# Với mỗi secret: không world-readable; đọc được từ container chạy đúng UID/GID của service dùng nó; KHÔNG đọc được
# từ container chạy UID/GID của service khác. Không in giá trị secret. Thoát khác 0 nếu có lỗi.
set -uo pipefail
R=/opt/meshguard/secrets
IMG=docker.io/library/alpine@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
# file | user của consumer | nhóm phụ của consumer | các "kẻ lạ" (user/nhóm phụ, cách nhau bởi ;)
CHECKS=(
  "postgres/superuser_password|999:999||12345:12345/;10001:10001/20005;65532:65532/20001"
  "crowdsec/bouncer_key|0:0||10001:10001/20005;12345:12345/"
  "edge/bouncer_key|10001:10001|20005|65532:65532/20001;12345:12345/"
  "edge/admin_token|10001:10001|20005|65532:65532/;65534:65534/20006"
  "app/edge_admin_token|65532:65532|20001|10001:10001/20005;65534:65534/20006"
  "edge/metrics_token|10001:10001|20005|65534:65534/;65532:65532/20001"
  "obs/edge_metrics_token|65534:65534|20006|10001:10001/20005;65532:65532/20001"
  "edge/cloudflare_dns_token|10001:10001|20005|65532:65532/20001;65534:65534/20006;12345:12345/"
  # IdP (P2-T05, project mg-idp — triển khai lên staging ở P2-T16). 999 = idp-db (cùng UID với postgres của core: không
  # phân biệt được bằng UID, file chỉ mount vào idp-db); 1000 = Keycloak; 65534 = mailsink (SMTP mẫu); 10007:20007 = backup
  "idp/keycloak.conf|1000:1000||999:999/;65534:65534/;10001:10001/20005;65532:65532/20001"
  "idp/db_password|999:999||1000:1000/;65534:65534/;10001:10001/20005"
  "idp/db_superuser_password|999:999||1000:1000/;65534:65534/;10001:10001/20005"
  "idp/backup_db_password|999:999||1000:1000/;65534:65534/;10007:10007/20007"
  "backup/idp_backup_password|10007:20007||1000:1000/;999:999/;65534:65534/;65532:65532/20001"
  # P2-T16 — mg-app (infrastructure/host/app-secrets.sh): api 65532+20001+20002, worker 65532+20001+20003,
  # migrate 65532+20004; một nhóm không bao giờ đọc được secret của nhóm khác
  "api/db_api_tenant_password|65532:65532|20002|65532:65532/20001;65532:65532/20003;65532:65532/20004"
  "api/db_api_platform_password|65532:65532|20002|65532:65532/20001;65532:65532/20003;65532:65532/20004"
  "worker/db_worker_tenant_password|65532:65532|20003|65532:65532/20001;65532:65532/20002;65532:65532/20004"
  "worker/db_worker_platform_password|65532:65532|20003|65532:65532/20001;65532:65532/20002;65532:65532/20004"
  "worker/db_partition_password|65532:65532|20003|65532:65532/20001;65532:65532/20002;65532:65532/20004"
  "app/db_audit_writer_password|65532:65532|20001|65532:65532/20002;65532:65532/20003;10001:10001/20005"
  "migrate/mg_migrator|65532:65532|20004|65532:65532/20001;65532:65532/20002;65532:65532/20003"
  "migrate/mg_api_tenant|65532:65532|20004|65532:65532/20001;65532:65532/20003"
  "migrate/mg_api_platform|65532:65532|20004|65532:65532/20001;65532:65532/20003"
  "migrate/mg_worker_tenant|65532:65532|20004|65532:65532/20001;65532:65532/20002"
  "migrate/mg_worker_platform|65532:65532|20004|65532:65532/20001;65532:65532/20002"
  "migrate/mg_partition_maint|65532:65532|20004|65532:65532/20001;65532:65532/20002"
  "migrate/mg_audit_writer|65532:65532|20004|65532:65532/20002;65532:65532/20003"
)
fail=0
can_read() {  # <file> <user> <groups>
  local ga=(); [ -n "$3" ] && ga=(--group-add "$3")
  sudo docker run --rm --network none --user "$2" "${ga[@]}" -v "$1:/s:ro" "$IMG" sh -c 'head -c1 /s >/dev/null 2>&1'
}
for c in "${CHECKS[@]}"; do
  IFS='|' read -r rel user groups intruders <<<"$c"
  f="$R/$rel"
  if ! sudo test -s "$f"; then echo "FAIL $rel: missing"; fail=1; continue; fi
  mode=$(sudo stat -c '%a %U:%G' "$f")
  case "${mode%% *}" in *[4-7]) echo "FAIL $rel: world-readable ($mode)"; fail=1; continue;; esac
  if can_read "$f" "$user" "$groups"; then r="consumer $user${groups:++$groups} reads"; else echo "FAIL $rel: consumer $user cannot read ($mode)"; fail=1; continue; fi
  bad=""
  IFS=';' read -ra list <<<"$intruders"
  for i in "${list[@]}"; do
    iu=${i%%/*}; ig=${i#*/}
    can_read "$f" "$iu" "$ig" && bad+=" $iu${ig:++$ig}"
  done
  if [ -n "$bad" ]; then echo "FAIL $rel: also readable by$bad"; fail=1; else echo "PASS $rel ($mode): $r; ${#list[@]} other UID/GID denied"; fi
done
exit $fail
