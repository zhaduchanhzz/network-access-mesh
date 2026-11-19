# Image IdP của MeshGuard (P2-T05, §8.2, §14.4): Keycloak 26.8.2 đã build tối ưu ("optimized server image" — tài liệu
# "Running Keycloak in a container" của Keycloak). Tùy chọn build-time được nướng sẵn để container chạy
# `start --optimized` với rootfs CHỈ ĐỌC: image gốc thấy tùy chọn build khác mặc định (db=postgres, health, metrics,
# feature) thì tự build lại lúc khởi động và ghi vào /opt/keycloak/lib/quarkus — cần rootfs ghi được.
# Không thêm gói, provider hay theme nào: so với base chỉ khác thư mục `kc.sh build` sinh ra, kho CA của JVM đã gỡ
# một root (stage truststore — CVE-2026-91403) và danh sách mật khẩu cấm (stage blocklist — G2 vòng 2, A-3).
# Base pin theo digest (versions.lock [images.keycloak]); tag 26.8.2 trên quay.io đã bị push lại khi rebuild base —
# 2026-11-19: 26.8.2-3 (JDK 21.0.13.1 vá CVE-2026-114938 "Java4Shell", RHSA-2026:100567).
ARG KEYCLOAK=quay.io/keycloak/keycloak:26.8.2@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3

FROM ${KEYCLOAK} AS build
# impersonation — §8.2 (2): tắt ở mức server ⇒ không realm nào có role/endpoint impersonation, kể cả admin master.
# kerberos, ciba, device-flow, token-exchange-standard — phương thức/grant MeshGuard không dùng: bớt bề mặt tấn công.
ENV KC_DB=postgres \
    KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=true \
    KC_FEATURES_DISABLED=impersonation,kerberos,ciba,device-flow,token-exchange-standard
RUN /opt/keycloak/bin/kc.sh build \
 && /opt/keycloak/bin/kc.sh show-config > /tmp/kc-config.txt 2>&1 \
 && grep -Eq 'kc\.db +[=:] +postgres' /tmp/kc-config.txt \
 && grep -Eq 'kc\.features-disabled +[=:] +impersonation,kerberos,ciba,device-flow,token-exchange-standard' /tmp/kc-config.txt \
 && grep -Eq 'kc\.health-enabled +[=:] +true' /tmp/kc-config.txt \
 && grep -Eq 'kc\.metrics-enabled +[=:] +true' /tmp/kc-config.txt

# CVE-2026-91403 — sự cố eMudhra (quyết định chủ dự án 2026-11-16 "Vá + ngoại lệ có hạn"; P2-T05 mục 7): gỡ ĐÚNG MỘT
# root "emSign Root CA - G1" khỏi kho CA mà JVM dùng. OpenJDK yêu cầu gỡ 4 root (openjdk.org/emudhra, JDK-8395690):
# emSign Root CA - G1, emSign Root CA - G2, emSign ECC Root CA - G3, Comodo AAA; kho Java của base này (ca-certificates
# 2026.2.92_v9.0.319-90.3.el9_8 = RHSA-2026:88459) không có 3 root sau, chỉ còn G1. JDK của RHEL đọc
# $JAVA_HOME/lib/security/cacerts -> /etc/pki/java/cacerts -> /etc/pki/ca-trust/extracted/java/cacerts (JKS do p11-kit
# trích từ ca-certificates). Cơ chế hệ thống (blocklist + update-ca-trust) không chạy được trong image này —
# /usr/bin/trust thiếu libp11-kit.so.0 (base dựng trên ubi9-micro) — nên dùng keytool -delete trên đúng file đó.
# Build fail nếu: kho ở chỗ khác; alias không trỏ đúng fingerprint (base mới đã bỏ root này ⇒ xem lại ngoại lệ grype
# infrastructure/docker/idp/grype.yaml); kho mất hoặc thêm bất kỳ mục nào khác. "changeit" là mật khẩu toàn vẹn cố định,
# công khai của kho JKS mà p11-kit ghi — không phải secret. keytool in "Warning: use -cacerts option…" — vô hại (-cacerts
# không đi cùng -storetype được). Chỉ file kho được chép sang image cuối.
FROM ${KEYCLOAK} AS truststore
USER 0
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN set -eu; export LC_ALL=C; \
    fp=40:F6:AF:03:46:A9:9A:A1:CD:1D:55:5A:4E:9C:CE:62:C7:F9:63:46:03:EE:40:66:15:83:3D:C8:C8:D0:03:67; \
    store=$(readlink -f "$(dirname "$(dirname "$(readlink -f /usr/bin/java)")")/lib/security/cacerts"); \
    test "$store" = /etc/pki/ca-trust/extracted/java/cacerts; \
    kt() { keytool -J-XX:-UsePerfData "$@" -keystore "$store" -storetype JKS -storepass changeit; }; \
    fps() { kt -list | sed -n 's/^Certificate fingerprint (SHA-256): //p' | sort; }; \
    before=$(fps); \
    test "$(kt -list -alias emsignrootca-g1 | sed -n 's/^Certificate fingerprint (SHA-256): //p')" = "$fp"; \
    kt -delete -alias emsignrootca-g1; \
    after=$(fps); \
    test "$(comm -23 <(echo "$before") <(echo "$after"))" = "$fp"; \
    test -z "$(comm -13 <(echo "$before") <(echo "$after"))"; \
    echo "kho CA của JVM ($store): $(echo "$before" | wc -l) -> $(echo "$after" | wc -l) mục, đã gỡ emsignrootca-g1 $fp"

# Danh sách mật khẩu cấm (G2 vòng 2, A-3 — ASVS 6.2.4, 6.2.11, 6.2.12; versions.lock [sources.password-blocklist]):
# passwordBlacklist(mg-passwords-v1.txt) của mọi realm (infrastructure/idp/realms, tools/render_idp.py check_realm) =
#   (1) 1 000 000 mật khẩu phổ biến nhất của bộ "Ten Million Passwords" (Mark Burnett, 2015) bản của SecLists
#       (MIT — LICENSE chép vào image), tải theo commit pin, kiểm sha256 ngay trong build (ADD --checksum), chỉ giữ mục
#       12–128 ký tự ASCII in được (policy length(12) maxLength(128) đã chặn phần còn lại) — ~46 000 mục;
#   (2) từ ngữ cảnh × hậu tố (password-blocklist/context-*.txt — danh sách có tài liệu của 6.1.2, 6.2.11).
# Chữ thường, sắp xếp, không trùng: Keycloak so khớp nguyên mật khẩu, không phân biệt hoa/thường (bloom filter, xác suất
# dương tính giả mặc định 0,01 %). File đặt NGOÀI /opt/keycloak/data (tmpfs lúc chạy — compose.idp.yaml) và Keycloak tìm
# nó qua tùy chọn SPI blacklists-path của provider password-blacklist (ENV ở stage cuối, tùy chọn runtime). Build fail
# nếu tải lệch sha256, số mục quá ít hoặc thiếu mục mẫu. Đổi nội dung ⇒ đổi tên file (v2) ở đây, render_idp.BLOCKLIST_FILE
# và realm template.
FROM ${KEYCLOAK} AS blocklist
USER 0
ADD --checksum=sha256:424a3e03a17df0a2bc2b3ca749d81b04e79d59cb7aeec8876a5a3f308d0caf51 \
    https://raw.githubusercontent.com/danielmiessler/SecLists/0008f4343439b48257c0815fc797955d0ab1e755/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt \
    /tmp/blocklist/common.txt
ADD --checksum=sha256:3dbdc93d5f8829de0941744841730a09c106d0732e5ae0e98ca1d77be7ded66c \
    https://raw.githubusercontent.com/danielmiessler/SecLists/0008f4343439b48257c0815fc797955d0ab1e755/LICENSE \
    /tmp/blocklist/SecLists-LICENSE
COPY password-blocklist/context-words.txt password-blocklist/context-suffixes.txt /tmp/blocklist/
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN set -eu; export LC_ALL=C; cd /tmp/blocklist; mkdir -p /out; \
    words=$(grep -v -e '^#' -e '^$' context-words.txt); \
    sufs=$(grep -v -e '^#' -e '^$' context-suffixes.txt | sed 's/^<empty>$//'); \
    { grep -E '^[ -~]{12,128}$' common.txt; \
      while IFS= read -r w; do while IFS= read -r s; do printf '%s%s\n' "$w" "$s"; done <<< "$sufs"; done <<< "$words" \
        | grep -E '^[ -~]{12,128}$'; } \
      | tr 'A-Z' 'a-z' | sort -u > /out/mg-passwords-v1.txt; \
    n=$(wc -l < /out/mg-passwords-v1.txt); test "$n" -ge 45000; \
    for p in password1234 qwertyuiop123 'password1234!' meshguard2026 tenant-a12345 'meshguard@2026!'; do \
      grep -qxF -- "$p" /out/mg-passwords-v1.txt; done; \
    echo "mg-passwords-v1.txt: $n mục, sha256 $(sha256sum < /out/mg-passwords-v1.txt | cut -c1-64)"; \
    install -d -m 0755 /out/mg/password-blacklists /out/mg/licenses; \
    install -m 0444 /out/mg-passwords-v1.txt /out/mg/password-blacklists/mg-passwords-v1.txt; \
    install -m 0444 SecLists-LICENSE /out/mg/licenses/SecLists-LICENSE

FROM ${KEYCLOAK}
COPY --from=build /opt/keycloak/lib/quarkus/ /opt/keycloak/lib/quarkus/
COPY --from=truststore /etc/pki/ca-trust/extracted/java/cacerts /etc/pki/ca-trust/extracted/java/cacerts
# root:root, thư mục 0755, file 0444 — Keycloak (UID 1000) chỉ đọc. Tên biến có chữ PASSWORD nên BuildKit cảnh báo
# SecretsUsedInArgOrEnv: dương tính giả — giá trị là một đường dẫn, không phải secret.
COPY --from=blocklist /out/mg/ /opt/keycloak/mg/
ENV KC_SPI_PASSWORD_POLICY__PASSWORD_BLACKLIST__BLACKLISTS_PATH=/opt/keycloak/mg/password-blacklists
USER 1000
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
