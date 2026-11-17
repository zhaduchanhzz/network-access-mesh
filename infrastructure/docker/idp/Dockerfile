# Image IdP của MeshGuard (P2-T05, §8.2, §14.4): Keycloak 26.8.2 đã build tối ưu ("optimized server image" — tài liệu
# "Running Keycloak in a container" của Keycloak). Tùy chọn build-time được nướng sẵn để container chạy
# `start --optimized` với rootfs CHỈ ĐỌC: image gốc thấy tùy chọn build khác mặc định (db=postgres, health, metrics,
# feature) thì tự build lại lúc khởi động và ghi vào /opt/keycloak/lib/quarkus — cần rootfs ghi được.
# Không thêm gói, provider hay theme nào: so với base chỉ khác thư mục `kc.sh build` sinh ra và kho CA của JVM đã gỡ
# một root (stage truststore — CVE-2026-91403).
# Base pin theo digest (versions.lock [images.keycloak]); tag 26.8.2 trên quay.io đã bị push lại khi rebuild base.
ARG KEYCLOAK=quay.io/keycloak/keycloak:26.8.2@sha256:c68e286cacd87b942ac1939a0a1481461109d6acd3a57dc496969a319a76bbf0

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

FROM ${KEYCLOAK}
COPY --from=build /opt/keycloak/lib/quarkus/ /opt/keycloak/lib/quarkus/
COPY --from=truststore /etc/pki/ca-trust/extracted/java/cacerts /etc/pki/ca-trust/extracted/java/cacerts
USER 1000
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
