# Image IdP của MeshGuard (P2-T05, §8.2, §14.4): Keycloak 26.8.2 đã build tối ưu ("optimized server image" — tài liệu
# "Running Keycloak in a container" của Keycloak). Tùy chọn build-time được nướng sẵn để container chạy
# `start --optimized` với rootfs CHỈ ĐỌC: image gốc thấy tùy chọn build khác mặc định (db=postgres, health, metrics,
# feature) thì tự build lại lúc khởi động và ghi vào /opt/keycloak/lib/quarkus — cần rootfs ghi được.
# Không thêm gói, provider hay theme nào: chỉ chạy `kc.sh build`, rồi chép đúng thư mục nó sinh ra.
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

FROM ${KEYCLOAK}
COPY --from=build /opt/keycloak/lib/quarkus/ /opt/keycloak/lib/quarkus/
USER 1000
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
