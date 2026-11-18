# internal

Module Go của Management Plane (§4.2): identity, idp (IdP driver `keycloak`/`external` + HTTP client chống SSRF — P2-T05a), authz, tenants, platform, headscale (adapter — ranh giới duy nhất tới Headscale, §13.4), provisioning, devices, enrollment, policies (lõi áp dụng HuJSON — P3-T08a), network, relay (RelayService + job `relay.probe` — P3-T05c), usage, audit, secrets, monitoring, notifications (outbox + job `notification.send` + SMTP — P3-T05b), store, jobs, httpapi. Bắt đầu ở Phase 2.
