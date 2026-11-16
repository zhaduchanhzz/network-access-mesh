# Research Evidence — D

> Một phần của [nhật ký bằng chứng nghiên cứu](../research-evidence.md) (P0-T08). Chép nguyên từ kết quả của research agent ngày 2026-11-16; nhận định và trích dẫn giữ nguyên tiếng Anh.

## D - Repository OwnDing/headscale-saas (Headscale 'clustering' via cluster_id, shared PostgreSQL, binary-only image archive) assessed against upstream Headscale v0.26.1 and v0.29.7

**Tóm tắt của agent:** Decision: use OwnDing/headscale-saas as reading material only. Do not download, load, run, redistribute or depend on h.tar. What it is. A single-day repository (four commits within about ten minutes on 2025-10-03; unchanged for 409 days) holding a bilingual README, an example config, an nginx-only compose file, an nginx config and an 88.6 MB binary image archive. There is no source, Dockerfile, go.mod, release, checksum, LICENSE or CONTRIBUTING file, and the owner's 27 public repositories contain no Headscale fork. The README's MIT badge points at a missing file and no readable file reproduces upstream's BSD-3-Clause notice. What it claims. Several Headscale processes, each with a unique cluster_id, share one PostgreSQL; an Admission/Control Service (a diagram box only) assigns new tenants to a node and clients then stick to it; 'unlimited devices' and 'high availability'. The only non-upstream config key is cluster_id ('all database records written by this instance will be tagged with this value'); the config is upstream's v0.26.x example with value edits. The shipped nginx.conf does no load balancing: two ports map one-to-one to two instances on one host over plain HTTP. No failover behaviour is described. How to read it. Per the README and the author's own blog, cluster_id is a shard identifier: N independent control planes separated by a discriminator column in one database, not active-active serving of one tailnet. That is cluster isolation. The repository states no security boundary between tenants and nothing about per-tenant netmaps, keys, policy, DNS or DERP; such claims appear only in a later blog post about a different, unpublished single-instance modification. None of it is verifiable without source. Against upstream. Headscale v0.29.7 scopes itself to a single tailnet, recommends SQLite, calls PostgreSQL maintenance-mode and 'highly discouraged', and its maintainers answer multi-replica requests with 'The short answer is no' (not-planned). Node state, IP allocation, pending authentication, registration locks, policy, route election and client streams live in per-process memory, so 'load-balance to any node' would need deep changes that cannot be confirmed. The presumed v0.26.x base is three minor lines and eleven releases behind, missing the 0.29.7 security release. What to keep (concepts only). (1) An admission/placement function in our Go backend: quota, region and load decide the instance, and the portal hands out a per-tenant login-server URL and pre-auth key. (2) An immutable instance identifier in our registry, stamped on logs and audit records. (3) Stickiness by construction: one hostname per tenant routed by Caddy to exactly one Headscale process. (4) Availability through fast restore and relocation of a tenant's whole data directory, as upstream's maintainer recommends, rather than active-active. Our planned one-tenant-one-instance model with per-instance SQLite already delivers shard-style horizontal scaling with a stronger isolation boundary than a shared database, and it needs no Headscale patching.

## Nhận định

### D-01 · `VERIFIED` — README headline claims

- **Nhận định:** README presents the project as a modified, 'multi-tenant, horizontally scalable' Headscale that achieves 'unlimited device support' and 'highly available SaaS capability' by adding a clustered architecture and shared PostgreSQL storage. No measurement, test result or design detail accompanies these headline claims.
- **Bằng chứng:** README 概述: 「通过引入集群化架构和 PostgreSQL 共享存储，我们实现了 无限设备支持能力 和 高可用性 SaaS 服务能力」 = 'by introducing a clustered architecture and shared PostgreSQL storage we achieved unlimited device support and highly available SaaS capability'.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/README.md

### D-02 · `VERIFIED` · *critical* — cluster_id meaning (README)

- **Nhận định:** In the README, cluster_id is unique per Headscale node (clusterID=A/B/C), so it names a shard or instance, not a group of replicas. It is set in config and used for identity, conflict avoidance, log tracing, auditing and 'future policy control', i.e. policy enforcement by cluster_id is presented as future work.
- **Bằng chứng:** 「每个 headscale 节点拥有唯一 cluster_id，用于标识其在集群中的身份，避免资源冲突」 (each node has a unique cluster_id identifying it in the cluster, avoiding resource conflicts); 「用于日志追踪、审计及未来策略控制」 (for log tracing, auditing and future policy control).
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/README.md

### D-03 · `VERIFIED` · *critical* — cluster_id semantics (config.yaml)

- **Nhận định:** config.yaml's only technical statement about cluster_id is that every database record written by an instance is tagged with that value (example: integer 1). It does not say reads are filtered, nor how uniqueness, IP allocation or policy are scoped.
- **Bằng chứng:** config.yaml L15-17: '# Cluster identifier used for multi-cluster deployments. # All database records written by this instance will be tagged with this value. cluster_id: 1'.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/config.yaml

### D-04 · `VERIFIED` · *critical* — Shared PostgreSQL (README)

- **Nhận định:** README states that all Headscale nodes connect to one highly available PostgreSQL cluster holding users, nodes and keys 'with a cluster_id dimension'. Prerequisites name PostgreSQL 13+ and recommend a clustered setup such as Patroni + HAProxy.
- **Bằng chứng:** 「所有 headscale 节点共享同一个 PostgreSQL 集群，确保用户、节点、密钥等数据一致性」 (all nodes share one PostgreSQL cluster, ensuring consistency of users, nodes, keys); diagram 「共享 PG/PG 集群 (带 cluster_id 维度)」; 「PostgreSQL 13+（推荐集群模式，如 Patroni + HAProxy）」.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/README.md

### D-05 · `VERIFIED` · *critical* — Admission/Control Service (ACS)

- **Nhận định:** The 'Admission/Control Service' (接入控制程序, ACS) exists only as a README diagram plus three lines of prose: it takes register/login/scale-out and admin-API/billing/quota inputs, chooses an available clusterID and returns node address, clusterID and registration info. No ACS code, API, image or configuration is published.
- **Bằng chứng:** 「Client 在首次接入时 -> 请求 ACS -> 获得 “可用 headscale 节点地址 + clusterID + 注册信息”」 (on first join the client asks the ACS and receives an available node address + clusterID + registration info). Inventory at the pinned commit: README.md, config.yaml, docker-compose.yml, nginx.conf, h.tar, images only.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/README.md

### D-06 · `VERIFIED` · *critical* — Stickiness and tenant placement (README)

- **Nhận định:** README says that after first join all client interaction goes directly to the assigned node ('sticky'), and that new tenants are assigned to nodes by the ACS during scale-out. This describes placement of tenants onto individual nodes, not one tenant served by several nodes.
- **Bằng chứng:** 「之后所有交互都直连对应节点（黏住），横向扩容时通过 ACS 做新租户的分配」 = 'afterwards all interaction goes directly to that node (sticky); during horizontal scale-out new tenants are assigned via the ACS'.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/README.md

### D-07 · `VERIFIED` · *critical* — Load-balancing claim (README)

- **Nhận định:** README contradicts its own sticky model: one bullet says device registration is distributed by a load balancer 'to any node', with consistency from 'database locks and state synchronisation' (the English text says 'DB-level locking and atomic operations'). No mechanism, schema or protocol is described.
- **Bằng chứng:** 「设备注册时由负载均衡器分发到任意节点，通过数据库锁与状态同步保证一致性」; step 4: 「使用 Nginx 或 Traefik 做前端负载均衡，将请求分发至不同 cluster 节点」 (use Nginx or Traefik as front-end load balancer distributing requests to different cluster nodes).
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/README.md

### D-08 · `UNSUPPORTED` · *critical* — Failover behaviour

- **Nhận định:** The repository describes no failover for Headscale nodes. 'High availability' appears only as a headline capability and as a property of the recommended PostgreSQL cluster. Nothing states what clients of a failed node do or whether another node can take over its cluster_id.
- **Bằng chứng:** README read in full in both languages: only 「高可用性 SaaS 服务能力」 (HA SaaS capability) and 「同一个高可用 PostgreSQL 集群」 (one HA PostgreSQL cluster). No failover, takeover, health-check or replica section; nginx.conf has no backup upstream.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/README.md

### D-09 · `VERIFIED` — Numbers, roadmap, contact (README)

- **Nhận định:** README gives no capacity, latency or benchmark figure, only 'unlimited' and 'theoretically unlimited devices', PostgreSQL 13+, Go 1.24+ and ports 8080/9090/50443. It has no roadmap and no contact, pricing or support channel beyond inviting issues and pull requests. 'Production-ready' and multi-region deployment appear only in the English half.
- **Bằng chứng:** 「理论上支持无限数量的设备」 (theoretically supports an unlimited number of devices); English half: 'production-ready Tailscale Control Plane SaaS', 'Deploy multiple headscale nodes across regions or data centers'; 「欢迎提交 Issue 或 Pull Request」.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/README.md

### D-10 · `VERIFIED` — Commercial context (outside the repository)

- **Nhận định:** Commercial intent is visible only at the edges: the README's ACS box lists 'billing/quotas', and the same owner's later documentation repository presents a closed SaaS remote-access product built by retrofitting Headscale for tenants, alongside a fork of the Tailscale Android client.
- **Bằng chứng:** README diagram: 「管理API/计费/配额」 (admin API/billing/quotas). Owner's docs blog 2026-04-24: 「我对 headscale 做了 SaaS 化改造」 (I retrofitted headscale for SaaS). Owner repository list includes a fork of tailscale/tailscale-android.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/larktun-docs/665cc67fe0398cb316774f07628c66da0f6c4c01/blog/2026-04-24-what-is-larktun.mdx ; https://github.com/OwnDing?tab=repositories

### D-11 · `VERIFIED` · *critical* — Non-upstream config keys

- **Nhận định:** The only key in config.yaml that does not exist in upstream Headscale is top-level `cluster_id`. There are no keys for peer membership, inter-node messaging, leader election, an ACS endpoint or tenant definitions: the entire cluster configuration is one integer.
- **Bằng chứng:** diff of config.yaml against upstream v0.26.1 config-example.yaml: the only added key is `cluster_id: 1` (L15-17). grep -i 'cluster' on upstream hscontrol/types/config.go and config-example.yaml at v0.26.1, v0.27.1 and v0.29.7 returns no match.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/config.yaml ; https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/types/config.go

### D-12 · `VERIFIED` · *critical* — Upstream base of config.yaml

- **Nhận định:** config.yaml is upstream's v0.26.x example file: it matches v0.26.0/v0.26.1 config-example.yaml (identical at both tags) line for line apart from value edits and the cluster_id block. It differs in keys from v0.25.1 (map_legacy_users, no override_local_dns) and v0.27.1 (derp.server.verify_clients).
- **Bằng chứng:** diff vs v0.26.1 shows only value changes (server_url, listen addresses, derp ipv4/ipv6, derp.paths, database.type, postgres block, policy.mode, extra_records, unix_socket, randomize_client_port) plus cluster_id. diff v0.26.0 vs v0.26.1 is empty. diffs vs v0.25.1 and v0.27.1 show key and comment differences.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.26.1/config-example.yaml

### D-13 · `ASSUMED` · *critical* — Upstream base of the binary

- **Nhận định:** The binary in h.tar is most likely built from v0.26.1-based source: README requires Go 1.24+ (v0.26.1 go.mod says go 1.24.0), the repository predates v0.27.0, and the author's build posts use tag v0.26.1 and show an 87.5 MB image. This is unconfirmed because the archive was not inspected.
- **Bằng chứng:** v0.26.1 go.mod L3 'go 1.24.0'; upstream CHANGELOG '## 0.27.0 (2025-10-27)' versus repository date 2025-10-03; owner's blog 2025-08-08 image list: 'headscale v0.26.1-r ... 87.5MB'; h.tar is 88,599,552 bytes.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/larktun-docs/665cc67fe0398cb316774f07628c66da0f6c4c01/blog/2025-08-08-headscale-source-build-docker-image.mdx ; https://raw.githubusercontent.com/juanfont/headscale/v0.26.1/go.mod

### D-14 · `VERIFIED` — Example config security posture

- **Nhận định:** The example config selects PostgreSQL directly beneath upstream's own warning that Postgres is 'highly discouraged', connects as user `postgres` with password `password` and ssl false, binds HTTP, metrics/debug and gRPC to 0.0.0.0, uses a plain-HTTP server_url on a bare IP and port, and leaves embedded DERP disabled.
- **Bằng chứng:** config.yaml L13 (http server_url), L23, L27, L37 (0.0.0.0 listeners), L81 (`enabled: false`), L142-144 ('using Postgres is highly discouraged as it is only supported for legacy reasons' then `type: postgres`), L184-185 and L192 (`user: postgres`, `pass: password`, `ssl: false`).
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/config.yaml

### D-15 · `VERIFIED` — docker-compose.yml and run command

- **Nhận định:** docker-compose.yml defines one service, `headscale-nginx` (nginx 1.26.2 from a registry addressed by a bare public IP and port 5080), ports 8081/8082, a bind-mounted nginx.conf and restart always. It has no Headscale, PostgreSQL, replicas or healthchecks. Headscale is started by a README `docker run` of `headscale:c1` loaded from h.tar.
- **Bằng chứng:** docker-compose.yml (250 bytes, version '3.7'): `image: <public-IP>:5080/library/nginx:1.26.2`, ports '8081:8081' and '8082:8082'. README step 3: `docker load -i h.tar` then `docker run -d --name headscale -p 8080:8080 -p 9090:9090 -p 50443:50443 ... headscale:c1 serve`.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/docker-compose.yml

### D-16 · `VERIFIED` · *critical* — nginx.conf load balancing and upstream list

- **Nhận định:** nginx.conf has no `upstream` block and no balancing or stickiness directive (no ip_hash, least_conn, hash or sticky). Two `server` blocks on ports 8081 and 8082 each proxy to one fixed backend on the same private host that also runs PostgreSQL: a two-instance, single-host, port-per-instance demo.
- **Bằng chứng:** nginx.conf: `listen 8081;` with `proxy_pass http://10.0.16.7:8080;` and `listen 8082;` with `proxy_pass http://10.0.16.7:7080;`. config.yaml L181: postgres `host: 10.0.16.7`.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/nginx.conf

### D-17 · `VERIFIED` — nginx.conf upgrade handling, timeouts, TLS

- **Nhận định:** nginx.conf forwards `Upgrade $http_upgrade` with a hard-coded `Connection upgrade` over HTTP/1.1 with buffering off; upstream's community example uses a map instead. It sets no proxy read or send timeout (nginx default 60s; v0.26.1 keepalives every 50–59s), terminates no TLS yet adds an HSTS header, and blocks only /swagger.
- **Bằng chứng:** nginx.conf location /: `proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection 'upgrade'; proxy_buffering off;`; no ssl_* or proxy_read_timeout directives. nginx docs: `proxy_read_timeout 60s;`. v0.26.1 hscontrol/poll.go L23 and L72: `keepAliveInterval = 50 * time.Second` plus up to 9000 ms jitter.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/nginx.conf ; https://raw.githubusercontent.com/juanfont/headscale/v0.26.1/docs/ref/integration/reverse-proxy.md ; https://nginx.org/en/docs/http/ngx_http_proxy_module.html

### D-18 · `VERIFIED` · *critical* — Source availability in the repository

- **Nhận định:** The repository contains no source code, Dockerfile, go.mod, patch, build script, checksum or release. The modified Headscale is published only as the binary image archive h.tar, although the README step is titled 'build and run' and lists Go 1.24+ as a prerequisite.
- **Bằng chứng:** Inventory at commit 25778c3: README.md, config.yaml, docker-compose.yml, nginx.conf, h.tar, images/*.png. Raw fetches of Dockerfile, go.mod, LICENSE and CONTRIBUTING.md at that commit return 404. README: 「3. 构建并运行」 (build and run) followed by `docker load -i h.tar`.
- **Nguồn:** https://github.com/OwnDing/headscale-saas/tree/25778c3e8ded3976e460cc88954383651e7b357e

### D-19 · `VERIFIED` · *critical* — Source availability elsewhere

- **Nhận định:** The owner's 27 public repositories include no fork of upstream Headscale and none holding the modified source. Headscale-related ones are load-test scripts, a Java API wrapper, a fork of a third-party admin UI and a Tailscale Android fork. Generic web searches surfaced only the README and a mirror of it.
- **Bằng chứng:** Owner repository list HTML: 27 repository names, no pagination; fork origins shown are GoodiesHQ/headscale-admin, tailscale/tailscale-android and six unrelated projects; the single 'juanfont/headscale' string on the page is in the admin-UI description.
- **Nguồn:** https://github.com/OwnDing?tab=repositories

### D-20 · `VERIFIED` — Repository history and activity

- **Nhận định:** The repository's whole history is four commits by one account within about ten minutes on 2025-10-03 ('first commit' plus three 'readme' commits). It shows 5 stars and no issues or releases, and has not changed in the 409 days to 2026-11-16.
- **Bằng chứng:** Commits feed for 25778c3: four entries timestamped 2025-10-03T13:25:00Z to 13:34:46Z, author OwnDing. Repository page HTML: 'commitCount':'4', '<strong>5</strong> stars'. Issues page: 0 results (commit messages and issue count read through the summarising fetch tool).
- **Nguồn:** https://github.com/OwnDing/headscale-saas/commits/25778c3e8ded3976e460cc88954383651e7b357e.atom

### D-21 · `VERIFIED` — Licence statements in the repository

- **Nhận định:** README shows an MIT badge, says 'MIT License – see LICENSE' and links a CONTRIBUTING.md, but neither file exists at the pinned commit. No licence text, copyright holder or year is published for the author's modifications or for the binary.
- **Bằng chứng:** README: 「MIT License - 查看 \[LICENSE\](LICENSE) 获取详情」. Raw fetches of LICENSE, LICENSE.md, LICENSE.txt, COPYING, NOTICE and CONTRIBUTING.md at commit 25778c3 all return 404.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/README.md

### D-22 · `VERIFIED` — Upstream licence obligations

- **Nhận định:** Upstream Headscale is BSD-3-Clause ('Copyright (c) 2020, Juan Font'). Redistributing a modified binary is permitted without publishing source, but the copyright notice, conditions and disclaimer must be reproduced in documentation or other materials shipped with it, and upstream names may not be used for endorsement.
- **Bằng chứng:** LICENSE, identical at v0.26.1 and v0.29.7: '2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.'
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/LICENSE

### D-23 · `REQUIRES_VALIDATION` — Licence compliance of the published artefact

- **Nhận định:** None of the four readable files reproduces upstream's BSD notice, and the archive could not be checked. With an MIT claim lacking any licence text and unknown notices for bundled Go dependencies, the right to use or redistribute h.tar is legally unclear; default copyright applies to the author's changes.
- **Bằng chứng:** README.md, config.yaml, docker-compose.yml and nginx.conf read in full: no 'Copyright (c) 2020, Juan Font' or BSD text. Validation needed: legal review, plus an offline file listing of the image by someone permitted to inspect it (prohibited in this research).
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/README.md

### D-24 · `VERIFIED` · *critical* — Upstream scope: single tailnet

- **Nhận định:** Upstream Headscale v0.29.7 defines its scope as one tailnet per server for self-hosters and hobbyists. Neither its README, its FAQ nor its feature list offers multi-tenancy, multiple tailnets or control-plane clustering.
- **Bằng chứng:** docs/about/faq.md L5-10 and README.md L39-44: 'It implements a narrow scope, a _single_ Tailscale network (tailnet), suitable for a personal use, or a small open-source organisation.' features.md (45 lines, read in full) lists no such feature.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/about/faq.md

### D-25 · `VERIFIED` · *critical* — Upstream PostgreSQL status

- **Nhận định:** Upstream recommends SQLite and keeps PostgreSQL only in 'maintenance mode'. Its example config calls Postgres 'highly discouraged' and 'only supported for legacy reasons', and the FAQ says the choice of database has 'little to no impact' on server performance.
- **Bằng chứng:** faq.md L113-124: 'PostgreSQL is still supported, but is considered to be in "maintenance mode"'. config-example.yaml L196-197: 'using Postgres is highly discouraged as it is only supported for legacy reasons. All new development, testing and optimisations are done with SQLite in mind.'
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/about/faq.md ; https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/config-example.yaml

### D-26 · `UNSUPPORTED` · *critical* — Unlimited-scale claim versus upstream

- **Nhận định:** The 'unlimited devices' claim cannot hold for one tailnet: upstream locates the bottleneck in CPU-bound recomputation of a per-tailnet 'world map' for every node on each change, not in the database. Scale can only come from splitting devices into separate netmaps, each bounded by single-process limits.
- **Bằng chứng:** faq.md L83-90: 'creating this "world map" requires a lot of CPU time. When an event that requires changes to this map happens, the whole "world" is recalculated, and a new "world map" is created for every node in the network.' The author's only public test harness simulates about 200 clients against one server.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/about/faq.md ; https://raw.githubusercontent.com/OwnDing/headscale-test-scripts/efcf3a84ab279915a4331149e1fa960b39a96e1d/README.md

### D-27 · `VERIFIED` · *critical* — Upstream stance on multiple instances and HA

- **Nhận định:** Upstream does not support or plan several Headscale processes for one deployment. The 2025 request for multiple replicas is labelled not-planned and answered 'The short answer is no' (split-brain, harder recovery). In 2021 the project owner noted that multiple instances would need cross-instance notification of long-polling clients.
- **Bằng chứng:** Issue #2695, kradalby (COLLABORATOR), 2025-07-23: 'The short answer is no. ... you now need to ensure you have multiple replicas, databases, there might be split brain issues, recovery becomes harder.' Issue #100, juanfont (OWNER), 2021-09-03: 'we would need a mechanism to have cross-headscale communication to notify the peers polling in different instances'.
- **Nguồn:** https://github.com/juanfont/headscale/issues/2695 ; https://github.com/juanfont/headscale/issues/100

### D-28 · `VERIFIED` · *critical* — Upstream recovery guidance

- **Nhận định:** Upstream's maintainer recommends fast recovery instead of HA: clients keep working from their current map through a 5–10 minute, even one-hour, control-plane outage if the network shape is stable. Minimum recovery is re-pointing DNS or a virtual IP, restoring the SQLite database and config, and starting Headscale.
- **Bằng chứng:** Issue #2695 maintainer comment: 'instead of a HA setup, you can easier focus on a much simpler "how quickly can I recover or replace my server?" setup ... DNS or Virtual IP, point to a new VM - Restore SQLite database and config from backup - Install Headscale and start it up'.
- **Nguồn:** https://github.com/juanfont/headscale/issues/2695

### D-29 · `VERIFIED` · *critical* — Single-process state in the fork's base (v0.26.1)

- **Nhận định:** In upstream v0.26.1, the fork's presumed base, each process keeps in memory the notifier's node channels and connected map, a singleton IP allocator, primary-route election, a 15-minute registration cache, the policy manager and ephemeral-node timers. Peer online status and map-update fan-out come from the local notifier only.
- **Bằng chứng:** hscontrol/app.go `type Headscale struct` fields ipAlloc, ephemeralGC, polMan, primaryRoutes, nodeNotifier, registrationCache; mapper/mapper.go L506 `online := m.notif.IsLikelyConnected(peer.ID)`; db/ip.go: 'IPAllocator is a singleton ... There can only be one'; CHANGELOG 0.26.0: route state 'is now only kept in memory'.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.26.1/hscontrol/app.go ; https://raw.githubusercontent.com/juanfont/headscale/v0.26.1/hscontrol/db/ip.go

### D-30 · `VERIFIED` · *critical* — Single-process state in current upstream (v0.29.7)

- **Nhận định:** In v0.29.7 an in-memory copy-on-write NodeStore, loaded once at startup, is the source of truth for nodes, and the database is made to converge on it. Pending authentication requests, per-machine registration locks, SSH-check approvals, ping tracking, IP allocation and the connection batcher are likewise process-local.
- **Bằng chứng:** hscontrol/state/state.go State struct: 'persistMu serialises node-row persistence and deletion so the database always converges on [NodeStore]'; node_store.go Snapshot: 'nodesByID is the main source of truth for nodes'; mapper/batcher.go: `nodes *xsync.Map[types.NodeID, *multiChannelNodeConn]`.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/state/state.go ; https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/state/node_store.go ; https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/mapper/batcher.go

### D-31 · `VERIFIED` · *critical* — Database-level coordination in upstream

- **Nhận định:** Upstream's database layer contains no row locks, advisory locks, LISTEN/NOTIFY or serializable transactions at v0.26.1 or v0.29.7, and policy is one global series in which the latest row wins. The README's 'database locks and state synchronisation' would therefore be entirely fork-specific code, which is unpublished.
- **Bằng chứng:** grep for clause.Locking, FOR UPDATE, advisory, LISTEN, NOTIFY, SERIALIZABLE in hscontrol/db/{db,node,users,preauth_keys,api_key,ip,policy}.go at both tags: no code matches. v0.26.1 db/policy.go: 'SELECT * FROM policies ORDER BY id DESC LIMIT 1;'. grpcv1.go SetPolicy updates the local polMan and calls nodeNotifier.NotifyAll.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.26.1/hscontrol/db/policy.go ; https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/db.go

### D-32 · `REQUIRES_VALIDATION` · *critical* — Author's description of the design (blog, vendor claim)

- **Nhận định:** The author's own blog post of 2025-10-01 calls the design cluster_id 'logical sharding': each node bound to one cluster_id, a shared database whose queries must include cluster_id, and nodes consuming only their own cluster's events. PostgreSQL LISTEN/NOTIFY for incremental netmaps is presented as an approach, with snippets that do not match the published config.
- **Bằng chứng:** 「多个 headscale 节点并行运行，每个节点绑定独立 cluster_id。所有节点共享数据库，但查询必须显式包含 cluster_id」; snippet `ADD COLUMN cluster_id TEXT NOT NULL DEFAULT 'default'` versus config `cluster_id: 1`. Vendor text with no source to check against.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/larktun-docs/665cc67fe0398cb316774f07628c66da0f6c4c01/blog/2025-10-01-headscale-cluster-infinite-scale.mdx

### D-33 · `REQUIRES_VALIDATION` — Author's tenant routing and migration claims (blog, vendor claim)

- **Nhận định:** A later post (2025-10-25) describes per-user domains routed by Traefik to the owning Headscale node, and manual migration between nodes: move rows, change cluster_id, switch the route, kill old TCP connections. It claims under 15s in total and 1–5s of client interruption with almost no re-authentication; its commands are not literally valid.
- **Bằng chứng:** 「迁移总时长：通常小于 15 秒 / 客户端中断：通常 1-5 秒 / 重新认证率：接近 0%」. The post uses `pg_dump ... --where=...`; the PostgreSQL pg_dump reference contains no `--where` option. Test: relocate one of our instances and measure client reconnect.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/larktun-docs/665cc67fe0398cb316774f07628c66da0f6c4c01/blog/2025-10-25-headscale-saas-seamless-user-switch.mdx ; https://www.postgresql.org/docs/current/app-pgdump.html

### D-34 · `REQUIRES_VALIDATION` · *critical* — Tenant and tailnet isolation claims (later blog, different modification)

- **Nhận định:** Per-tenant tailnet address pools, ACLs, routes, MagicDNS namespaces (hostname.<tenant_key>.<base_domain>), a CLI tenant flag and optional dedicated relays are claimed only in a 2026-04-22 post about a different modification inside a single Headscale instance. None of it is in this repository or published as source.
- **Bằng chứng:** 「这篇文章展示在单实例 headscale 中实现多租户隔离的改造结果」 (shows multi-tenant isolation implemented within a single headscale instance); 「每个租户独立 tailnet」 (each tenant has its own tailnet). The researched repository was last pushed 2025-10-03.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/larktun-docs/665cc67fe0398cb316774f07628c66da0f6c4c01/blog/2026-04-22-headscale-multi-tenant-isolation.mdx

### D-35 · `VERIFIED` · *critical* — Which isolation the repository claims

- **Nhận định:** The repository claims cluster isolation only: 'cluster_id isolation' means a unique identity per instance and tagging of written rows. It uses 'multi-tenant' as a label and mentions tenant placement, but states no security boundary between customers and nothing about separate netmaps, keys, policy, DNS or DERP maps per tenant.
- **Bằng chứng:** README read in full: 「cluster_id 隔离机制」 is the only isolation statement; 'tenant' appears only in 「多租户」 (multi-tenant) and 「新租户的分配」 (assignment of new tenants). config.yaml has one policy block, one dns.base_domain and one derp section per instance.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/README.md

### D-36 · `REQUIRES_VALIDATION` · *critical* — Verifiability of isolation claims

- **Nhận định:** No isolation claim can be verified without source. Whether reads, unique constraints, IP allocation, policy rows, API keys and pre-auth keys are scoped by cluster_id could only be established by black-box testing of the unauditable binary. The config key alone proves nothing, since an unmodified build would probably ignore it.
- **Bằng chứng:** Test (not permitted here): run two instances with different cluster_id on one PostgreSQL in an isolated lab, inspect the schema, and attempt cross-cluster listing, registration and API-key use. v0.26.1 hscontrol/types/config.go uses viper.ReadInConfig (L336); no strict unknown-key handling was found by grep.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.26.1/hscontrol/types/config.go

### D-37 · `ASSUMED` · *critical* — Trust boundary of a shared database

- **Nhận định:** With one shared database, every instance holds credentials that can read all shards' rows (the example uses the `postgres` superuser). cluster_id is therefore at most a logical partition inside one trust domain, weaker than a separate database and key set per tenant.
- **Bằng chứng:** Inference from config.yaml L179-185 (a single postgres block with `user: postgres`) and README 「所有 headscale 节点共享同一个 PostgreSQL 集群」. No per-cluster roles, schemas or row-level security are mentioned anywhere in the repository.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/config.yaml

### D-38 · `VERIFIED` · *critical* — Risk of the binary archive

- **Nhận định:** h.tar is an 88.6 MB image archive with no source, Dockerfile, SBOM, digest, signature or provenance. The README instructs loading it and running it with the HTTP, metrics/debug and gRPC ports published. Its contents cannot be audited by reading, and it was not downloaded for this research.
- **Bằng chứng:** Inventory: h.tar 88,599,552 bytes. README contains no checksum or signature; step 3: `docker load -i h.tar` and `-p 8080:8080 -p 9090:9090 -p 50443:50443`.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/README.md

### D-39 · `VERIFIED` · *critical* — Staleness relative to v0.29.7

- **Nhận định:** A v0.26.x base is three minor lines and eleven upstream releases behind v0.29.7. It misses the 0.29.7 security release, the 0.29.6 Go and dependency vulnerability rebuild, 0.29.3 registration hardening and 0.28.0 hashed pre-auth keys. Upstream requires sequential minor upgrades and now supports clients from v1.80.0.
- **Bằng chứng:** CHANGELOG at v0.29.7: '## 0.29.7 (2026-10-30) ... This is a security release'; 'Minimum supported Tailscale client version: v1.80.0'; 0.28.0: 'Pre-authentication keys now use bcrypt hashing'. faq.md L52-54: update 'without skipping minor versions in between'.
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/CHANGELOG.md

### D-40 · `ASSUMED` — Ideas worth keeping

- **Nhận định:** Three ideas are worth keeping as concepts for our own backend: an admission/placement service that picks an instance per new tenant from quota, region and load; an immutable instance identifier in a central registry, stamped on logs and audit records; and routing each tenant to exactly one control-plane instance.
- **Bằng chứng:** Our synthesis from the README diagram (ACS: 「选择可用 clusterID」; 「管理API/计费/配额」), the logging/audit use of cluster_id and the sticky client model; the author's blog adds 「区域与负载选择」 (region and load selection). Nothing is reusable as code.
- **Nguồn:** https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/README.md

### D-41 · `VERIFIED` — Upstream stance on reverse proxies and containers

- **Nhận định:** Upstream says it does not support or encourage reverse proxies or containers for Headscale, and its reverse-proxy page is community-maintained. A proxy must pass an HTTP upgrade made with POST and `Upgrade: tailscale-control-protocol`; gRPC 'may not be proxied'; v0.29.7 honours forwarded client-IP headers only from configured `trusted_proxies`.
- **Bằng chứng:** README.md L61-62: 'we do not support nor encourage the use of reverse proxies and container to run Headscale'. docs/ref/integration/reverse-proxy.md L27-32 (POST upgrade, header value), L50-52 (trusted_proxies), L72 (gRPC may not be proxied).
- **Nguồn:** https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/integration/reverse-proxy.md ; https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/README.md

## Hệ quả thiết kế (agent đề xuất)

- Do not download, load, run, redistribute or depend on h.tar or this repository. Cite it only as a concept reference and use official upstream release artefacts pinned by digest.
- Keep one tenant = one Headscale process with its own SQLite, noise and DERP keys, policy, DNS and DERP configuration. Never point two Headscale processes at one database or data directory. PostgreSQL is for the central backend only.
- Build the admission function as a placement/provisioning module in the Go backend: a registry mapping tenant to instance to host to server URL, quota and billing checks, capacity- and region-aware host selection, and issuing a per-tenant login-server URL and pre-auth key through the portal. Official Tailscale clients cannot query an admission service, so onboarding is out-of-band.
- Make stickiness structural: one FQDN per tenant, routed by Caddy to exactly one upstream. No balancing policy across Headscale instances, and no ip_hash or cookie affinity is needed.
- Give every instance an immutable instance_id in the registry and stamp it on container labels, logs, metrics and audit events. This is the useful part of cluster_id and needs no Headscale patch.
- Treat availability as fast recovery and relocation, not active-active: back up and restore the SQLite database, noise key, DERP key and config together, re-point Caddy or DNS, restart, and measure the recovery time. Moving the whole data directory preserves the server's identity.
- Edge requirements for Caddy: HTTPS on 443 with an https server_url, pass the POST-based upgrade with `Upgrade: tailscale-control-protocol`, no response buffering, no read or idle timeout shorter than the roughly 60-second keepalive cadence, UDP 3478 published directly for STUN, gRPC not proxied (use the REST API or a private socket), metrics/debug listener private, and `trusted_proxies` set to the proxy address.
- Plan fleet upgrade tooling from the start: upstream requires stepping through every minor release and ships frequent security fixes. A private fork would freeze us at its base, as this fork is frozen at v0.26.x.
- Capacity planning is per instance and per host (CPU for netmap recomputation inside each tailnet), not per database.
- Keep the standard CGNAT and ULA prefixes for every tenant. Overlapping 100.64.0.0/10 across tenants is acceptable because each tenant is a separate tailnet; custom non-CGNAT pools are unsupported upstream.
- Licence hygiene for our own distribution: ship upstream's BSD-3-Clause notice (and dependency notices) with any Headscale image or binary we distribute, and keep any future patches in an auditable repository.
- Do not copy the example's settings: no database superuser or default passwords, no metrics or gRPC on 0.0.0.0, no plain HTTP control URL, no images from unknown registries.

## Câu hỏi mở

- How many idle and active Headscale v0.29.7 instances fit on one Ubuntu host? Measure memory and CPU per instance at roughly 10, 100 and 500 nodes with churn; a harness of containerised clients with periodic up/down, as the author's test scripts describe, is a pattern we can re-implement.
- What is the measured recovery and relocation time for one tenant instance, and how do Tailscale v1.104.7 clients behave when the instance restarts or moves host (reconnect delay, any forced re-authentication)?
- Does Caddy pass the POST-based `tailscale-control-protocol` upgrade and long-lived map streams without extra configuration, and which timeouts need raising? Needs a hands-on test.
- What happens when the edge routes a tenant hostname to the wrong or a fresh instance with a different noise key? Test this failure mode to define routing guardrails.
- Is a warm standby per tenant (replicated SQLite with a stopped second process) worth building given upstream's refusal of multi-replica operation, and how would single-writer fencing be enforced?
- Which signals (node count, churn, CPU) drive placement and rebalancing across hosts, and how is a host drained?
- Legal confirmation that referencing concepts from this repository carries no obligation, and that our own packaging reproduces the BSD-3-Clause notice correctly.
- The screenshots in images/ and the contents of h.tar were not inspected by rule, so whether they show cluster_id columns, an image tag or licence files remains unknown. Low value; no action recommended.

## Nguồn đã đọc

- https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/README.md (full)
- https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/config.yaml (full, 395 lines)
- https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/docker-compose.yml (full)
- https://raw.githubusercontent.com/OwnDing/headscale-saas/25778c3e8ded3976e460cc88954383651e7b357e/nginx.conf (full)
- https://github.com/OwnDing/headscale-saas (page HTML counters), /tree/25778c3e8ded3976e460cc88954383651e7b357e, /commits/25778c3e8ded3976e460cc88954383651e7b357e and its .atom feed, /issues
- https://github.com/OwnDing?tab=repositories (raw HTML and summarising fetch)
- https://raw.githubusercontent.com/juanfont/headscale/v0.26.1/config-example.yaml (full diff against the repository config; v0.26.0 confirmed identical)
- https://raw.githubusercontent.com/juanfont/headscale/v0.25.1/config-example.yaml and v0.27.1/config-example.yaml (diffed against the repository config)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/config-example.yaml (full)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/about/faq.md (full)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/about/features.md (full)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/README.md (full)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/setup/requirements.md (full)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/docs/ref/integration/reverse-proxy.md (lines 1-80)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/state/state.go (lines 1-470 plus declaration listing)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/state/node_store.go (lines 1-200)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/mapper/batcher.go (lines 1-330 plus declaration listing)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/db/ip.go (type comment), hscontrol/app.go (Headscale struct), hscontrol/db/{db,node,users,preauth_keys,api_key,ip,policy}.go (pattern search), hscontrol/types/config.go (pattern search), go.mod (go directive)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/CHANGELOG.md (lines 1-345, 469-560, 633-830 and all release headings)
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/LICENSE and v0.26.1/LICENSE (full)
- https://raw.githubusercontent.com/juanfont/headscale/v0.26.1/hscontrol/app.go (lines 1-200 plus pattern search)
- https://raw.githubusercontent.com/juanfont/headscale/v0.26.1/hscontrol/notifier/notifier.go (lines 1-110)
- https://raw.githubusercontent.com/juanfont/headscale/v0.26.1/hscontrol/db/ip.go (lines 1-110)
- https://raw.githubusercontent.com/juanfont/headscale/v0.26.1/hscontrol/routes/primary.go (lines 1-80)
- https://raw.githubusercontent.com/juanfont/headscale/v0.26.1/hscontrol/db/policy.go (full) and hscontrol/types/policy.go
- https://raw.githubusercontent.com/juanfont/headscale/v0.26.1/hscontrol/{poll.go,mapper/mapper.go,grpcv1.go,auth.go} (pattern search; grpcv1.go lines 715-790), hscontrol/db/{db,node,users,preauth_keys,api_key}.go (pattern search), hscontrol/types/config.go (pattern search), go.mod (go directive)
- https://raw.githubusercontent.com/juanfont/headscale/v0.26.1/docs/ref/integration/reverse-proxy.md (lines 1-120)
- https://github.com/juanfont/headscale/issues/2695 (summarising fetch plus raw HTML confirmation of maintainer comment, author, labels, state)
- https://github.com/juanfont/headscale/issues/100 (summarising fetch plus raw HTML confirmation of owner comment)
- https://raw.githubusercontent.com/OwnDing/larktun-docs/665cc67fe0398cb316774f07628c66da0f6c4c01/README.md (full; content hash matched branch main)
- https://raw.githubusercontent.com/OwnDing/larktun-docs/665cc67fe0398cb316774f07628c66da0f6c4c01/blog/2025-10-01-headscale-cluster-infinite-scale.mdx (full)
- https://raw.githubusercontent.com/OwnDing/larktun-docs/665cc67fe0398cb316774f07628c66da0f6c4c01/blog/2025-10-25-headscale-saas-seamless-user-switch.mdx (full)
- https://raw.githubusercontent.com/OwnDing/larktun-docs/665cc67fe0398cb316774f07628c66da0f6c4c01/blog/2026-04-22-headscale-multi-tenant-isolation.mdx (full)
- https://raw.githubusercontent.com/OwnDing/larktun-docs/665cc67fe0398cb316774f07628c66da0f6c4c01/blog/2025-09-28-headscale-stress-test.mdx (full)
- https://raw.githubusercontent.com/OwnDing/larktun-docs/665cc67fe0398cb316774f07628c66da0f6c4c01/blog/2025-08-08-headscale-source-build-docker-image.mdx (full)
- https://raw.githubusercontent.com/OwnDing/larktun-docs/665cc67fe0398cb316774f07628c66da0f6c4c01/blog/2025-07-30-headscale-build-from-source.mdx (full)
- https://raw.githubusercontent.com/OwnDing/larktun-docs/665cc67fe0398cb316774f07628c66da0f6c4c01/blog/2026-04-24-what-is-larktun.mdx (full)
- https://github.com/OwnDing/larktun-docs/tree/main/docs and /tree/main/blog (directory listings)
- https://raw.githubusercontent.com/OwnDing/headscale-test-scripts/efcf3a84ab279915a4331149e1fa960b39a96e1d/README.md (full)
- https://raw.githubusercontent.com/OwnDing/headscale-java/1a2c8710b127a24f96a4115b8cdbcfdb56a2a9c3/README.md (full)
- https://nginx.org/en/docs/http/ngx_http_proxy_module.html (default proxy timeouts)
- https://www.postgresql.org/docs/current/app-pgdump.html (option search)
- Web searches (generic queries): upstream high-availability / shared-database statements; cluster_id clustering fork and its source availability

**Nguồn không đọc được:**

- images/*.png and h.tar in the researched repository: intentionally not fetched (task rule), so screenshot content, image tag, binary version and embedded licence files are unverified.
- https://github.com/OwnDing/headscale-saas/forks : the summarising fetch showed no forks under the page's default filters while the repository page summary reported 2 forks; fork contents were not examined.
- https://raw.githubusercontent.com/juanfont/headscale/v0.29.7/hscontrol/mapper/batcher_lockfree.go and .../hscontrol/state/ephemeral.go : 404 (guessed file names that do not exist at this tag; not needed).
- Repository issue count, commit messages, fork count and release status were read only through the summarising fetch tool; star count, commit count and commit timestamps were confirmed from raw HTML and the commits feed.
- One HTML extraction command against the upstream issue page exceeded its time limit and was stopped; the same data was then obtained with a different extraction.
