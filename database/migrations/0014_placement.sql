-- 0014 — Placement (P3-T04, §11.3 bước 3 `placement.allocate`, §6.3): chốt tập giá trị và hình dạng của các cột `hosts`
-- mà placement đọc (status, capacity, public_entry, run_uid_range, tenant_net_pool, stun_port_range) và ràng buộc
-- net_cidr/run_uid của tenant_instances. Không bảng, cột, quyền hay policy RLS mới.
-- Người dùng: platform.Placer (worker, pool platform — bước 3), platform.EnsureHost (adopt-instance, P2-T11).
-- Expand-only: chỉ thêm CHECK/DEFAULT + một lần điền capacity.max_instances cho host chưa khai báo (mẫu "migration dữ
-- liệu" của database/README.md); không đổi truy vấn nào của bản đang chạy (adopt-instance ghi capacity '{}' ⇒ từ bản này
-- CreateHost bỏ cột đó để DEFAULT áp dụng). Database có hàng vi phạm (pool không phải IPv4, net_cidr không phải /29…)
-- không migrate được cho tới khi hàng đó được sửa — fail closed có chủ đích (goose: mỗi migration một transaction).
-- Forward-only.

-- +goose Up

-- ---------------------------------------------------------------- hosts.status ("chốt ở P3-T04" — 0001)
-- active   = nhận instance mới (placement chỉ chọn host active);
-- draining = không nhận instance mới, instance đang có vẫn chạy (bảo trì, chuẩn bị relocation — Phase 7);
-- disabled = ngừng hẳn: không nhận instance mới; instance còn lại phải được chuyển/gỡ theo luồng vòng đời.
ALTER TABLE hosts
    ADD CONSTRAINT hosts_status_valid CHECK (status IN ('active', 'draining', 'disabled'));

-- ---------------------------------------------------------------- hosts.capacity
-- Đúng một khóa: max_instances = trần instance chưa `removed` trên host (§5.5 "trần instance/host cấu hình được"),
-- số nguyên 0…2147483647 viết không có phần thập phân; 0 = không nhận instance mới. Giá trị khởi đầu 100 = mức tạm tính của P1-T20 (restart edge
-- ~11 s với 100 network) — chủ dự án chỉnh theo host; trần lớn hơn quyết định ở P6-T08. DEFAULT cho host mới, điền cho
-- host chưa khai báo (staging: adopt-instance ghi '{}'). hosts là bảng FORCE RLS và owner (mg_migrator) không có policy
-- ⇒ tạm NO FORCE trong cùng transaction rồi FORCE lại. Khóa lạ đã có (không bao giờ do ứng dụng ghi) ⇒ CHECK dưới làm
-- migration thất bại thay vì lặng lẽ bỏ đi.
ALTER TABLE hosts ALTER COLUMN capacity SET DEFAULT '{"max_instances": 100}';
ALTER TABLE hosts NO FORCE ROW LEVEL SECURITY;
UPDATE hosts SET capacity = capacity || '{"max_instances": 100}' WHERE NOT capacity ? 'max_instances';
ALTER TABLE hosts FORCE ROW LEVEL SECURITY;
ALTER TABLE hosts
    ADD CONSTRAINT hosts_capacity_valid CHECK (
        capacity - 'max_instances' = '{}'::jsonb
        AND CASE WHEN jsonb_typeof(capacity -> 'max_instances') = 'number'
                      AND capacity ->> 'max_instances' ~ '^[0-9]{1,10}$'
                 THEN (capacity ->> 'max_instances')::bigint <= 2147483647
                 ELSE false
            END);

-- ---------------------------------------------------------------- hosts.public_entry
-- Điểm vào công khai của host (§6.3, §10.1): ipv4 = derp.server.ipv4 của mọi instance trên host — Agent so với cấu hình
-- cục bộ của nó (MG_AGENT_PUBLIC_ENTRY_IPV4) và từ chối khi khác; mode = direct | vps_gateway (§15.3). Cả hai tùy chọn,
-- nhưng placement không chọn host chưa có ipv4 (config bước 8 không render được). ipv4: dạng thập phân chuẩn, unicast
-- dùng được (không thuộc 0/8, 127/8, 169.254/16, 224/3) và nằm ngoài tenant_net_pool. Khóa ipv6 chưa được nhận: MVP chỉ
-- IPv4 (§10.1, §15.4 — không bản ghi AAAA); mở thêm khóa phải sửa §6.3 và CHECK này trước.
ALTER TABLE hosts
    ADD CONSTRAINT hosts_public_entry_valid CHECK (
        public_entry - 'ipv4' - 'mode' = '{}'::jsonb
        AND (NOT public_entry ? 'mode' OR public_entry -> 'mode' IN ('"direct"'::jsonb, '"vps_gateway"'::jsonb))
        AND (NOT public_entry ? 'ipv4'
             OR CASE WHEN jsonb_typeof(public_entry -> 'ipv4') = 'string'
                          AND public_entry ->> 'ipv4'
                              ~ '^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$'
                     THEN NOT ((public_entry ->> 'ipv4')::inet
                               <<= ANY ('{0.0.0.0/8,127.0.0.0/8,169.254.0.0/16,224.0.0.0/3}'::inet[]))
                          AND NOT (tenant_net_pool >>= (public_entry ->> 'ipv4')::inet)
                     ELSE false
                END));

-- ---------------------------------------------------------------- hosts: dải cấp phát
-- tenant_net_pool: IPv4, /8…/29 (cùng giới hạn với Agent — agentspec.Host.Check), không chồng 100.64.0.0/10 (dải IP
-- của tailnet — §6.3). run_uid_range: hữu hạn, trong 1000…2147483646 (Agent: run_uid ≠ 0, không trùng UID hệ thống);
-- việc dải không chứa UID/GID của service core (versions.lock [ids]) được kiểm ở code (platform.HostSpec, Agent) vì
-- danh sách đó đổi theo versions.lock. stun_port_range (chỉ phương án dự phòng per-tenant STUN — §10.1): hữu hạn, trong
-- 1024…65535; cổng của chính nền tảng (3478, cổng listener tunnel) loại ở code.
ALTER TABLE hosts
    ADD CONSTRAINT hosts_tenant_net_pool_valid CHECK (
        family(tenant_net_pool) = 4 AND masklen(tenant_net_pool) BETWEEN 8 AND 29
        AND NOT (tenant_net_pool && '100.64.0.0/10'::cidr)),
    ADD CONSTRAINT hosts_run_uid_range_bounds CHECK (
        NOT lower_inf(run_uid_range) AND NOT upper_inf(run_uid_range)
        AND lower(run_uid_range) >= 1000 AND upper(run_uid_range) <= 2147483647),
    ADD CONSTRAINT hosts_stun_port_range_valid CHECK (
        stun_port_range IS NULL
        OR (NOT isempty(stun_port_range) AND NOT lower_inf(stun_port_range) AND NOT upper_inf(stun_port_range)
            AND lower(stun_port_range) >= 1024 AND upper(stun_port_range) <= 65536));

-- ---------------------------------------------------------------- tenant_instances
-- net_cidr: đúng một /29 IPv4 (§14.3; Agent từ chối mọi kích thước khác) ⇒ partial UNIQUE(host_id, net_cidr) WHERE
-- status <> 'removed' của 0001 tương đương "không chồng nhau" giữa các instance chưa removed của một host (hai /29 căn lề
-- hoặc trùng hẳn hoặc rời nhau). run_uid: cùng biên với hosts.run_uid_range.
ALTER TABLE tenant_instances
    ADD CONSTRAINT tenant_instances_net_cidr_slash29 CHECK (family(net_cidr) = 4 AND masklen(net_cidr) = 29),
    ADD CONSTRAINT tenant_instances_run_uid_bounds CHECK (run_uid BETWEEN 1000 AND 2147483646);
