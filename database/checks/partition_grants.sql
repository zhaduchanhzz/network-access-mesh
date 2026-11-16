-- Kiểm tra CI (P2-T03, §6.1): RLS của bảng cha KHÔNG áp dụng khi truy vấn thẳng một partition, nên quyền chỉ được
-- cấp trên bảng cha. Mỗi hàng trả về là một vi phạm; CI đòi 0 hàng:
--   partition_grant       — partition (của audit_events, usage_records từ 0016, hay bất kỳ bảng partition nào) có
--                           quyền cấp cho role khác owner (gồm PUBLIC và mọi role ứng dụng);
--   partition_without_rls — partition chưa bật RLS (lớp phòng thủ thứ hai: lỡ cấp quyền vẫn đọc 0 hàng);
--   default_privileges    — có default privileges (quyền phải cấp tường minh trên bảng cha, không tự động).
SELECT 'partition_grant' AS check_name,
       c.oid::regclass::text AS object,
       format('%s có %s (bảng gốc %s)',
              CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,
              a.privilege_type, pg_partition_root(c.oid)::regclass) AS detail
FROM pg_class c
CROSS JOIN LATERAL aclexplode(c.relacl) AS a
WHERE c.relispartition AND a.grantee <> c.relowner
UNION ALL
SELECT 'partition_without_rls', c.oid::regclass::text, format('bảng gốc %s', pg_partition_root(c.oid)::regclass)
FROM pg_class c
WHERE c.relispartition AND c.relkind IN ('r', 'p') AND NOT c.relrowsecurity
UNION ALL
SELECT 'default_privileges',
       CASE WHEN d.defaclnamespace = 0 THEN '(mọi schema)' ELSE d.defaclnamespace::regnamespace::text END,
       format('%s: %s', d.defaclrole::regrole, d.defaclacl)
FROM pg_default_acl d
ORDER BY 1, 2, 3
