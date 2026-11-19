// Audit của tenant (P4-T13, §6.1, §8.7 bước 3): GET /tenants/{t}/audit — sự kiện của tenant, gồm hành động của nhân sự
// nền tảng dưới Support Access Grant (actor.type = support + support_grant_id). Query key bắt đầu bằng tenantId.
import { useTranslation } from "react-i18next";
import { api, call } from "../../api/client";
import { queryKeys } from "../../api/queryClient";
import { AuditLog, type AuditPageQuery } from "../../audit/AuditLog";
import { Page } from "../../components/Page";
import { useTenant } from "../TenantScope";

export function AuditPage() {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  return (
    <Page title={t("nav.tenant.audit")}>
      <p className="mb-4 text-sm text-muted">{t("audit.tenantIntro")}</p>
      <AuditLog
        supportShortcut
        queryKeyOf={(q: AuditPageQuery) => queryKeys.tenant(tenantId, "audit", { ...q })}
        fetchPage={(q) => call(api.GET("/tenants/{tenantId}/audit", { params: { path: { tenantId }, query: q } }))}
      />
    </Page>
  );
}
