// Audit phạm vi platform (P4-T13, §8.5 platform.audit:read): GET /platform/audit — hành động của nhân sự nền tảng (gồm
// yêu cầu/break-glass/thu hồi support grant), từ chối của họ, sự kiện hệ thống mức platform. Query key bắt đầu PLATFORM.
import { useTranslation } from "react-i18next";
import { api, call } from "../../api/client";
import { queryKeys } from "../../api/queryClient";
import { AuditLog, type AuditPageQuery } from "../../audit/AuditLog";
import { Page } from "../../components/Page";

export function PlatformAuditPage() {
  const { t } = useTranslation();
  return (
    <Page title={t("nav.platform.audit")}>
      <p className="mb-4 text-sm text-muted">{t("audit.platformIntro")}</p>
      <AuditLog
        queryKeyOf={(q: AuditPageQuery) => queryKeys.platform("audit", { ...q })}
        fetchPage={(q) => call(api.GET("/platform/audit", { params: { query: q } }))}
      />
    </Page>
  );
}
