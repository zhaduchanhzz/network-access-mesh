// Chọn tenant: trên app. là các membership đang hoạt động của session (GET /auth/session); trên admin. là các
// Support Access Grant còn hiệu lực (§8.7 — không có "vào thẳng tenant"; grant có từ P4-T13).
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { useConsole } from "../app/console";
import { useSession } from "../auth/session";
import { Page } from "../components/Page";
import { formatDateTime } from "../i18n";
import { AppShell } from "../layout/AppShell";

export function TenantSelectPage() {
  const { t, i18n } = useTranslation();
  const kind = useConsole();
  const session = useSession().data;
  const [now] = useState(Date.now); // thời điểm mở trang — grant hết hạn sau đó bị server từ chối
  if (!session) return null;
  const grants = session.support_grants.filter((g) => Date.parse(g.expires_at) > now);
  return (
    <AppShell base={null} nav={[]} context="">
      <Page title={t("tenantSelect.title")}>
        {kind === "tenant" ? (
          session.memberships.length === 0 ? (
            <p className="text-muted">{t("tenantSelect.noMemberships")}</p>
          ) : (
            <ul className="grid gap-3 sm:grid-cols-2">
              {session.memberships.map((m) => (
                <li key={m.membership_id}>
                  <Link to={`/t/${m.tenant_id}`} className="card-link">
                    <span className="block font-medium">{m.tenant_name}</span>
                    <span className="block text-sm text-muted">
                      {m.tenant_slug}
                      {" · "}
                      {t(`roles.${m.role}`, { defaultValue: m.role })}
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )
        ) : grants.length === 0 ? (
          <div className="space-y-3">
            <p className="text-muted">{t("tenantSelect.noGrants")}</p>
            <Link to="/platform" className="link">
              {t("shell.platformConsole")}
            </Link>
          </div>
        ) : (
          <ul className="grid gap-3 sm:grid-cols-2">
            {grants.map((g) => (
              <li key={g.id}>
                <Link to={`/t/${g.tenant_id}`} className="card-link">
                  <code className="block text-sm">{g.tenant_id}</code>
                  <span className="block text-sm text-muted">
                    {t(`roles.${g.effective_role}`)}
                    {" · "}
                    {t("tenantSelect.grantExpires", { at: formatDateTime(g.expires_at, i18n.language) })}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Page>
    </AppShell>
  );
}
