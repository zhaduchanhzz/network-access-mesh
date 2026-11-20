// Tenants — danh sách (§12.2): GET /platform/tenants (lọc trạng thái + tìm theo slug/tên, phân trang con trỏ).
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { useCursorPager } from "../../api/pagination";
import { can } from "../../auth/permissions";
import { EmptyState, Pager, QueryBlock } from "../../ui/Data";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { Page } from "../../components/Page";
import { TENANT_STATUSES, useTenantList, type TenantStatus } from "../api";
import { usePlatformRole } from "../PlatformScope";

function isTenantStatus(v: string): v is TenantStatus {
  return (TENANT_STATUSES as readonly string[]).includes(v);
}

export function TenantListPage() {
  const { t } = useTranslation();
  const role = usePlatformRole();
  const [status, setStatus] = useState<TenantStatus | "">("");
  const [draft, setDraft] = useState("");
  const [q, setQ] = useState("");
  const pager = useCursorPager(`${status}|${q}`);
  const list = useTenantList({ status: status || undefined, q: q || undefined, cursor: pager.cursor });
  const filtered = status !== "" || q !== "";

  return (
    <Page
      title={t("platform.tenants.title")}
      actions={
        can(role, "platform.tenant:create") ? (
          <Link to="/platform/tenants/new" className="btn-primary">
            {t("platform.tenants.create")}
          </Link>
        ) : null
      }
    >
      <form
        role="search"
        aria-label={t("platform.tenants.filters")}
        className="mb-4 flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          setQ(draft.trim().slice(0, 64));
        }}
      >
        <div>
          <label htmlFor="tenant-q" className="label">
            {t("platform.tenants.search")}
          </label>
          <input
            id="tenant-q"
            type="search"
            className="input"
            maxLength={64}
            value={draft}
            onChange={(e) => {
              setDraft(e.target.value);
            }}
          />
        </div>
        <div>
          <label htmlFor="tenant-status" className="label">
            {t("platform.tenants.status")}
          </label>
          <select
            id="tenant-status"
            className="select"
            value={status}
            onChange={(e) => {
              setStatus(isTenantStatus(e.target.value) ? e.target.value : "");
            }}
          >
            <option value="">{t("common.all")}</option>
            {TENANT_STATUSES.map((s) => (
              <option key={s} value={s}>
                {t(`status.tenant.${s}`)}
              </option>
            ))}
          </select>
        </div>
        <button type="submit" className="btn-secondary">
          {t("common.search")}
        </button>
      </form>

      <QueryBlock query={list}>
        {(data) =>
          data.items.length === 0 ? (
            <EmptyState>{filtered ? t("platform.tenants.emptyFiltered") : t("platform.tenants.empty")}</EmptyState>
          ) : (
            <>
              <div className="relative overflow-x-auto rounded-lg border border-line bg-surface">
                <table className="data-table">
                  <caption className="sr-only">{t("platform.tenants.caption")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{t("platform.tenants.col.slug")}</th>
                      <th scope="col">{t("platform.tenants.col.name")}</th>
                      <th scope="col">{t("platform.tenants.col.status")}</th>
                      <th scope="col">{t("platform.tenants.col.plan")}</th>
                      <th scope="col">{t("platform.tenants.col.region")}</th>
                      <th scope="col">{t("platform.tenants.col.created")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((tn) => (
                      <tr key={tn.id}>
                        <td>
                          <Link to={`/platform/tenants/${tn.id}`} className="link font-mono">
                            {tn.slug}
                          </Link>
                        </td>
                        <td>{tn.name}</td>
                        <td>
                          <StatusBadge status={tn.status}>{t(`status.tenant.${tn.status}`)}</StatusBadge>
                        </td>
                        <td>
                          <code>{tn.plan}</code>
                        </td>
                        <td>{tn.deployment_region}</td>
                        <td>
                          <Timestamp iso={tn.created_at} emptyKey="common.none" />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pager pager={pager} nextCursor={data.next_cursor} label={t("platform.tenants.pagination")} />
            </>
          )
        }
      </QueryBlock>
    </Page>
  );
}
