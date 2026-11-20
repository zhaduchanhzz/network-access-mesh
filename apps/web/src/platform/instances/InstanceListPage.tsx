// Instances — danh sách (§12.2 "Theo dõi health; Instance detail"): GET /platform/instances (lọc trạng thái, host — từ
// trang Hosts qua ?host=, phân trang con trỏ). Health luôn kèm `checked_at` + lý do khi không healthy (không số giả).
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router";
import { useCursorPager } from "../../api/pagination";
import { isUuid } from "../../api/queryClient";
import { EmptyState, Pager, QueryBlock } from "../../ui/Data";
import { StatusBadge } from "../../ui/Status";
import { Page } from "../../components/Page";
import { INSTANCE_STATUSES, isOneOf, useInstanceList, type Instance, type InstanceStatus } from "../opsApi";
import { HealthCell } from "./InstanceBits";

export function InstanceListPage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const rawHost = params.get("host") ?? "";
  const host = isUuid(rawHost) ? rawHost.toLowerCase() : undefined;
  const [status, setStatus] = useState<InstanceStatus | "">("");
  const pager = useCursorPager(`${status}|${host ?? ""}`);
  const list = useInstanceList({ status: status || undefined, host, cursor: pager.cursor });

  return (
    <Page title={t("platform.instances.title")}>
      <div className="mb-4 flex flex-wrap items-end gap-3">
        <div>
          <label htmlFor="instance-status" className="label">
            {t("platform.instances.status")}
          </label>
          <select
            id="instance-status"
            className="select"
            value={status}
            onChange={(e) => {
              setStatus(isOneOf(INSTANCE_STATUSES, e.target.value) ? e.target.value : "");
            }}
          >
            <option value="">{t("common.all")}</option>
            {INSTANCE_STATUSES.map((s) => (
              <option key={s} value={s}>
                {t(`status.instance.${s}`)}
              </option>
            ))}
          </select>
        </div>
        {host ? (
          <p className="text-sm" data-testid="host-filter">
            {t("platform.instances.onHost")} <code className="text-xs">{host}</code>{" "}
            <button
              type="button"
              className="link"
              onClick={() => {
                setParams({});
              }}
            >
              {t("platform.instances.clearHost")}
            </button>
          </p>
        ) : null}
      </div>
      <QueryBlock query={list}>
        {(data) =>
          data.items.length === 0 ? (
            <EmptyState>{status || host ? t("platform.instances.emptyFiltered") : t("platform.instances.empty")}</EmptyState>
          ) : (
            <>
              <InstanceTable items={data.items} caption={t("platform.instances.caption")} />
              <Pager pager={pager} nextCursor={data.next_cursor} label={t("platform.instances.pagination")} />
            </>
          )
        }
      </QueryBlock>
    </Page>
  );
}

/** Bảng instance (danh sách và trang host). */
export function InstanceTable({ items, caption, showHost = true }: { items: readonly Instance[]; caption: string; showHost?: boolean }) {
  const { t } = useTranslation();
  return (
    <div className="relative overflow-x-auto rounded-lg border border-line bg-surface">
      <table className="data-table">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            <th scope="col">{t("platform.instances.col.hostname")}</th>
            <th scope="col">{t("platform.instances.col.status")}</th>
            <th scope="col">{t("platform.instances.col.health")}</th>
            <th scope="col">{t("platform.instances.col.version")}</th>
            <th scope="col">{t("platform.instances.col.tenant")}</th>
            {showHost ? <th scope="col">{t("platform.instances.col.host")}</th> : null}
          </tr>
        </thead>
        <tbody>
          {items.map((i) => (
            <tr key={i.id}>
              <td>
                <Link to={`/platform/instances/${i.id}`} className="link font-mono">
                  {i.control_hostname}
                </Link>
              </td>
              <td>
                <StatusBadge status={i.status}>{t(`status.instance.${i.status}`)}</StatusBadge>
              </td>
              <td>
                <HealthCell health={i.health} />
              </td>
              <td>
                <code>{i.headscale_version}</code>
              </td>
              <td>
                <Link to={`/platform/tenants/${i.tenant_id}`} className="link font-mono text-xs">
                  {i.tenant_id}
                </Link>
              </td>
              {showHost ? (
                <td>
                  <Link to={`/platform/hosts/${i.host_id}`} className="link font-mono text-xs">
                    {i.host_id}
                  </Link>
                </td>
              ) : null}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
