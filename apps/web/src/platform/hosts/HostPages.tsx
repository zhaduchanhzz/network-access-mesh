// Hosts (§12.2 "Cluster/host placement — capacity, instance theo host"): GET /platform/hosts (mức dùng đọc cùng lúc:
// instance chưa removed so với capacity, UID còn cấp được, slot /29 còn trống, cổng STUN còn trống — P4-T03; `null` =
// host dùng STUN chung), chi tiết GET /platform/hosts/{id} + instance trên host (GET /platform/instances?host=).
// Chỉ đọc ở màn hình này: sửa host (platform.host:manage) vẫn qua lệnh `meshguard admin host-set` / PATCH của P3-T04.
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useParams } from "react-router";
import { useCursorPager } from "../../api/pagination";
import { ApiError } from "../../api/problem";
import { isUuid } from "../../api/queryClient";
import { EmptyState, Field, Pager, QueryBlock } from "../../ui/Data";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { Loading, Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { NotFoundPage } from "../../pages/StatusPages";
import { HOST_STATUSES, isOneOf, useHost, useHostList, useInstanceList, type Host, type HostStatus } from "../opsApi";
import { InstanceTable } from "../instances/InstanceListPage";

export function HostListPage() {
  const { t } = useTranslation();
  const [status, setStatus] = useState<HostStatus | "">("");
  const pager = useCursorPager(status);
  const list = useHostList({ status: status || undefined, cursor: pager.cursor });
  return (
    <Page title={t("platform.hosts.title")}>
      <div className="mb-4">
        <label htmlFor="host-status" className="label">
          {t("platform.hosts.status")}
        </label>
        <select
          id="host-status"
          className="select"
          value={status}
          onChange={(e) => {
            setStatus(isOneOf(HOST_STATUSES, e.target.value) ? e.target.value : "");
          }}
        >
          <option value="">{t("common.all")}</option>
          {HOST_STATUSES.map((s) => (
            <option key={s} value={s}>
              {t(`status.host.${s}`)}
            </option>
          ))}
        </select>
      </div>
      <QueryBlock query={list}>
        {(data) =>
          data.items.length === 0 ? (
            <EmptyState>{status ? t("platform.hosts.emptyFiltered") : t("platform.hosts.empty")}</EmptyState>
          ) : (
            <>
              <div className="relative overflow-x-auto rounded-lg border border-line bg-surface">
                <table className="data-table">
                  <caption className="sr-only">{t("platform.hosts.caption")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{t("platform.hosts.col.name")}</th>
                      <th scope="col">{t("platform.hosts.col.region")}</th>
                      <th scope="col">{t("platform.hosts.col.status")}</th>
                      <th scope="col">{t("platform.hosts.col.capacity")}</th>
                      <th scope="col">{t("platform.hosts.col.stunFree")}</th>
                      <th scope="col">{t("platform.hosts.col.netFree")}</th>
                      <th scope="col">{t("platform.hosts.col.heartbeat")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((h) => (
                      <tr key={h.id} data-testid="host-row">
                        <td>
                          <Link to={`/platform/hosts/${h.id}`} className="link font-mono">
                            {h.name}
                          </Link>
                        </td>
                        <td>{h.region}</td>
                        <td>
                          <StatusBadge status={hostTone(h.status)}>{t(`status.host.${h.status}`)}</StatusBadge>
                        </td>
                        <td>
                          <Capacity host={h} />
                        </td>
                        <td>
                          <StunFree host={h} />
                        </td>
                        <td>{String(h.usage.net_slots_free)}</td>
                        <td>
                          <Timestamp iso={h.last_heartbeat_at} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pager pager={pager} nextCursor={data.next_cursor} label={t("platform.hosts.pagination")} />
            </>
          )
        }
      </QueryBlock>
    </Page>
  );
}

/** draining là cảnh báo, disabled là trung tính (bảng tone dùng chung coi `active` là ok). */
function hostTone(s: HostStatus): string {
  return s === "draining" ? "pending" : s;
}

/** "n / max instance" — max 0 = không nhận instance mới. */
function Capacity({ host: h }: { host: Host }) {
  const { t } = useTranslation();
  return (
    <span data-testid="capacity">
      {t("platform.hosts.capacityValue", { live: h.usage.live_instances, max: h.capacity.max_instances })}
      {h.capacity.max_instances === 0 ? <span className="hint block">{t("platform.hosts.noNew")}</span> : null}
    </span>
  );
}

function StunFree({ host: h }: { host: Host }) {
  const { t } = useTranslation();
  return h.usage.stun_ports_free === null ? (
    <span className="text-muted" data-testid="stun-free">
      {t("platform.hosts.sharedStun")}
    </span>
  ) : (
    <span data-testid="stun-free">{String(h.usage.stun_ports_free)}</span>
  );
}

export function HostDetailPage() {
  const { hostId: raw = "" } = useParams();
  const hostId = raw.toLowerCase();
  if (!isUuid(hostId)) return <NotFoundPage />;
  return <HostDetail key={hostId} hostId={hostId} />;
}

function HostDetail({ hostId }: { hostId: string }) {
  const { t } = useTranslation();
  const q = useHost(hostId);
  const pager = useCursorPager(hostId);
  const instances = useInstanceList({ host: hostId, cursor: pager.cursor });
  if (q.isPending) return <Loading />;
  if (q.isError) {
    if (q.error instanceof ApiError && q.error.status === 404) return <NotFoundPage />;
    return (
      <Page title={t("platform.host.title")}>
        <ProblemAlert error={q.error} onRetry={() => void q.refetch()} />
      </Page>
    );
  }
  const h = q.data;
  const range = (r: { first: number; last: number } | undefined) => (r ? `${String(r.first)}–${String(r.last)}` : t("common.none"));
  return (
    <Page title={h.name}>
      <p className="mb-4">
        <Link to="/platform/hosts" className="link text-sm">
          {t("platform.host.back")}
        </Link>
      </p>
      <div className="space-y-6">
        <section aria-labelledby="host-summary" className="card">
          <h2 id="host-summary" className="mb-3 text-lg font-semibold">
            {t("platform.host.summary")}
          </h2>
          <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Field label={t("platform.hosts.col.status")}>
              <StatusBadge status={hostTone(h.status)}>{t(`status.host.${h.status}`)}</StatusBadge>
            </Field>
            <Field label={t("platform.hosts.col.region")}>{h.region}</Field>
            <Field label={t("platform.hosts.col.capacity")}>
              <Capacity host={h} />
            </Field>
            <Field label={t("platform.hosts.col.stunFree")}>
              <StunFree host={h} />
            </Field>
            <Field label={t("platform.host.stunRange")}>
              <code>{range(h.stun_port_range)}</code>
            </Field>
            <Field label={t("platform.hosts.col.netFree")}>{String(h.usage.net_slots_free)}</Field>
            <Field label={t("platform.host.netPool")}>
              <code>{h.tenant_net_pool}</code>
            </Field>
            <Field label={t("platform.host.uidFree")}>{String(h.usage.run_uids_free)}</Field>
            <Field label={t("platform.host.uidRange")}>
              <code>{range(h.run_uid_range)}</code>
            </Field>
            <Field label={t("platform.host.publicEntry")}>
              {h.public_entry.ipv4 ? <code>{h.public_entry.ipv4}</code> : t("platform.host.noEntry")}
              {h.public_entry.mode ? <span className="hint block">{t(`platform.host.entryModes.${h.public_entry.mode}`)}</span> : null}
            </Field>
            <Field label={t("platform.hosts.col.heartbeat")}>
              <Timestamp iso={h.last_heartbeat_at} />
            </Field>
            <Field label={t("platform.host.byStatus")}>
              {Object.keys(h.usage.by_status).length === 0 ? (
                t("common.none")
              ) : (
                <ul className="text-sm">
                  {Object.entries(h.usage.by_status).map(([s, n]) => (
                    <li key={s}>
                      {t(`status.instance.${s}`, { defaultValue: s })}
                      {": "}
                      {String(n)}
                    </li>
                  ))}
                </ul>
              )}
            </Field>
          </dl>
        </section>
        <section aria-labelledby="host-instances" className="card">
          <h2 id="host-instances" className="mb-3 text-lg font-semibold">
            {t("platform.host.instances")}
          </h2>
          <QueryBlock query={instances}>
            {(data) =>
              data.items.length === 0 ? (
                <EmptyState>{t("platform.host.noInstances")}</EmptyState>
              ) : (
                <>
                  <InstanceTable items={data.items} caption={t("platform.host.instances")} showHost={false} />
                  <Pager pager={pager} nextCursor={data.next_cursor} label={t("platform.host.instancesPagination")} />
                </>
              )
            }
          </QueryBlock>
        </section>
      </div>
    </Page>
  );
}
