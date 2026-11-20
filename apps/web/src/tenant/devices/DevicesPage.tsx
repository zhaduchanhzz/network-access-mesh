// Devices (P4-T04, §12.3): GET /tenants/{t}/devices — lọc (tên, trực tuyến, tag, tagged, có hạn, "của tôi"), phân trang
// cursor (trước/sau), mỗi trang kèm `synced_at`; "Làm mới từ Headscale" = `fresh=true` (trang 1, giới hạn tần suất);
// đồng bộ (job). End User chỉ thấy thiết bị của chính mình — server lọc (§8.4 bất biến 3b). Báo cáo rà soát tagged
// node không hết hạn: `?view=review` (§7.4, ADR-23). Không cột hệ điều hành/phiên bản client (HS-14).
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type SyntheticEvent } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router";
import { api, call } from "../../api/client";
import { queryKeys } from "../../api/queryClient";
import { can } from "../../auth/permissions";
import { Loading, Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { ObservedAt, Timestamp } from "../../ui/time";
import { useTenant } from "../TenantScope";
import { ExpiryText, OnlineBadge, OwnerText, RevocationBadge, TagList } from "./DeviceBits";
import { apiQuery, filtersFromParams, paramsFromFilters, revocationPending, TAG_RE, type DeviceFilters, type TriState } from "./deviceModel";
import { SyncControl } from "./SyncControl";

export const PENDING_POLL_MS = 5000;

export function DevicesPage() {
  const { t } = useTranslation();
  const { tenantId, role, membershipId } = useTenant();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const filters = filtersFromParams(params);
  const query = apiQuery(filters, membershipId);
  // cursor của từng trang đã đi qua (trang 1 = ""), đặt lại khi bộ lọc đổi
  const [cursors, setCursors] = useState<{ key: string; stack: string[] }>({ key: "", stack: [""] });
  const filterKey = JSON.stringify(query);
  const stack = cursors.key === filterKey ? cursors.stack : [""];
  const cursor = stack[stack.length - 1] ?? "";

  const listKey = queryKeys.tenant(tenantId, "devices", "list", { ...query, cursor });
  const list = useQuery({
    queryKey: listKey,
    queryFn: () =>
      call(api.GET("/tenants/{tenantId}/devices", { params: { path: { tenantId }, query: { ...query, ...(cursor ? { cursor } : {}) } } })),
    refetchInterval: (q) => (q.state.data?.items.some((d) => revocationPending(d)) ? PENDING_POLL_MS : false),
  });

  const fresh = useMutation({
    mutationFn: () =>
      call(api.GET("/tenants/{tenantId}/devices", { params: { path: { tenantId }, query: { ...query, fresh: true } } })),
    onSuccess: (page) => {
      setCursors({ key: filterKey, stack: [""] });
      queryClient.setQueryData(queryKeys.tenant(tenantId, "devices", "list", { ...query, cursor: "" }), page);
      void queryClient.invalidateQueries({ queryKey: queryKeys.tenant(tenantId, "dashboard") });
    },
  });

  const update = (f: Partial<DeviceFilters>) => {
    setParams(paramsFromFilters({ ...filters, ...f }), { replace: true });
  };
  const items = list.data?.items ?? [];
  // G4b-E9: mốc của tenant (`synced_at` của trang — lần sync gần nhất của instance, có cả khi trang rỗng); server cũ
  // không trả ⇒ mốc mới nhất của các hàng
  const tenantSynced = list.data?.synced_at;
  const syncedAt =
    tenantSynced !== undefined
      ? tenantSynced
      : items.reduce<string | null>((max, d) => (max === null || d.synced_at > max ? d.synced_at : max), null);

  return (
    <Page title={filters.review ? t("devices.review.title") : t("nav.tenant.devices")} actions={can(role, "tenant.device:sync") ? <SyncControl /> : null}>
      {filters.review ? (
        <div className="mb-4 rounded-md border border-line bg-surface p-4 text-sm" data-testid="review-banner">
          <p>{t("devices.review.description")}</p>
          <p className="mt-2">
            <button type="button" className="link" onClick={() => update({ review: false, tagged: "any", expiry: "any" })}>
              {t("devices.review.exit")}
            </button>
          </p>
        </div>
      ) : null}
      <Filters filters={filters} canMine={membershipId !== null} onChange={update} />
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        {/* "Đồng bộ từ Headscale lúc …" theo mốc của tenant — đúng cả khi danh sách rỗng; chưa sync lần nào ⇒ câu riêng
            (G4b-E9). Server cũ không có mốc của tenant và trang rỗng ⇒ không hiện câu nào thay vì "chưa từng" sai */}
        <div data-testid="devices-synced">
          {list.isSuccess && (tenantSynced !== undefined || items.length > 0) ? <ObservedAt labelKey="ui.syncedAt" iso={syncedAt} /> : null}
        </div>
        <button type="button" className="btn-secondary" disabled={fresh.isPending} onClick={() => fresh.mutate()}>
          {t("devices.fresh")}
        </button>
      </div>
      {fresh.isError ? (
        <div className="mb-3">
          <ProblemAlert error={fresh.error} />
        </div>
      ) : null}
      {list.isPending ? <Loading /> : null}
      {list.isError ? <ProblemAlert error={list.error} onRetry={() => void list.refetch()} /> : null}
      {list.isSuccess && items.length === 0 ? (
        <p className="text-muted" data-testid="devices-empty">
          {filters.review ? t("devices.review.empty") : t("devices.empty")}
        </p>
      ) : null}
      {items.length > 0 ? (
        <div className="relative overflow-x-auto">
          <table className="data-table" data-testid="devices-table">
            <caption className="sr-only">{t("nav.tenant.devices")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("devices.col.name")}</th>
                <th scope="col">{t("devices.col.owner")}</th>
                <th scope="col">{t("devices.col.tags")}</th>
                <th scope="col">{t("devices.col.addresses")}</th>
                <th scope="col">{t("devices.col.status")}</th>
                <th scope="col">{t("devices.col.lastSeen")}</th>
                <th scope="col">{t("devices.col.expiry")}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((d) => (
                <tr key={d.id} data-testid="device-row">
                  <td>
                    <Link to={`/t/${tenantId}/devices/${d.id}`} className="link font-medium">
                      {d.given_name}
                    </Link>
                    <div className="text-xs text-muted">{d.name}</div>
                  </td>
                  <td>
                    <OwnerText device={d} />
                  </td>
                  <td>
                    <TagList tags={d.tags} />
                  </td>
                  <td className="font-mono text-xs">{d.ip_addresses.join(", ")}</td>
                  <td className="space-x-1">
                    <OnlineBadge device={d} />
                    <RevocationBadge device={d} />
                  </td>
                  <td>
                    <Timestamp iso={d.last_seen} relative={false} />
                  </td>
                  <td>
                    <ExpiryText device={d} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      <p className="mt-2 text-xs text-muted">{t("devices.noOsNote")}</p>
      <nav aria-label={t("ui.pagination")} className="mt-4 flex gap-2">
        <button
          type="button"
          className="btn-secondary"
          disabled={stack.length <= 1}
          onClick={() => setCursors({ key: filterKey, stack: stack.slice(0, -1) })}
        >
          {t("ui.prevPage")}
        </button>
        <button
          type="button"
          className="btn-secondary"
          disabled={!list.data?.next_cursor}
          onClick={() => {
            const next = list.data?.next_cursor;
            if (next) setCursors({ key: filterKey, stack: [...stack, next] });
          }}
        >
          {t("ui.nextPage")}
        </button>
      </nav>
    </Page>
  );
}

function TriSelect({ id, label, value, labels, onChange }: { id: string; label: string; value: TriState; labels: [string, string, string]; onChange: (v: TriState) => void }) {
  return (
    <div>
      <label htmlFor={id} className="block text-xs font-medium text-muted">
        {label}
      </label>
      <select
        id={id}
        className="select"
        value={value}
        onChange={(e) => {
          onChange(e.target.value as TriState);
        }}
      >
        <option value="any">{labels[0]}</option>
        <option value="yes">{labels[1]}</option>
        <option value="no">{labels[2]}</option>
      </select>
    </div>
  );
}

function Filters({ filters, canMine, onChange }: { filters: DeviceFilters; canMine: boolean; onChange: (f: Partial<DeviceFilters>) => void }) {
  const { t } = useTranslation();
  const [q, setQ] = useState(filters.q);
  const [tag, setTag] = useState(filters.tag);
  const tagInvalid = tag !== "" && !TAG_RE.test(tag);
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    if (!tagInvalid) onChange({ q: q.trim(), tag });
  };
  return (
    <form role="search" aria-label={t("devices.filters")} className="mb-4 flex flex-wrap items-end gap-3" onSubmit={submit}>
      <div>
        <label htmlFor="dev-q" className="block text-xs font-medium text-muted">
          {t("devices.search")}
        </label>
        <input id="dev-q" className="input" type="search" maxLength={64} value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <div>
        <label htmlFor="dev-tag" className="block text-xs font-medium text-muted">
          {t("devices.tagFilter")}
        </label>
        <input
          id="dev-tag"
          className="input"
          value={tag}
          placeholder={t("devices.tagPlaceholder")}
          aria-invalid={tagInvalid}
          aria-describedby={tagInvalid ? "dev-tag-err" : undefined}
          onChange={(e) => setTag(e.target.value)}
        />
        {tagInvalid ? (
          <p id="dev-tag-err" className="text-xs text-danger">
            {t("devices.tagInvalid")}
          </p>
        ) : null}
      </div>
      <button type="submit" className="btn-primary">
        {t("devices.applyFilters")}
      </button>
      <TriSelect
        id="dev-online"
        label={t("devices.col.status")}
        value={filters.online}
        labels={[t("devices.any"), t("devices.online"), t("devices.offline")]}
        onChange={(v) => onChange({ online: v })}
      />
      {filters.review ? null : (
        <>
          <TriSelect
            id="dev-tagged"
            label={t("devices.taggedFilter")}
            value={filters.tagged}
            labels={[t("devices.any"), t("devices.taggedYes"), t("devices.taggedNo")]}
            onChange={(v) => onChange({ tagged: v })}
          />
          <TriSelect
            id="dev-expiry"
            label={t("devices.col.expiry")}
            value={filters.expiry}
            labels={[t("devices.any"), t("devices.expiryYes"), t("devices.neverExpires")]}
            onChange={(v) => onChange({ expiry: v })}
          />
        </>
      )}
      {canMine ? (
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={filters.mine} onChange={(e) => onChange({ mine: e.target.checked })} />
          {t("devices.mine")}
        </label>
      ) : null}
      {!filters.review ? (
        <button type="button" className="link text-sm" onClick={() => onChange({ review: true })}>
          {t("devices.review.open")}
        </button>
      ) : null}
    </form>
  );
}
