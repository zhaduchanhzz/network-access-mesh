// Nhật ký audit (P4-T13, §6.1, §16.5) — một thành phần cho cả hai console: GET /tenants/{t}/audit (Tenant Portal — mọi
// sự kiện của tenant, gồm hành động của nhân sự nền tảng dưới Support Access Grant, §8.7 bước 3) và GET /platform/audit
// (Platform Console — sự kiện platform). Lọc theo actor (identity UUID), loại actor (identity/system/support), action,
// kết quả, khoảng thời gian; phân trang con trỏ (api/pagination). Bộ lọc nằm trên URL (?actor_type=support… — trang
// Support Access trỏ thẳng tới hành động của support). Dữ liệu thật của server, không số liệu giả (§12.4).
import { useQuery, type QueryKey } from "@tanstack/react-query";
import { Fragment, useState, type ChangeEvent } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router";
import { useCursorPager } from "../api/pagination";
import { isUuid } from "../api/queryClient";
import type { components } from "../api/schema";
import { EmptyState, JsonBlock, Pager, QueryBlock } from "../ui/Data";
import { StatusBadge, type Tone } from "../ui/Status";
import { Timestamp } from "../ui/time";

export type AuditEvent = components["schemas"]["AuditEvent"];
export type AuditEventList = components["schemas"]["AuditEventList"];
export type ActorType = AuditEvent["actor"]["type"];
export type AuditOutcome = AuditEvent["outcome"];

export const ACTOR_TYPES = ["identity", "system", "support"] as const satisfies readonly ActorType[];
export const OUTCOMES = ["success", "denied", "failure"] as const satisfies readonly AuditOutcome[];
type Assert<T extends true> = T;
/** Lỗi typecheck ⇒ spec thêm giá trị chưa có trong danh sách (và chưa có bản dịch audit.actorTypes.* / audit.outcomes.*). */
export type AllActorTypesListed = Assert<[Exclude<ActorType, (typeof ACTOR_TYPES)[number]>] extends [never] ? true : false>;
export type AllOutcomesListed = Assert<[Exclude<AuditOutcome, (typeof OUTCOMES)[number]>] extends [never] ? true : false>;

export const AUDIT_PAGE = 50;
const ACTION_RE = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$/;

/** Bộ lọc đã áp dụng — đúng tên tham số query của API. */
export interface AuditFilter {
  actor?: string;
  actor_type?: ActorType;
  action?: string;
  outcome?: AuditOutcome;
  from?: string;
  to?: string;
}

export interface AuditPageQuery extends AuditFilter {
  limit: number;
  cursor?: string;
}

const OUTCOME_TONE: Record<AuditOutcome, Tone> = { success: "ok", denied: "danger", failure: "warn" };

function isActorType(v: string | null): v is ActorType {
  return v !== null && (ACTOR_TYPES as readonly string[]).includes(v);
}

function isOutcome(v: string | null): v is AuditOutcome {
  return v !== null && (OUTCOMES as readonly string[]).includes(v);
}

/** Đọc bộ lọc từ URL — giá trị lạ bị bỏ qua (không bao giờ gửi tham số sai lên server). */
export function filterFromParams(p: URLSearchParams): AuditFilter {
  const f: AuditFilter = {};
  const actor = p.get("actor");
  if (actor && isUuid(actor)) f.actor = actor.toLowerCase();
  const type = p.get("actor_type");
  if (isActorType(type)) f.actor_type = type;
  const action = p.get("action");
  if (action && action.length <= 128 && ACTION_RE.test(action)) f.action = action;
  const outcome = p.get("outcome");
  if (isOutcome(outcome)) f.outcome = outcome;
  for (const k of ["from", "to"] as const) {
    const v = p.get(k);
    if (v && !Number.isNaN(Date.parse(v))) f[k] = new Date(v).toISOString();
  }
  return f;
}

function toParams(f: AuditFilter): URLSearchParams {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(f)) if (typeof v === "string" && v) p.set(k, v);
  return p;
}

/** ISO ⇒ giá trị của ô datetime-local (giờ địa phương) và ngược lại. */
function toLocalInput(iso: string | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function fromLocalInput(v: string): string | undefined {
  if (!v) return undefined;
  const t = Date.parse(v);
  return Number.isNaN(t) ? undefined : new Date(t).toISOString();
}

export interface AuditLogProps {
  /** query key của một trang — bắt đầu bằng tenantId (Portal) hoặc PLATFORM (Console) */
  queryKeyOf: (q: AuditPageQuery) => QueryKey;
  fetchPage: (q: AuditPageQuery) => Promise<AuditEventList>;
  /** Portal: hành động của support là một bộ lọc nhanh (minh bạch §8.7) */
  supportShortcut?: boolean;
}

export function AuditLog({ queryKeyOf, fetchPage, supportShortcut = false }: AuditLogProps) {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const filter = filterFromParams(params);
  const resetKey = toParams(filter).toString();
  const pager = useCursorPager(resetKey);
  const q: AuditPageQuery = { ...filter, limit: AUDIT_PAGE, ...(pager.cursor ? { cursor: pager.cursor } : {}) };
  const list = useQuery({ queryKey: queryKeyOf(q), queryFn: () => fetchPage(q), placeholderData: (prev) => prev });
  const apply = (f: AuditFilter) => {
    setParams(toParams(f), { replace: true });
  };

  return (
    <>
      <AuditFilters key={resetKey} filter={filter} onApply={apply} />
      {supportShortcut ? (
        <p className="mb-3">
          <button
            type="button"
            className={filter.actor_type === "support" ? "btn-primary" : "btn-secondary"}
            aria-pressed={filter.actor_type === "support"}
            onClick={() => {
              apply(filter.actor_type === "support" ? { ...filter, actor_type: undefined } : { ...filter, actor_type: "support" });
            }}
          >
            {t("audit.supportOnly")}
          </button>
        </p>
      ) : null}
      <QueryBlock query={list}>
        {(data) =>
          data.items.length === 0 ? (
            <EmptyState>{t("audit.empty")}</EmptyState>
          ) : (
            <>
              <AuditTable items={data.items} />
              <Pager pager={pager} nextCursor={data.next_cursor} label={t("audit.pagination")} />
            </>
          )
        }
      </QueryBlock>
    </>
  );
}

function AuditFilters({ filter, onApply }: { filter: AuditFilter; onApply: (f: AuditFilter) => void }) {
  const { t } = useTranslation();
  const [actor, setActor] = useState(filter.actor ?? "");
  const [actorType, setActorType] = useState<string>(filter.actor_type ?? "");
  const [action, setAction] = useState(filter.action ?? "");
  const [outcome, setOutcome] = useState<string>(filter.outcome ?? "");
  const [from, setFrom] = useState(toLocalInput(filter.from));
  const [to, setTo] = useState(toLocalInput(filter.to));
  const actorBad = actor !== "" && !isUuid(actor.trim());
  const actionBad = action !== "" && (action.length > 128 || !ACTION_RE.test(action.trim()));
  const fromIso = fromLocalInput(from);
  const toIso = fromLocalInput(to);
  const rangeBad = fromIso !== undefined && toIso !== undefined && Date.parse(fromIso) >= Date.parse(toIso);
  const set = (fn: (v: string) => void) => (e: ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    fn(e.target.value);
  };
  return (
    <form
      role="search"
      aria-label={t("audit.filters")}
      className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3"
      onSubmit={(e) => {
        e.preventDefault();
        if (actorBad || actionBad || rangeBad) return;
        onApply({
          actor: actor.trim() ? actor.trim().toLowerCase() : undefined,
          actor_type: isActorType(actorType) ? actorType : undefined,
          action: action.trim() || undefined,
          outcome: isOutcome(outcome) ? outcome : undefined,
          from: fromIso,
          to: toIso,
        });
      }}
    >
      <div>
        <label htmlFor="audit-actor" className="label">
          {t("audit.actor")}
        </label>
        <input id="audit-actor" className="input font-mono" value={actor} placeholder={t("audit.actorPlaceholder")} aria-invalid={actorBad} onChange={set(setActor)} />
        {actorBad ? <p className="hint text-danger">{t("audit.actorInvalid")}</p> : null}
      </div>
      <div>
        <label htmlFor="audit-actor-type" className="label">
          {t("audit.actorType")}
        </label>
        <select id="audit-actor-type" className="select" value={actorType} onChange={set(setActorType)}>
          <option value="">{t("common.all")}</option>
          {ACTOR_TYPES.map((a) => (
            <option key={a} value={a}>
              {t(`audit.actorTypes.${a}`)}
            </option>
          ))}
        </select>
      </div>
      <div>
        <label htmlFor="audit-action" className="label">
          {t("audit.action")}
        </label>
        <input id="audit-action" className="input font-mono" value={action} placeholder={t("audit.actionPlaceholder")} aria-invalid={actionBad} onChange={set(setAction)} />
        {actionBad ? <p className="hint text-danger">{t("audit.actionInvalid")}</p> : null}
      </div>
      <div>
        <label htmlFor="audit-outcome" className="label">
          {t("audit.outcome")}
        </label>
        <select id="audit-outcome" className="select" value={outcome} onChange={set(setOutcome)}>
          <option value="">{t("common.all")}</option>
          {OUTCOMES.map((o) => (
            <option key={o} value={o}>
              {t(`audit.outcomes.${o}`)}
            </option>
          ))}
        </select>
      </div>
      <div>
        <label htmlFor="audit-from" className="label">
          {t("audit.from")}
        </label>
        <input id="audit-from" type="datetime-local" className="input" value={from} onChange={set(setFrom)} />
      </div>
      <div>
        <label htmlFor="audit-to" className="label">
          {t("audit.to")}
        </label>
        <input id="audit-to" type="datetime-local" className="input" value={to} aria-invalid={rangeBad} onChange={set(setTo)} />
        {rangeBad ? <p className="hint text-danger">{t("audit.rangeInvalid")}</p> : null}
      </div>
      <div className="flex items-end gap-2">
        <button type="submit" className="btn-primary" disabled={actorBad || actionBad || rangeBad}>
          {t("common.search")}
        </button>
        <button
          type="button"
          className="btn-secondary"
          onClick={() => {
            onApply({});
          }}
        >
          {t("audit.clear")}
        </button>
      </div>
    </form>
  );
}

/** Mã actor (`actor.kind` — G4b-E13); server cũ không trả ⇒ suy từ loại. */
export function actorKindOf(actor: AuditEvent["actor"]): string {
  if (actor.kind) return actor.kind;
  return actor.type === "identity" ? "user" : actor.type === "support" ? "support" : "system";
}

/**
 * Người thực hiện (G4b-E13 — một quy ước cho mọi màn hình): người dùng / nhân viên hỗ trợ ⇒ tên hiển thị (tên hiện tại
 * của danh tính khi server đọc được, nếu không thì ảnh chụp lúc ghi) kèm e-mail nhỏ, ID danh tính ở tooltip; hệ thống ⇒
 * nhãn đã dịch theo mã actor, ảnh chụp thô (mã job, lệnh, mô tả tiếng Anh) chỉ ở tooltip. Hành động của support mang
 * grant (§8.7 bước 3).
 */
export function ActorCell({ actor }: { actor: AuditEvent["actor"] }) {
  const { t, i18n } = useTranslation();
  const kind = actorKindOf(actor);
  const person = actor.type !== "system";
  const kindKey = `audit.actorKinds.${kind}`;
  const label = i18n.exists(kindKey) ? t(kindKey) : t("audit.actorKinds.system");
  const name = person ? (actor.display_name ?? t("audit.unknownUser")) : label;
  const title = person
    ? actor.identity_id
      ? t("audit.actorIdTooltip", { id: actor.identity_id })
      : undefined
    : actor.display_name
      ? t("audit.actorRaw", { raw: actor.display_name })
      : undefined;
  return (
    <div className="space-y-1" data-actor-kind={kind}>
      <div title={title} data-testid="actor-name">
        {name}
      </div>
      {person && actor.email && actor.email !== name ? (
        <div className="hint break-all" data-testid="actor-email">
          {actor.email}
        </div>
      ) : null}
      {actor.type === "identity" ? null : (
        <StatusBadge tone={actor.type === "support" ? "warn" : "neutral"} testId={`actor-${actor.type}`}>
          {t(`audit.actorTypes.${actor.type}`)}
        </StatusBadge>
      )}
      {actor.support_grant_id ? (
        <div className="hint font-mono" title={actor.support_grant_id}>
          {t("audit.grant", { id: actor.support_grant_id.slice(0, 8) })}
        </div>
      ) : null}
    </div>
  );
}

function AuditTable({ items }: { items: AuditEvent[] }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState<string | null>(null);
  return (
    <div className="relative overflow-x-auto rounded-lg border border-line bg-surface">
      <table className="data-table">
        <caption className="sr-only">{t("audit.caption")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("audit.col.time")}</th>
            <th scope="col">{t("audit.col.actor")}</th>
            <th scope="col">{t("audit.col.action")}</th>
            <th scope="col">{t("audit.col.resource")}</th>
            <th scope="col">{t("audit.col.outcome")}</th>
            <th scope="col">
              <span className="sr-only">{t("audit.col.details")}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {items.map((e) => (
            <Fragment key={e.id}>
              <tr data-testid="audit-row" data-actor-type={e.actor.type}>
                <td>
                  <Timestamp iso={e.occurred_at} relative={false} />
                </td>
                <td>
                  <ActorCell actor={e.actor} />
                </td>
                <td>
                  <code className="text-xs">{e.action}</code>
                </td>
                <td>
                  <code className="text-xs break-all">{`${e.resource.type}${e.resource.id ? `:${e.resource.id}` : ""}`}</code>
                </td>
                <td>
                  <StatusBadge tone={OUTCOME_TONE[e.outcome]}>{t(`audit.outcomes.${e.outcome}`)}</StatusBadge>
                </td>
                <td>
                  <button
                    type="button"
                    className="btn-secondary"
                    aria-expanded={open === e.id}
                    aria-controls={`audit-details-${e.id}`}
                    onClick={() => {
                      setOpen(open === e.id ? null : e.id);
                    }}
                  >
                    {t("audit.details")}
                  </button>
                </td>
              </tr>
              {open === e.id ? (
                <tr id={`audit-details-${e.id}`}>
                  <td colSpan={6}>
                    <p className="hint mb-2">
                      {t("audit.requestId")} <code>{e.request_id}</code>
                    </p>
                    <JsonBlock value={e.details} />
                  </td>
                </tr>
              ) : null}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}
