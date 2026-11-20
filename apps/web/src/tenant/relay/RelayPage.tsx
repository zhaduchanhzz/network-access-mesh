// Mục Relay của tenant (P4-T04, §12.3; API P3-T05c): GET /tenants/{t}/relay — region DERP được gán (tham số công khai
// như client thấy trong DERP map), trạng thái quản trị, health của lần probe gần nhất kèm `checked_at` và hai phép kiểm
// (DERP, STUN). Số đo relay mà nền tảng không có (byte, throughput, kết nối…) ở `unavailable` ⇒ "không khả dụng" kèm lý
// do (§10.6 — không số giả).
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { api, call } from "../../api/client";
import { queryKeys } from "../../api/queryClient";
import type { components } from "../../api/schema";
import { Loading, Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { StatusBadge, UnavailableBox, useCodeText } from "../../ui/Status";
import { ObservedAt } from "../../ui/time";
import { HEALTH_TONE } from "../dashboard/DashboardPage";
import { useTenant } from "../TenantScope";

type Assignment = components["schemas"]["RelayAssignment"];
type Check = components["schemas"]["RelayCheck"];

export const RELAY_POLL_MS = 60_000;

export function RelayPage() {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const code = useCodeText();
  const relay = useQuery({
    queryKey: queryKeys.tenant(tenantId, "relay"),
    queryFn: () => call(api.GET("/tenants/{tenantId}/relay", { params: { path: { tenantId } } })),
    refetchInterval: RELAY_POLL_MS,
  });
  if (relay.isPending) return <Loading />;
  if (relay.isError) {
    return (
      <Page title={t("nav.tenant.relay")}>
        <ProblemAlert error={relay.error} onRetry={() => void relay.refetch()} />
      </Page>
    );
  }
  const { assignments, unavailable } = relay.data;
  return (
    <Page title={t("nav.tenant.relay")}>
      <p className="mb-4 text-sm text-muted">{t("relay.intro")}</p>
      {assignments.length === 0 ? (
        <p className="text-muted" data-testid="relay-empty">
          {t("relay.empty")}
        </p>
      ) : (
        <div className="space-y-4">
          {assignments.map((a) => (
            <AssignmentCard key={a.id} a={a} />
          ))}
        </div>
      )}
      {unavailable.length > 0 ? (
        <section className="mt-6" aria-labelledby="relay-unavailable">
          <h2 id="relay-unavailable" className="mb-2 font-semibold">
            {t("relay.unavailableTitle")}
          </h2>
          <div className="grid gap-3 md:grid-cols-2">
            {unavailable.map((u) => (
              <UnavailableBox
                key={u.metric}
                title={code("relay.metrics", u.metric, "relay.metrics.other")}
                reason={code("relay.reasons", u.reason)}
                code={u.reason}
              />
            ))}
          </div>
        </section>
      ) : null}
    </Page>
  );
}

function AssignmentCard({ a }: { a: Assignment }) {
  const { t } = useTranslation();
  const code = useCodeText();
  const r = a.region;
  return (
    <section className="card" aria-labelledby={`relay-${a.id}`} data-testid="relay-assignment">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 id={`relay-${a.id}`} className="font-semibold">
          {r.name} <code className="text-sm text-muted">{r.code}</code>
        </h2>
        <StatusBadge tone={HEALTH_TONE[a.health.status]} testId="relay-health">
          {t(`health.status.${a.health.status}`)}
        </StatusBadge>
      </div>
      {a.health.reason ? (
        <p className="mt-1 text-sm" title={a.health.reason}>
          {code("relay.healthReason", a.health.reason, "health.reasonOther")}
        </p>
      ) : null}
      <ObservedAt labelKey="ui.checkedAt" iso={a.health.checked_at} />
      <dl className="mt-3 grid gap-x-6 gap-y-1 text-sm md:grid-cols-[max-content_1fr]">
        <dt className="text-muted">{t("relay.kind")}</dt>
        <dd>{t(`relay.kinds.${r.kind}`)}</dd>
        <dt className="text-muted">{t("relay.hostname")}</dt>
        <dd className="font-mono text-xs">{r.hostname}</dd>
        <dt className="text-muted">{t("relay.derpRegion")}</dt>
        <dd>{r.derp_region_id}</dd>
        <dt className="text-muted">{t("relay.ports")}</dt>
        <dd className="font-mono text-xs">
          {r.stun_port ? t("relay.portsBoth", { derp: r.derp_port, stun: r.stun_port }) : t("relay.portsDerp", { derp: r.derp_port })}
        </dd>
        {r.ipv4 || r.ipv6 ? (
          <>
            <dt className="text-muted">{t("relay.addresses")}</dt>
            <dd className="font-mono text-xs">{[r.ipv4, r.ipv6].filter(Boolean).join(", ")}</dd>
          </>
        ) : null}
        <dt className="text-muted">{t("relay.verifyMode")}</dt>
        <dd>{t(`relay.verify.${r.verify_mode}`)}</dd>
        <dt className="text-muted">{t("relay.adminStatus")}</dt>
        <dd>{t(`relay.adminStatuses.${a.status}`)}</dd>
        <dt className="text-muted">{t("relay.priority")}</dt>
        <dd>{a.priority}</dd>
      </dl>
      {a.health.derp || a.health.stun ? (
        <ul className="mt-3 space-y-1 text-sm" aria-label={t("relay.checks")}>
          {a.health.derp ? <CheckLine name="DERP" c={a.health.derp} /> : null}
          {a.health.stun ? <CheckLine name="STUN" c={a.health.stun} /> : null}
        </ul>
      ) : null}
    </section>
  );
}

function CheckLine({ name, c }: { name: string; c: Check }) {
  const { t } = useTranslation();
  return (
    <li>
      <StatusBadge tone={c.ok ? "ok" : "danger"}>{c.ok ? t("relay.checkOk") : t("relay.checkFailed")}</StatusBadge>{" "}
      <span className="font-medium">{name}</span>
      {" · "}
      {t("relay.duration", { ms: c.duration_ms })}
      {c.status !== undefined ? <code className="ms-2">{t("relay.httpStatus", { status: c.status })}</code> : null}
      {c.code ? <code className="ms-2">{c.code}</code> : null}
    </li>
  );
}
