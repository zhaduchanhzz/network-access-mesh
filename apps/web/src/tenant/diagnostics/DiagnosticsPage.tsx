// Connectivity Diagnostics (P5-T08, §12.3 "Trạng thái control plane + checklist lệnh chạy trên client (§9.5)", §13.2):
// - Trạng thái control plane (tenant.diagnostics:read — TO/TA/TP, staff có grant): GET /tenants/{t}/diagnostics/instance —
//   health của instance, edge, relay (DERP/STUN), policy đang áp, số thiết bị, hạn API key; mỗi phần kèm thời điểm quan
//   sát; phần không có nguồn hiển thị "không khả dụng" kèm lý do (không số giả).
// - Kiểm kết nối (tenant.diagnostics:run — TO/TA/TP, staff; End User chỉ với thiết bị của chính mình): POST
//   /tenants/{t}/diagnostics/connectivity — kết luận TỪ DỮ LIỆU CONTROL PLANE (server không quan sát được đường đi thật)
//   + các phép kiểm + checklist lệnh theo OS, mỗi lệnh có nút sao chép.
// Danh sách thiết bị lấy từ GET /devices (End User chỉ thấy thiết bị của mình — server lọc); tài nguyên chỉ khi có
// tenant.resource:read. Tenant chỉ-đọc (suspended) ⇒ nút kiểm bị khóa (server trả 403 tenant_suspended).
import { useMutation, useQuery } from "@tanstack/react-query";
import { useId, useState, type ReactNode, type SyntheticEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, call } from "../../api/client";
import { queryKeys } from "../../api/queryClient";
import type { components } from "../../api/schema";
import { can } from "../../auth/permissions";
import { Loading, Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { CodeLine } from "../../ui/Copy";
import { SelectField, TextField } from "../../ui/Form";
import { StatusBadge, UnavailableBox, useCodeText, type Tone } from "../../ui/Status";
import { ObservedAt, Timestamp } from "../../ui/time";
import { HEALTH_TONE } from "../dashboard/DashboardPage";
import { useTenant } from "../TenantScope";

type TenantDiagnostics = components["schemas"]["TenantDiagnostics"];
type Diagnosis = components["schemas"]["ConnectivityDiagnosis"];
type DiagCheck = components["schemas"]["DiagnosticsCheck"];
type DiagCommand = components["schemas"]["DiagnosticsCommand"];
type Os = DiagCommand["os"];

export const DIAGNOSTICS_POLL_MS = 60_000;
const LIST_LIMIT = 200;

export const OS_LIST: readonly Os[] = ["linux", "macos", "windows"];
export const VERDICT_TONE: Record<Diagnosis["verdict"], Tone> = { allowed: "ok", blocked: "danger", unknown: "warn" };
export const CHECK_TONE: Record<DiagCheck["status"], Tone> = {
  pass: "ok",
  fail: "danger",
  warn: "warn",
  unknown: "neutral",
  not_applicable: "neutral",
};
const EDGE_TONE: Record<TenantDiagnostics["edge"]["status"], Tone> = { reachable: "ok", unreachable: "danger", unknown: "warn" };
const KEY_TONE: Record<TenantDiagnostics["instance"]["api_key"]["status"], Tone> = {
  valid: "ok",
  expiring: "warn",
  expired: "danger",
  unknown: "neutral",
};

export function DiagnosticsPage() {
  const { t } = useTranslation();
  const { role } = useTenant();
  const canRead = can(role, "tenant.diagnostics:read");
  const canRun = can(role, "tenant.diagnostics:run");
  return (
    <Page title={t("nav.tenant.diagnostics")}>
      <p className="mb-2 text-sm text-muted">{t("diagnostics.intro")}</p>
      <p className="mb-6 rounded-md border border-line bg-surface p-3 text-sm" data-testid="diag-not-observable">
        {t("diagnostics.notObservable")}
      </p>
      {canRead ? <InstanceSection /> : null}
      {canRun ? <ConnectivitySection /> : null}
    </Page>
  );
}

// ------------------------------------------------------------------------------------------- control plane

function InstanceSection() {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const code = useCodeText();
  const q = useQuery({
    queryKey: queryKeys.tenant(tenantId, "diagnostics", "instance"),
    queryFn: () => call(api.GET("/tenants/{tenantId}/diagnostics/instance", { params: { path: { tenantId } } })),
    refetchInterval: DIAGNOSTICS_POLL_MS,
  });
  return (
    <section aria-labelledby="diag-instance" className="mb-8" data-testid="diag-instance">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 id="diag-instance" className="text-lg font-semibold">
          {t("diagnostics.instance.title")}
        </h2>
        {q.data ? <ObservedAt labelKey="diagnostics.readAt" iso={q.data.checked_at} /> : null}
      </div>
      {q.isPending ? <Loading /> : null}
      {q.isError ? <ProblemAlert error={q.error} onRetry={() => void q.refetch()} /> : null}
      {q.data ? (
        <>
          {q.data.tenant_status !== "active" ? (
            <p className="mb-3" data-testid="diag-tenant-status">
              {t("diagnostics.instance.tenantStatus")}{" "}
              <StatusBadge status={q.data.tenant_status}>{t(`status.tenant.${q.data.tenant_status}`)}</StatusBadge>
            </p>
          ) : null}
          <div className="grid gap-4 md:grid-cols-2">
            <InstanceCard d={q.data} />
            <EdgeCard d={q.data} />
            <PolicyCard d={q.data} />
            <DevicesCard d={q.data} />
          </div>
          <RelaysCard d={q.data} />
          {q.data.unavailable.length > 0 ? (
            <section className="mt-6" aria-labelledby="diag-unavailable">
              <h3 id="diag-unavailable" className="mb-2 font-semibold">
                {t("diagnostics.unavailableTitle")}
              </h3>
              <div className="grid gap-3 md:grid-cols-2">
                {q.data.unavailable.map((u) => (
                  <UnavailableBox
                    key={u.section}
                    title={code("diagnostics.sections", u.section)}
                    reason={code("diagnostics.reasons", u.reason)}
                    code={u.reason}
                  />
                ))}
              </div>
            </section>
          ) : null}
        </>
      ) : null}
    </section>
  );
}

function Card({ id, title, children, testId }: { id: string; title: string; children: ReactNode; testId: string }) {
  return (
    <section className="card" aria-labelledby={id} data-testid={testId}>
      <h3 id={id} className="mb-2 font-semibold">
        {title}
      </h3>
      {children}
    </section>
  );
}

function InstanceCard({ d }: { d: TenantDiagnostics }) {
  const { t } = useTranslation();
  const code = useCodeText();
  const h = d.instance.health;
  const key = d.instance.api_key;
  return (
    <Card id="diag-card-instance" title={t("diagnostics.instance.instance")} testId="diag-card-instance">
      <p>
        <StatusBadge tone={HEALTH_TONE[h.status]} testId="diag-instance-health">
          {t(`health.status.${h.status}`)}
        </StatusBadge>
        {d.instance.status ? <span className="ms-2 text-sm">{t(`status.instance.${d.instance.status}`)}</span> : null}
      </p>
      {h.reason ? <p className="mt-1 text-sm">{code("health.reason", h.reason, "health.reasonOther")}</p> : null}
      <ObservedAt labelKey="ui.checkedAt" iso={h.checked_at} />
      <p className="mt-3 text-sm">
        {t("diagnostics.instance.apiKey")}{" "}
        <StatusBadge tone={KEY_TONE[key.status]} testId="diag-api-key">
          {t(`diagnostics.apiKey.${key.status}`)}
        </StatusBadge>
      </p>
      {key.expires_at ? (
        <p className="mt-1 text-xs text-muted">
          {t("diagnostics.instance.apiKeyExpires")} <Timestamp iso={key.expires_at} />
        </p>
      ) : null}
    </Card>
  );
}

function EdgeCard({ d }: { d: TenantDiagnostics }) {
  const { t } = useTranslation();
  const code = useCodeText();
  return (
    <Card id="diag-card-edge" title={t("diagnostics.instance.edge")} testId="diag-card-edge">
      <p>
        <StatusBadge tone={EDGE_TONE[d.edge.status]} testId="diag-edge">
          {t(`diagnostics.edge.${d.edge.status}`)}
        </StatusBadge>
      </p>
      {d.edge.reason ? (
        <p className="mt-1 text-sm">
          {code("diagnostics.reasons", d.edge.reason)} <code>{`(${d.edge.reason})`}</code>
        </p>
      ) : null}
      <ObservedAt labelKey="ui.checkedAt" iso={d.edge.checked_at} />
      <p className="mt-2 text-xs text-muted">{t("diagnostics.instance.edgeHint")}</p>
    </Card>
  );
}

function PolicyCard({ d }: { d: TenantDiagnostics }) {
  const { t } = useTranslation();
  const p = d.policy;
  return (
    <Card id="diag-card-policy" title={t("diagnostics.instance.policy")} testId="diag-card-policy">
      {p.applied ? (
        <dl className="grid gap-x-4 gap-y-1 text-sm md:grid-cols-[max-content_1fr]">
          <dt className="text-muted">{t("diagnostics.policy.version")}</dt>
          <dd data-testid="diag-policy-version">{p.version ?? t("common.none")}</dd>
          <dt className="text-muted">{t("diagnostics.policy.sha")}</dt>
          <dd>
            <code className="text-xs" title={p.applied_sha256}>
              {p.applied_sha256?.slice(0, 12)}
            </code>
          </dd>
          <dt className="text-muted">{t("diagnostics.policy.appliedAt")}</dt>
          <dd>
            <Timestamp iso={p.applied_at} />
          </dd>
          {p.desired_version && p.desired_version !== p.version ? (
            <>
              <dt className="text-muted">{t("diagnostics.policy.desired")}</dt>
              <dd>{p.desired_version}</dd>
            </>
          ) : null}
        </dl>
      ) : (
        <p className="text-sm text-muted" data-testid="diag-policy-none">
          {t("diagnostics.policy.none")}
        </p>
      )}
      {p.latest_state === "failed" ? (
        <p className="mt-2 text-sm text-danger" data-testid="diag-policy-failed">
          {t("diagnostics.policy.latestFailed")} {p.latest_error_code ? <code>{p.latest_error_code}</code> : null}
        </p>
      ) : null}
    </Card>
  );
}

function DevicesCard({ d }: { d: TenantDiagnostics }) {
  const { t } = useTranslation();
  const c = d.devices;
  return (
    <Card id="diag-card-devices" title={t("diagnostics.instance.devices")} testId="diag-card-devices">
      {c.synced_at ? (
        <>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
            <dt className="text-muted">{t("diagnostics.devices.total")}</dt>
            <dd data-testid="diag-devices-total">{c.total}</dd>
            <dt className="text-muted">{t("diagnostics.devices.online")}</dt>
            <dd>{c.online}</dd>
            <dt className="text-muted">{t("diagnostics.devices.offline")}</dt>
            <dd>{c.offline}</dd>
            <dt className="text-muted">{t("diagnostics.devices.expired")}</dt>
            <dd data-testid="diag-devices-expired">{c.expired}</dd>
          </dl>
          <ObservedAt labelKey="ui.syncedAt" iso={c.synced_at} />
        </>
      ) : (
        <p className="text-sm text-muted" data-testid="diag-devices-unavailable">
          {t("ui.unavailable")} — {t("diagnostics.reasons.never_synced")}
        </p>
      )}
    </Card>
  );
}

function RelaysCard({ d }: { d: TenantDiagnostics }) {
  const { t } = useTranslation();
  const code = useCodeText();
  if (d.relays.length === 0) return null;
  return (
    <section className="card mt-4" aria-labelledby="diag-card-relays" data-testid="diag-card-relays">
      <h3 id="diag-card-relays" className="mb-2 font-semibold">
        {t("diagnostics.instance.relays")}
      </h3>
      <ul className="space-y-3">
        {d.relays.map((r) => (
          <li key={r.code} data-testid="diag-relay">
            <span className="font-medium">{r.name}</span> <code className="text-sm text-muted">{r.code}</code>{" "}
            <StatusBadge tone={HEALTH_TONE[r.health]}>{t(`health.status.${r.health}`)}</StatusBadge>
            {r.status !== "active" ? <span className="ms-2 text-sm">{t(`relay.adminStatuses.${r.status}`)}</span> : null}
            {r.reason ? <span className="ms-2 text-sm">{code("relay.healthReason", r.reason, "health.reasonOther")}</span> : null}
            <span className="ms-2 text-sm">
              {r.derp_ok !== undefined ? t(r.derp_ok ? "diagnostics.relay.derpOk" : "diagnostics.relay.derpFailed") : null}
              {r.stun_ok !== undefined ? ` · ${t(r.stun_ok ? "diagnostics.relay.stunOk" : "diagnostics.relay.stunFailed")}` : null}
            </span>
            <ObservedAt labelKey="ui.checkedAt" iso={r.checked_at} />
          </li>
        ))}
      </ul>
    </section>
  );
}

// ------------------------------------------------------------------------------------------- connectivity

type TargetKind = "device" | "resource";

function ConnectivitySection() {
  const { t } = useTranslation();
  const { tenantId, role, readOnly } = useTenant();
  const canResources = can(role, "tenant.resource:read");
  const devices = useQuery({
    queryKey: queryKeys.tenant(tenantId, "devices", "diagnostics"),
    queryFn: () => call(api.GET("/tenants/{tenantId}/devices", { params: { path: { tenantId }, query: { limit: LIST_LIMIT } } })),
  });
  const resources = useQuery({
    queryKey: queryKeys.tenant(tenantId, "resources", "diagnostics"),
    queryFn: () => call(api.GET("/tenants/{tenantId}/resources", { params: { path: { tenantId }, query: { limit: LIST_LIMIT } } })),
    enabled: canResources,
  });
  const [source, setSource] = useState("");
  const [kind, setKind] = useState<TargetKind>("device");
  const [target, setTarget] = useState("");
  const [port, setPort] = useState("");
  const [errors, setErrors] = useState<{ source?: string; target?: string; port?: string }>({});
  const run = useMutation({
    mutationFn: (body: components["schemas"]["ConnectivityDiagnosisRequest"]) =>
      call(api.POST("/tenants/{tenantId}/diagnostics/connectivity", { params: { path: { tenantId } }, body })),
  });
  const kindId = useId();

  const deviceItems = devices.data?.items ?? [];
  const resourceItems = resources.data?.items ?? [];
  const deviceOptions = [
    { value: "", label: t("diagnostics.form.choose") },
    ...deviceItems.map((d) => ({ value: d.id, label: `${d.given_name} (${d.ip_addresses[0] ?? d.name})` })),
  ];
  const targetOptions =
    kind === "device"
      ? deviceOptions.filter((o) => o.value === "" || o.value !== source)
      : [
          { value: "", label: t("diagnostics.form.choose") },
          ...resourceItems.map((r) => ({ value: r.id, label: `${r.name} (${r.address})` })),
        ];

  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    const errs: typeof errors = {};
    if (!source) errs.source = t("diagnostics.form.required");
    if (!target) errs.target = t("diagnostics.form.required");
    const p = port.trim();
    const n = Number(p);
    if (p !== "" && (!/^\d+$/.test(p) || n < 1 || n > 65535)) errs.port = t("diagnostics.form.portInvalid");
    setErrors(errs);
    if (Object.keys(errs).length > 0) return;
    run.mutate({
      source_device_id: source,
      ...(kind === "device" ? { target_device_id: target } : { target_resource_id: target }),
      ...(p !== "" ? { port: n } : {}),
    });
  };

  return (
    <section aria-labelledby="diag-connectivity" data-testid="diag-connectivity">
      <h2 id="diag-connectivity" className="mb-2 text-lg font-semibold">
        {t("diagnostics.connectivity.title")}
      </h2>
      <p className="mb-4 text-sm text-muted">{t("diagnostics.connectivity.intro")}</p>
      {devices.isError ? <ProblemAlert error={devices.error} onRetry={() => void devices.refetch()} /> : null}
      {devices.isPending ? <Loading /> : null}
      {devices.data && deviceItems.length === 0 ? (
        <p className="text-muted" data-testid="diag-no-devices">
          {t("diagnostics.form.noDevices")}
        </p>
      ) : null}
      {devices.data && deviceItems.length > 0 ? (
        <form className="card grid gap-4 md:grid-cols-2" onSubmit={submit} noValidate data-testid="diag-form">
          <SelectField
            label={t("diagnostics.form.source")}
            value={source}
            options={deviceOptions}
            error={errors.source}
            onChange={(v) => {
              setSource(v);
              if (kind === "device" && v === target) setTarget("");
            }}
          />
          <fieldset>
            <legend className="label">{t("diagnostics.form.targetKind")}</legend>
            <div className="flex gap-4">
              {(["device", "resource"] as const)
                .filter((k) => k === "device" || canResources)
                .map((k) => (
                  <label key={k} className="flex items-center gap-2 text-sm" htmlFor={`${kindId}-${k}`}>
                    <input
                      id={`${kindId}-${k}`}
                      type="radio"
                      name={`${kindId}-kind`}
                      value={k}
                      checked={kind === k}
                      onChange={() => {
                        setKind(k);
                        setTarget("");
                      }}
                    />
                    {t(`diagnostics.form.kinds.${k}`)}
                  </label>
                ))}
            </div>
          </fieldset>
          <SelectField
            label={kind === "device" ? t("diagnostics.form.targetDevice") : t("diagnostics.form.targetResource")}
            value={target}
            options={targetOptions}
            error={errors.target}
            onChange={setTarget}
          />
          <TextField
            label={t("diagnostics.form.port")}
            hint={t("diagnostics.form.portHint")}
            value={port}
            onChange={setPort}
            numeric
            maxLength={5}
            error={errors.port}
          />
          <div className="md:col-span-2">
            <button type="submit" className="btn-primary" disabled={readOnly || run.isPending} data-testid="diag-run">
              {run.isPending ? t("common.working") : t("diagnostics.form.run")}
            </button>
            {readOnly ? <p className="mt-2 text-sm text-muted">{t("ui.readOnlyActions")}</p> : null}
          </div>
        </form>
      ) : null}
      {run.isError ? (
        <div className="mt-4">
          <ProblemAlert error={run.error} />
        </div>
      ) : null}
      {run.data ? <DiagnosisView r={run.data} /> : null}
    </section>
  );
}

function DiagnosisView({ r }: { r: Diagnosis }) {
  const { t } = useTranslation();
  const code = useCodeText();
  const [os, setOs] = useState<Os>("linux");
  const osId = useId();
  const commands = r.commands.filter((c) => c.os === os);
  const target = r.target.device?.given_name ?? r.target.resource?.name ?? "";
  const access = r.policy.access;
  return (
    <section className="mt-6 space-y-6" aria-labelledby="diag-result" data-testid="diag-result">
      <div className="card">
        <h3 id="diag-result" className="font-semibold">
          {t("diagnostics.result.title", { source: r.source.given_name, target, port: r.port ?? t("diagnostics.result.anyPort") })}
        </h3>
        <p className="mt-2">
          <StatusBadge tone={VERDICT_TONE[r.verdict]} status={r.verdict} testId="diag-verdict">
            {t(`diagnostics.verdict.${r.verdict}`)}
          </StatusBadge>
        </p>
        <p className="mt-2 text-sm">{t(`diagnostics.verdictExplain.${r.verdict}`)}</p>
        <p className="mt-2 text-sm text-muted" data-testid="diag-result-not-observable">
          {t("diagnostics.notObservable")}
        </p>
        <ObservedAt labelKey="diagnostics.readAt" iso={r.checked_at} />
      </div>

      <section className="card" aria-labelledby="diag-checks">
        <h4 id="diag-checks" className="mb-2 font-semibold">
          {t("diagnostics.result.checks")}
        </h4>
        <ul className="space-y-1 text-sm">
          {r.checks.map((c) => (
            <li key={c.id} data-testid="diag-check" data-check={c.id} data-status={c.status}>
              <StatusBadge tone={CHECK_TONE[c.status]}>{t(`diagnostics.checkStatus.${c.status}`)}</StatusBadge>{" "}
              {t(`diagnostics.checks.${c.id}`)}
              {c.reason ? (
                <span className="text-muted">
                  {" — "}
                  {code("diagnostics.checkReasons", c.reason)}
                </span>
              ) : null}
            </li>
          ))}
        </ul>
        {access ? (
          <div className="mt-3 text-sm" data-testid="diag-access">
            <p>
              {t("diagnostics.result.grants", { count: access.grants.length })}
              {access.allowed.length > 0 ? (
                <>
                  {" "}
                  {t("diagnostics.result.allowedEntries")} <code>{access.allowed.join(", ")}</code>
                </>
              ) : null}
            </p>
            {access.unresolved.length > 0 ? (
              <p className="mt-1 text-muted">
                {t("diagnostics.result.unresolved")} <code>{access.unresolved.join(", ")}</code>
              </p>
            ) : null}
          </div>
        ) : null}
        {r.target.routers.length > 0 ? (
          <p className="mt-2 text-sm" data-testid="diag-routers">
            {t("diagnostics.result.routers")}{" "}
            {r.target.routers.map((rt) => `${rt.name}${rt.online ? "" : ` (${t("diagnostics.result.offline")})`}`).join(", ")}
          </p>
        ) : null}
      </section>

      <section className="card" aria-labelledby="diag-commands" data-testid="diag-commands">
        <h4 id="diag-commands" className="mb-1 font-semibold">
          {t("diagnostics.commands.title")}
        </h4>
        <p className="mb-3 text-sm text-muted">{t("diagnostics.commands.intro")}</p>
        <fieldset className="mb-4">
          <legend className="label">{t("diagnostics.commands.os")}</legend>
          <div className="flex flex-wrap gap-4">
            {OS_LIST.map((o) => (
              <label key={o} className="flex items-center gap-2 text-sm" htmlFor={`${osId}-${o}`}>
                <input
                  id={`${osId}-${o}`}
                  type="radio"
                  name={`${osId}-os`}
                  value={o}
                  checked={os === o}
                  onChange={() => {
                    setOs(o);
                  }}
                />
                {t(`diagnostics.os.${o}`)}
              </label>
            ))}
          </div>
        </fieldset>
        {os === "macos" ? <p className="mb-3 text-sm text-muted">{t("diagnostics.commands.macosNote")}</p> : null}
        <ol className="space-y-4">
          {commands.map((c, i) => (
            <li key={`${c.id}-${String(i)}`} data-testid="diag-command" data-command={c.id}>
              <p className="font-medium">
                {t(`diagnostics.commands.items.${c.id}.title`)}{" "}
                <span className="text-xs text-muted">({t(`diagnostics.commands.runOn.${c.run_on}`)})</span>
              </p>
              <CodeLine value={c.command} copyLabel={t("diagnostics.commands.copy", { command: c.command })} />
              <p className="mt-1 text-sm text-muted">
                {t(`diagnostics.commands.items.${c.id}.expect`, { code: r.relay_code ?? "mg-…" })}
              </p>
            </li>
          ))}
        </ol>
        <p className="mt-4 text-sm text-muted">{t("diagnostics.commands.mobileNote")}</p>
        <p className="mt-1 text-sm text-muted">{t("diagnostics.commands.pingNote")}</p>
      </section>
    </section>
  );
}
