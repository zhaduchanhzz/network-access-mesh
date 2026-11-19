// DNS (P4-T12, §12.3; T-09, R-19): GET /tenants/{t}/dns — MagicDNS (luôn bật, `base_domain`), nameserver của version
// cấu hình đang hiệu lực, lần reconfigure chưa xong (`pending`). Đổi nameserver: PUT /dns/settings (`If-Match` = `etag`)
// sau hộp xác nhận nói rõ instance restart có kiểm soát và phiên relay bị ngắt ⇒ 202 + job `instance.reconfigure` — chỉ
// báo "đã áp dụng" khi job `succeeded`. Extra records: GET/POST /dns/records (Idempotency-Key ⇒ 201 {record, job}),
// DELETE /dns/records/{id} ⇒ 202 + job `dns.records_write` (ghi file, không restart). Bản ghi phải trỏ vào địa chỉ tailnet
// của thiết bị hoặc IP trong subnet route đã duyệt — server kiểm (422 field `value`, hiện cạnh ô nhập).
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useId, useState, type SyntheticEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, call, callWithResponse } from "../../api/client";
import { ifMatch, isStaleVersion } from "../../api/etag";
import { useIdempotentMutation } from "../../api/idempotency";
import { isSettled, tenantJobFromLocation, useTenantJob } from "../../api/jobs";
import { ApiError } from "../../api/problem";
import { queryKeys } from "../../api/queryClient";
import type { components } from "../../api/schema";
import { can } from "../../auth/permissions";
import { Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { EmptyState, QueryBlock } from "../../ui/Data";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { useTenant } from "../TenantScope";
import { FieldError, formLevelError, invalidProps, JobProgress, useFieldErrors } from "./networkBits";

type DnsView = components["schemas"]["DnsView"];
type DnsRecord = components["schemas"]["DnsRecord"];
type RecordType = components["schemas"]["DnsRecordType"];

export const MAX_NAMESERVERS = 8;
export const DNS_PENDING_POLL_MS = 5000;

/** Danh sách nameserver từ ô nhập (mỗi dòng/khoảng trắng/dấu phẩy một địa chỉ). */
export function parseNameservers(text: string): string[] {
  return text.split(/[\s,]+/).filter((s) => s !== "");
}

export function DnsPage() {
  const { t } = useTranslation();
  const { tenantId, role } = useTenant();
  const dns = useQuery({
    queryKey: queryKeys.tenant(tenantId, "dns", "view"),
    queryFn: () => call(api.GET("/tenants/{tenantId}/dns", { params: { path: { tenantId } } })),
    // lần reconfigure chưa xong: đọc lại tới khi server không còn báo pending
    refetchInterval: (q) => (q.state.data?.pending && !isSettled(q.state.data.pending.status) ? DNS_PENDING_POLL_MS : false),
  });
  const canUpdate = can(role, "tenant.dns:update");
  return (
    <Page title={t("nav.tenant.dns")}>
      <QueryBlock query={dns}>{(view) => <DnsSettings view={view} canUpdate={canUpdate} />}</QueryBlock>
      <DnsRecords canUpdate={canUpdate} baseDomain={dns.data?.base_domain ?? null} />
    </Page>
  );
}

function DnsSettings({ view, canUpdate }: { view: DnsView; canUpdate: boolean }) {
  const { t } = useTranslation();
  const { tenantId, readOnly } = useTenant();
  const queryClient = useQueryClient();
  const viewKey = queryKeys.tenant(tenantId, "dns", "view");
  const [text, setText] = useState(() => view.nameservers.join("\n"));
  const [confirming, setConfirming] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const update = useMutation({
    mutationFn: (nameservers: string[]) =>
      callWithResponse(
        api.PUT("/tenants/{tenantId}/dns/settings", { params: { path: { tenantId }, header: ifMatch(view.etag) }, body: { nameservers } }),
      ),
    onSuccess: ({ data, response }) => {
      setConfirming(false);
      setJobId(tenantJobFromLocation(response.headers.get("Location"), tenantId) ?? data.id);
      void queryClient.invalidateQueries({ queryKey: viewKey });
    },
    onError: (e) => {
      if (isStaleVersion(e)) void queryClient.invalidateQueries({ queryKey: viewKey });
      // lỗi theo field: đóng hộp để lỗi hiện ngay cạnh ô nhập
      if (e instanceof ApiError && e.code === "validation_failed") setConfirming(false);
    },
  });
  const refresh = useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: viewKey });
  }, [queryClient, viewKey]);

  const nameservers = parseNameservers(text);
  const localError =
    nameservers.length < 1 || nameservers.length > MAX_NAMESERVERS
      ? t("network.dns.nsCount", { max: MAX_NAMESERVERS })
      : new Set(nameservers).size !== nameservers.length
        ? t("network.dns.nsDuplicate")
        : undefined;
  const fieldError = useFieldErrors(update.error);
  const nsError = (text.trim() !== "" ? localError : undefined) ?? fieldError("nameservers");
  const unchanged = nameservers.join("\n") === view.nameservers.join("\n");
  // job đang theo dõi: của lần gửi này, hoặc lần reconfigure chưa xong mà server báo
  const trackedJob = jobId ?? (view.pending && !isSettled(view.pending.status) ? view.pending.job_id : null);
  // cùng query key với JobProgress (một lượt poll): chưa xong ⇒ khóa nút đổi tiếp
  const tracked = useTenantJob(tenantId, trackedJob);
  const running = trackedJob !== null && !tracked.isError && !isSettled(tracked.data?.status);
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    if (localError === undefined && !unchanged) {
      update.reset();
      setConfirming(true);
    }
  };

  return (
    <section className="card" aria-labelledby="dns-settings" data-testid="dns-settings">
      <h2 id="dns-settings" className="font-semibold">
        {t("network.dns.settingsTitle")}
      </h2>
      <dl className="mt-3 grid gap-x-6 gap-y-1 text-sm md:grid-cols-[max-content_1fr]">
        <dt className="text-muted">{t("network.dns.magicDns")}</dt>
        <dd>
          <StatusBadge tone="ok">{view.magic_dns ? t("network.dns.alwaysOn") : t("network.dns.off")}</StatusBadge>
        </dd>
        <dt className="text-muted">{t("network.dns.baseDomain")}</dt>
        <dd className="font-mono text-xs" data-testid="dns-base-domain">
          {view.base_domain}
        </dd>
        <dt className="text-muted">{t("network.dns.nameservers")}</dt>
        <dd data-testid="dns-nameservers">
          {view.nameservers.length > 0 ? (
            <ul className="font-mono text-xs">
              {view.nameservers.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          ) : (
            <span className="text-muted">{t("network.dns.noNameservers")}</span>
          )}
        </dd>
        <dt className="text-muted">{t("network.dns.configVersion")}</dt>
        <dd>{view.config_version ?? <span className="text-muted">{t("common.none")}</span>}</dd>
        <dt className="text-muted">{t("network.dns.records")}</dt>
        <dd>{view.records}</dd>
      </dl>
      {view.pending ? (
        <div className="mt-3 rounded-md border border-warn/40 bg-warn-bg p-3 text-sm" data-testid="dns-pending">
          <p>
            {t("network.dns.pending")}{" "}
            {view.pending.nameservers ? <code className="text-xs">{view.pending.nameservers.join(", ")}</code> : null}
          </p>
        </div>
      ) : null}
      {trackedJob ? (
        <JobProgress
          key={trackedJob}
          tenantId={tenantId}
          jobId={trackedJob}
          label={t("network.dns.jobLabel")}
          doneText={t("network.dns.applied")}
          onSucceeded={refresh}
          testId="dns-job"
        />
      ) : null}
      {canUpdate ? (
        <form className="mt-4 space-y-2" onSubmit={submit} aria-labelledby="dns-ns-title">
          <h3 id="dns-ns-title" className="text-sm font-semibold">
            {t("network.dns.changeTitle")}
          </h3>
          {readOnly ? <p className="text-sm text-muted">{t("ui.readOnlyActions")}</p> : null}
          <div>
            <label htmlFor="dns-ns" className="label">
              {t("network.dns.nsLabel", { max: MAX_NAMESERVERS })}
            </label>
            <textarea
              id="dns-ns"
              className="input font-mono"
              rows={3}
              value={text}
              disabled={readOnly}
              spellCheck={false}
              {...invalidProps("dns-ns", nsError, "dns-ns-hint")}
              onChange={(e) => {
                setText(e.target.value);
                if (update.isError) update.reset();
              }}
            />
            <p id="dns-ns-hint" className="hint">
              {t("network.dns.nsHint")}
            </p>
            <FieldError id="dns-ns" message={nsError} />
          </div>
          <button type="submit" className="btn-primary" disabled={readOnly || running || unchanged || localError !== undefined}>
            {t("network.dns.change")}
          </button>
          {update.isError && !confirming && formLevelError(update.error, ["nameservers"]) ? (
            <ProblemAlert error={formLevelError(update.error, ["nameservers"])} />
          ) : null}
        </form>
      ) : null}
      <ConfirmDialog
        isOpen={confirming}
        onOpenChange={(open) => {
          if (!open) {
            setConfirming(false);
            update.reset();
          }
        }}
        title={t("network.dns.confirmTitle")}
        description={
          <div className="space-y-2">
            <p className="font-semibold" data-testid="dns-restart-warning">
              {t("network.dns.confirmRestart")}
            </p>
            <p>{t("network.dns.confirmRelay")}</p>
            <p>
              {t("network.dns.confirmNew")} <code className="text-xs">{nameservers.join(", ")}</code>
            </p>
            {isStaleVersion(update.error) ? <p>{t("network.dns.stale")}</p> : null}
          </div>
        }
        confirmLabel={t("network.dns.confirm")}
        destructive
        pending={update.isPending}
        error={update.error ?? undefined}
        onConfirm={() => {
          update.mutate(nameservers);
        }}
      />
    </section>
  );
}

const RECORD_FIELDS = ["name", "type", "value"] as const;

function DnsRecords({ canUpdate, baseDomain }: { canUpdate: boolean; baseDomain: string | null }) {
  const { t } = useTranslation();
  const { tenantId, readOnly } = useTenant();
  const queryClient = useQueryClient();
  const recordsKey = queryKeys.tenant(tenantId, "dns", "records");
  const records = useQuery({
    queryKey: recordsKey,
    queryFn: () => call(api.GET("/tenants/{tenantId}/dns/records", { params: { path: { tenantId } } })),
  });
  const [job, setJob] = useState<{ id: string; kind: "create" | "delete" } | null>(null);
  const [deleting, setDeleting] = useState<DnsRecord | null>(null);
  const refresh = useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: recordsKey });
    void queryClient.invalidateQueries({ queryKey: queryKeys.tenant(tenantId, "dns", "view") });
  }, [queryClient, recordsKey, tenantId]);

  const remove = useMutation({
    mutationFn: (r: DnsRecord) =>
      callWithResponse(api.DELETE("/tenants/{tenantId}/dns/records/{recordId}", { params: { path: { tenantId, recordId: r.id } } })),
    onSuccess: ({ data, response }) => {
      setDeleting(null);
      setJob({ id: tenantJobFromLocation(response.headers.get("Location"), tenantId) ?? data.id, kind: "delete" });
      refresh();
    },
  });

  return (
    <section className="card mt-4" aria-labelledby="dns-records">
      <h2 id="dns-records" className="font-semibold">
        {t("network.dns.recordsTitle")}
      </h2>
      <p className="mt-1 text-sm text-muted">{t("network.dns.recordsIntro")}</p>
      {job ? (
        <JobProgress
          key={job.id}
          tenantId={tenantId}
          jobId={job.id}
          label={job.kind === "create" ? t("network.dns.recordJobCreate") : t("network.dns.recordJobDelete")}
          doneText={t("network.dns.recordWritten")}
          onSucceeded={refresh}
          testId="record-job"
        />
      ) : null}
      <div className="mt-3">
        <QueryBlock query={records}>
          {(data) =>
            data.items.length === 0 ? (
              <EmptyState>{t("network.dns.noRecords")}</EmptyState>
            ) : (
              <div className="overflow-x-auto">
                <table className="data-table" data-testid="records-table">
                  <caption className="sr-only">{t("network.dns.recordsTitle")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{t("network.dns.col.name")}</th>
                      <th scope="col">{t("network.dns.col.type")}</th>
                      <th scope="col">{t("network.dns.col.value")}</th>
                      <th scope="col">{t("network.dns.col.createdAt")}</th>
                      {canUpdate ? <th scope="col">{t("network.dns.col.actions")}</th> : null}
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((r) => (
                      <tr key={r.id} data-testid="record-row">
                        <td className="font-mono text-xs">{r.name}</td>
                        <td>{r.type}</td>
                        <td className="font-mono text-xs">{r.value}</td>
                        <td>
                          <Timestamp iso={r.created_at} relative={false} />
                        </td>
                        {canUpdate ? (
                          <td>
                            <button
                              type="button"
                              className="btn-secondary"
                              disabled={readOnly}
                              aria-label={t("network.dns.deleteFor", { name: r.name, type: r.type })}
                              onClick={() => {
                                remove.reset();
                                setDeleting(r);
                              }}
                            >
                              {t("network.dns.delete")}
                            </button>
                          </td>
                        ) : null}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          }
        </QueryBlock>
      </div>
      {canUpdate ? (
        <AddRecordForm
          baseDomain={baseDomain}
          disabled={readOnly}
          onCreated={(jobId) => {
            setJob({ id: jobId, kind: "create" });
            refresh();
          }}
        />
      ) : null}
      <ConfirmDialog
        isOpen={deleting !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDeleting(null);
            remove.reset();
          }
        }}
        title={t("network.dns.deleteTitle", { name: deleting?.name ?? "", type: deleting?.type ?? "" })}
        description={<p>{t("network.dns.deleteDesc", { value: deleting?.value ?? "" })}</p>}
        confirmLabel={t("network.dns.delete")}
        destructive
        pending={remove.isPending}
        error={remove.error ?? undefined}
        onConfirm={() => {
          if (deleting) remove.mutate(deleting);
        }}
      />
    </section>
  );
}

function AddRecordForm({ baseDomain, disabled, onCreated }: { baseDomain: string | null; disabled: boolean; onCreated: (jobId: string) => void }) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const id = useId();
  const [name, setName] = useState("");
  const [type, setType] = useState<RecordType>("A");
  const [value, setValue] = useState("");
  const create = useIdempotentMutation({
    mutationFn: (body: components["schemas"]["DnsRecordCreate"], key: string) =>
      call(api.POST("/tenants/{tenantId}/dns/records", { params: { path: { tenantId }, header: { "Idempotency-Key": key } }, body })),
    onSuccess: (r) => {
      setName("");
      setValue("");
      onCreated(r.job.id);
    },
  });
  const fieldError = useFieldErrors(create.error);
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    if (name.trim() !== "" && value.trim() !== "") create.mutate({ name: name.trim(), type, value: value.trim() });
  };
  const nameErr = fieldError("name");
  const typeErr = fieldError("type");
  const valueErr = fieldError("value");
  const shown = formLevelError(create.error, RECORD_FIELDS);
  return (
    <form className="mt-4 space-y-3" onSubmit={submit} aria-labelledby={`${id}-title`} data-testid="record-form">
      <h3 id={`${id}-title`} className="text-sm font-semibold">
        {t("network.dns.addTitle")}
      </h3>
      <div className="grid gap-3 md:grid-cols-[2fr_1fr_2fr]">
        <div>
          <label htmlFor={`${id}-name`} className="label">
            {t("network.dns.col.name")}
          </label>
          <input
            id={`${id}-name`}
            className="input font-mono"
            value={name}
            disabled={disabled}
            spellCheck={false}
            autoComplete="off"
            maxLength={253}
            {...invalidProps(`${id}-name`, nameErr, `${id}-name-hint`)}
            onChange={(e) => {
              setName(e.target.value.toLowerCase());
            }}
          />
          <p id={`${id}-name-hint`} className="hint">
            {baseDomain ? t("network.dns.nameHint", { domain: baseDomain }) : t("network.dns.nameHintGeneric")}
          </p>
          <FieldError id={`${id}-name`} message={nameErr} />
        </div>
        <div>
          <label htmlFor={`${id}-type`} className="label">
            {t("network.dns.col.type")}
          </label>
          <select
            id={`${id}-type`}
            className="select"
            value={type}
            disabled={disabled}
            {...invalidProps(`${id}-type`, typeErr)}
            onChange={(e) => {
              setType(e.target.value === "AAAA" ? "AAAA" : "A");
            }}
          >
            <option value="A">{t("network.dns.typeA")}</option>
            <option value="AAAA">{t("network.dns.typeAAAA")}</option>
          </select>
          <FieldError id={`${id}-type`} message={typeErr} />
        </div>
        <div>
          <label htmlFor={`${id}-value`} className="label">
            {t("network.dns.col.value")}
          </label>
          <input
            id={`${id}-value`}
            className="input font-mono"
            value={value}
            disabled={disabled}
            spellCheck={false}
            autoComplete="off"
            maxLength={64}
            {...invalidProps(`${id}-value`, valueErr, `${id}-value-hint`)}
            onChange={(e) => {
              setValue(e.target.value);
            }}
          />
          <p id={`${id}-value-hint`} className="hint">
            {t("network.dns.valueHint")}
          </p>
          <FieldError id={`${id}-value`} message={valueErr} />
        </div>
      </div>
      <button type="submit" className="btn-primary" disabled={disabled || create.isPending || name.trim() === "" || value.trim() === ""}>
        {create.isPending ? t("common.working") : t("network.dns.add")}
      </button>
      {shown ? <ProblemAlert error={shown} /> : null}
    </form>
  );
}
