// Một version policy (P4-T11, §7.3, §12.3 Access Policies): nội dung (form hoặc HuJSON), báo cáo kiểm tra, diff, vòng đời
// — lưu (PATCH, If-Match = revision), kiểm tra (validate: render + lint + CheckPolicy), gửi duyệt, duyệt (content_sha256
// của bản đã xem; 4-eyes: ẩn với người soạn/gửi — server quyết định), từ chối (lý do), áp dụng/rollback (202 + job
// policy.apply, step-up 401 reauth_required), tạo bản nháp mới từ nội dung này. 412 (bản đã đổi) ⇒ tải lại; 409
// stale_base ⇒ giải thích + soạn lại trên version mong muốn hiện tại.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { api, call, callWithResponse } from "../../api/client";
import { ifMatch, isStaleVersion } from "../../api/etag";
import { useIdempotentMutation } from "../../api/idempotency";
import { tenantJobFromLocation } from "../../api/jobs";
import { ApiError } from "../../api/problem";
import { isUuid } from "../../api/queryClient";
import { can } from "../../auth/permissions";
import { useSession } from "../../auth/session";
import { Loading, Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { NotFoundPage } from "../../pages/StatusPages";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { useTenant } from "../TenantScope";
import { policyKeys, usePolicyCurrent, usePolicyNames, usePolicyVersion, usePolicyVersions } from "./api";
import { ApplyJobPanel } from "./AppliedState";
import { HuJSONPanel, useExport } from "./HuJSONPanel";
import {
  ackRulesInReport,
  canRollbackTo,
  isEditable,
  isStaleBase,
  localProblems,
  namesFrom,
  reviewActions,
  sameSource,
  toSourceBody,
  type PolicyFinding,
  type PolicySource,
  type PolicyVersion,
} from "./model";
import { PolicyForm } from "./PolicyForm";
import { DiffPanel, ReportPanel } from "./ReportAndDiff";
import { TemplatePanel } from "./TemplatePanel";

export function PolicyVersionPage() {
  const { versionId: raw = "" } = useParams();
  const id = raw.toLowerCase();
  if (!isUuid(id)) return <NotFoundPage />;
  return <VersionView key={id} versionId={id} />;
}

type Dialog = "approve" | "reject" | "apply" | "rollback" | null;
type Transition = "validate" | "submit" | "approve" | "reject";

function hasResourceRefs(s: PolicySource | undefined): boolean {
  return JSON.stringify(s ?? {}).includes('"type":"resource"');
}

function VersionView({ versionId }: { versionId: string }) {
  const { t } = useTranslation();
  const { tenantId, role, readOnly } = useTenant();
  const identityId = useSession().data?.principal.identity_id;
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const jobParam = (params.get("job") ?? "").toLowerCase();
  const jobId = isUuid(jobParam) ? jobParam : null;

  const q = usePolicyVersion(tenantId, versionId);
  const current = usePolicyCurrent(tenantId);
  const names = usePolicyNames(tenantId, role);
  const list = usePolicyVersions(tenantId, undefined);
  const [edit, setEdit] = useState<PolicySource | null>(null);
  const [mode, setMode] = useState<"form" | "hujson">("form");
  const [hujson, setHujson] = useState<{ text: string; warnings: PolicyFinding[] }>({ text: "", warnings: [] });
  const [extra, setExtra] = useState<Map<string, string>>(() => new Map());
  const [stale, setStale] = useState(false);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [reviewed, setReviewed] = useState(false);
  const [reason, setReason] = useState("");
  const exporter = useExport();

  const v = q.data?.data;
  // tên của tài nguyên mạng (chưa có API danh mục — P4-T12): lấy qua export của chính nội dung này
  const resourceNames = useQuery({
    queryKey: policyKeys.version(tenantId, `${versionId}:names:${String(v?.revision ?? 0)}`),
    queryFn: () =>
      call(api.POST("/tenants/{tenantId}/policies/export", { params: { path: { tenantId } }, body: { source: toSourceBody(v?.source ?? { grants: [] }) } }), {
        notify: false,
      }),
    enabled: v !== undefined && hasResourceRefs(v.source),
    staleTime: Infinity,
  });

  const store = (next: PolicyVersion) => {
    queryClient.setQueryData(policyKeys.version(tenantId, next.id), { data: next, etag: next.etag });
    void queryClient.invalidateQueries({ queryKey: groupKey(tenantId, "list") });
    void queryClient.invalidateQueries({ queryKey: groupKey(tenantId, "current") });
    void queryClient.invalidateQueries({ queryKey: groupKey(tenantId, "diff") });
  };
  const onWriteError = (e: Error) => {
    if (isStaleVersion(e)) setStale(true);
  };
  const etag = q.data?.etag ?? v?.etag ?? null;

  const save = useMutation({
    mutationFn: (source: PolicySource) =>
      call(
        api.PATCH("/tenants/{tenantId}/policies/{versionId}", {
          params: { path: { tenantId, versionId }, header: ifMatch(etag) },
          body: { source: toSourceBody(source) },
        }),
      ),
    onSuccess: (next) => {
      store(next);
      setEdit(null);
    },
    onError: onWriteError,
  });
  const transition = useMutation({
    mutationFn: ({ action }: { action: Transition }) => {
      const params = { path: { tenantId, versionId }, header: ifMatch(etag) };
      switch (action) {
        case "validate":
          return call(api.POST("/tenants/{tenantId}/policies/{versionId}/validate", { params }));
        case "submit":
          return call(api.POST("/tenants/{tenantId}/policies/{versionId}/submit", { params }));
        case "approve":
          return call(api.POST("/tenants/{tenantId}/policies/{versionId}/approve", { params, body: { content_sha256: v?.content_sha256 ?? "" } }));
        case "reject":
          return call(api.POST("/tenants/{tenantId}/policies/{versionId}/reject", { params, body: { reason: reason.trim() } }));
      }
    },
    onSuccess: (next) => {
      store(next);
      setDialog(null);
    },
    onError: onWriteError,
  });
  const accept = useIdempotentMutation({
    fingerprint: (kind: "apply" | "rollback") => `${kind}:${versionId}`,
    mutationFn: async (kind: "apply" | "rollback", key: string) => {
      const params = { path: { tenantId, versionId }, header: { "Idempotency-Key": key } };
      const r =
        kind === "apply"
          ? await callWithResponse(api.POST("/tenants/{tenantId}/policies/{versionId}/apply", { params }))
          : await callWithResponse(api.POST("/tenants/{tenantId}/policies/{versionId}/rollback", { params }));
      return { kind, data: r.data, job: tenantJobFromLocation(r.response.headers.get("Location"), tenantId) ?? r.data.job.id };
    },
    onSuccess: ({ kind, data, job }) => {
      store(data.version);
      setDialog(null);
      if (kind === "rollback") void navigate(`/t/${tenantId}/policies/${data.version.id}?job=${job}`);
      else setParams({ job }, { replace: true });
    },
  });
  const newDraft = useIdempotentMutation({
    mutationFn: (source: PolicySource, key: string) =>
      call(api.POST("/tenants/{tenantId}/policies", { params: { path: { tenantId }, header: { "Idempotency-Key": key } }, body: { source: toSourceBody(source) } })),
    onSuccess: (created) => {
      void queryClient.invalidateQueries({ queryKey: groupKey(tenantId, "list") });
      void navigate(`/t/${tenantId}/policies/${created.id}`);
    },
  });

  if (q.error instanceof ApiError && q.error.status === 404) return <NotFoundPage />;
  if (q.isPending) return <Loading />;
  if (q.isError || !v) {
    return (
      <Page title={t("nav.tenant.policies")}>
        <ProblemAlert error={q.error} onRetry={() => void q.refetch()} />
      </Page>
    );
  }

  const canEdit = can(role, "tenant.policy:edit") && !readOnly;
  const canApprove = can(role, "tenant.policy:approve") && !readOnly;
  const canApply = can(role, "tenant.policy:apply") && !readOnly;
  const editable = canEdit && isEditable(v);
  const source = edit ?? v.source;
  const dirty = edit !== null && v.source !== undefined && !sameSource(edit, v.source);
  const problems = edit ? localProblems(edit) : [];
  const report = v.validation_report;
  const findings = [...(report?.errors ?? []), ...(report?.warnings ?? []), ...(report?.info ?? [])];
  const fourEyes = current.data?.four_eyes ?? false;
  const review = reviewActions(v, { fourEyes, identityId, canEdit, canApprove, role });
  const staleBase = isStaleBase(v, current.data);
  const extraNames = namesFrom(resourceNames.data?.principals, new Map(extra));
  const identities = names.data?.identities;
  const who = (id: string | undefined) => (id ? (identities?.get(id) ?? id.slice(0, 8)) : t("common.none"));
  const busy = save.isPending || transition.isPending || accept.isPending;
  const lifecycleBlocked = dirty || busy;
  const acceptError = accept.error;
  const staleBaseError =
    acceptError instanceof ApiError && acceptError.code === "conflict" && (staleBase || (acceptError.problem?.detail ?? "").includes("stale_base"));

  const toHuJSON = () => {
    if (!source) return;
    exporter.mutate(source, {
      onSuccess: (r) => {
        setHujson({ text: r.hujson, warnings: r.warnings });
        setExtra((m) => namesFrom(r.principals, new Map(m)));
        setMode("hujson");
      },
    });
  };

  return (
    <Page
      title={t("policies.versionN", { n: v.version })}
      actions={
        <Link to={`/t/${tenantId}/policies`} className="link text-sm">
          {t("policies.backToList")}
        </Link>
      }
    >
      {readOnly ? <p className="mb-3 text-sm text-muted">{t("ui.readOnlyActions")}</p> : null}
      {stale ? (
        <div role="alert" className="mb-4 rounded-md border border-warn/40 bg-warn-bg p-4 text-sm" data-testid="stale-revision">
          <p className="font-semibold">{t("policies.stale.title")}</p>
          <p>{t("policies.stale.body")}</p>
          <button
            type="button"
            className="btn-secondary mt-2"
            onClick={() => {
              setStale(false);
              setEdit(null);
              save.reset();
              transition.reset();
              void q.refetch();
            }}
          >
            {t("policies.stale.reload")}
          </button>
        </div>
      ) : null}
      {jobId ? (
        <div className="mb-4">
          <ApplyJobPanel jobId={jobId} />
        </div>
      ) : null}

      <section className="card mb-4" aria-labelledby="pol-meta">
        <h2 id="pol-meta" className="sr-only">
          {t("policies.meta.title")}
        </h2>
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <StatusBadge status={v.state} testId="version-state">
            {t(`policies.states.${v.state}`)}
          </StatusBadge>
          <span className="badge">{t(`policies.kinds.${v.kind}`)}</span>
          {v.desired ? <StatusBadge tone="ok">{t("policies.desiredBadge")}</StatusBadge> : null}
          {v.review_mode ? <span className="badge">{t(`policies.reviewModes.${v.review_mode}`)}</span> : null}
        </div>
        <dl className="grid gap-x-6 gap-y-1 text-sm md:grid-cols-[max-content_1fr]">
          <dt className="text-muted">{t("policies.meta.revision")}</dt>
          <dd>
            <code data-testid="version-etag">{v.etag}</code>
          </dd>
          <dt className="text-muted">{t("policies.meta.content")}</dt>
          <dd>
            <code className="break-all" data-testid="content-sha">
              {v.content_sha256}
            </code>
          </dd>
          <dt className="text-muted">{t("policies.meta.createdBy")}</dt>
          <dd>
            {who(v.created_by)} · <Timestamp iso={v.created_at} />
          </dd>
          {v.submitted_by ? (
            <>
              <dt className="text-muted">{t("policies.meta.submittedBy")}</dt>
              <dd>
                {who(v.submitted_by)} · <Timestamp iso={v.submitted_at} />
              </dd>
            </>
          ) : null}
          {v.approved_by ? (
            <>
              <dt className="text-muted">{t("policies.meta.approvedBy")}</dt>
              <dd data-testid="approved-by">
                {who(v.approved_by)} · <Timestamp iso={v.approved_at} />
              </dd>
            </>
          ) : null}
          {v.rejected_by ? (
            <>
              <dt className="text-muted">{t("policies.meta.rejectedBy")}</dt>
              <dd>
                {who(v.rejected_by)} · <Timestamp iso={v.rejected_at} /> — {v.rejected_reason}
              </dd>
            </>
          ) : null}
          {v.parent_version_id ? (
            <>
              <dt className="text-muted">{t("policies.meta.parent")}</dt>
              <dd>
                <Link className="link" to={`/t/${tenantId}/policies/${v.parent_version_id}`}>
                  {v.parent_version_id.slice(0, 8)}
                </Link>
                {staleBase ? <span className="ms-2 badge badge-warn">{t("policies.meta.staleBase")}</span> : null}
              </dd>
            </>
          ) : null}
          {v.rollback_of ? (
            <>
              <dt className="text-muted">{t("policies.meta.rollbackOf")}</dt>
              <dd>
                <Link className="link" to={`/t/${tenantId}/policies/${v.rollback_of}`}>
                  {v.rollback_of.slice(0, 8)}
                </Link>
              </dd>
            </>
          ) : null}
        </dl>
      </section>

      {/* ---- vòng đời */}
      <section className="card mb-4 space-y-3" aria-labelledby="pol-actions" data-testid="policy-actions">
        <h2 id="pol-actions" className="font-semibold">
          {t("policies.actions.title")}
        </h2>
        {dirty ? <p className="text-sm text-warn">{t("policies.actions.saveFirst")}</p> : null}
        {review.blockedBy === "self" ? (
          <p className="text-sm" data-testid="four-eyes-self">
            {t("policies.actions.fourEyesSelf")}
          </p>
        ) : null}
        {review.blockedBy === "owner" ? <p className="text-sm">{t("policies.actions.ownerOnly")}</p> : null}
        <div className="flex flex-wrap gap-2">
          {editable ? (
            <button type="button" className="btn-secondary" disabled={lifecycleBlocked} onClick={() => transition.mutate({ action: "validate" })}>
              {t("policies.actions.validate")}
            </button>
          ) : null}
          {review.submit ? (
            <button type="button" className="btn-secondary" disabled={lifecycleBlocked} onClick={() => transition.mutate({ action: "submit" })}>
              {t("policies.actions.submit")}
            </button>
          ) : null}
          {review.approve ? (
            <button type="button" className="btn-primary" disabled={lifecycleBlocked} onClick={() => { setReviewed(false); transition.reset(); setDialog("approve"); }}>
              {t(fourEyes ? "policies.actions.approve" : "policies.actions.selfApprove")}
            </button>
          ) : null}
          {review.reject ? (
            <button type="button" className="btn-secondary" disabled={lifecycleBlocked} onClick={() => { setReason(""); transition.reset(); setDialog("reject"); }}>
              {t("policies.actions.reject")}
            </button>
          ) : null}
          {canApply && v.kind === "user" && v.state === "approved" ? (
            <button type="button" className="btn-primary" disabled={lifecycleBlocked} onClick={() => { accept.reset(); setDialog("apply"); }}>
              {t(v.desired ? "policies.actions.reapply" : "policies.actions.apply")}
            </button>
          ) : null}
          {canApply && canRollbackTo(v) ? (
            <button type="button" className="btn-secondary" disabled={lifecycleBlocked} onClick={() => { accept.reset(); setDialog("rollback"); }}>
              {t("policies.actions.rollback")}
            </button>
          ) : null}
          {canEdit && v.kind === "user" && v.source ? (
            <button type="button" className="btn-secondary" disabled={busy || newDraft.isPending} onClick={() => v.source && newDraft.mutate(v.source)}>
              {t("policies.actions.newDraft")}
            </button>
          ) : null}
        </div>
        {transition.isError && dialog === null ? <ProblemAlert error={transition.error} /> : null}
        {newDraft.isError ? <ProblemAlert error={newDraft.error} /> : null}
        {staleBaseError && dialog === null ? (
          <div role="alert" className="rounded-md border border-warn/40 bg-warn-bg p-3 text-sm" data-testid="stale-base">
            <p className="font-semibold">{t("policies.staleBase.title")}</p>
            <p>{t("policies.staleBase.body")}</p>
          </div>
        ) : null}
        {acceptError && dialog === null ? <ProblemAlert error={acceptError} /> : null}
      </section>

      {/* ---- nội dung */}
      <section className="card mb-4 space-y-3" aria-labelledby="pol-content">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 id="pol-content" className="font-semibold">
            {t("policies.content.title")}
          </h2>
          {source ? (
            <div role="radiogroup" aria-label={t("policies.content.mode")} className="flex gap-1">
              <button type="button" role="radio" aria-checked={mode === "form"} className={mode === "form" ? "btn-primary" : "btn-secondary"} onClick={() => setMode("form")}>
                {t("policies.content.form")}
              </button>
              <button
                type="button"
                role="radio"
                aria-checked={mode === "hujson"}
                className={mode === "hujson" ? "btn-primary" : "btn-secondary"}
                disabled={exporter.isPending || problems.length > 0}
                onClick={toHuJSON}
              >
                {t("policies.content.hujson")}
              </button>
            </div>
          ) : null}
        </div>
        {exporter.isError ? <ProblemAlert error={exporter.error} /> : null}
        {!source ? (
          <div>
            <p className="text-sm text-muted">{t("policies.content.platformText")}</p>
            <pre tabIndex={0} className="mt-2 max-h-96 overflow-auto rounded-md border border-line bg-bg p-2 font-mono text-xs">
              {v.hujson}
            </pre>
          </div>
        ) : mode === "form" ? (
          <div className="space-y-4">
            {editable ? (
              <TemplatePanel
                source={source}
                catalog={names.data}
                onApply={(next, principals) => {
                  setEdit(next);
                  setExtra((m) => namesFrom(principals, new Map(m)));
                }}
              />
            ) : null}
            <PolicyForm
              source={source}
              onChange={editable ? (next) => setEdit(next) : undefined}
              catalog={names.data}
              extra={extraNames}
              findings={findings}
              ackNeeded={ackRulesInReport(report)}
            />
          </div>
        ) : (
          <HuJSONPanel
            text={hujson.text}
            onText={(text) => setHujson((h) => ({ ...h, text }))}
            exportWarnings={hujson.warnings}
            onImported={
              editable
                ? (imported, principals) => {
                    // xác nhận không nằm trong văn bản: giữ các xác nhận đang có của form
                    const acks = source.acknowledgements;
                    setEdit({ ...imported, ...(acks && acks.length > 0 ? { acknowledgements: acks } : {}) });
                    setExtra((m) => namesFrom(principals, new Map(m)));
                    setMode("form");
                  }
                : undefined
            }
          />
        )}
        {editable && mode === "form" ? (
          <div className="flex flex-wrap items-center gap-2 border-t border-line pt-3">
            <button type="button" className="btn-primary" disabled={!dirty || problems.length > 0 || save.isPending} onClick={() => edit && save.mutate(edit)}>
              {save.isPending ? t("common.working") : t("policies.content.save")}
            </button>
            <button type="button" className="btn-secondary" disabled={!dirty || save.isPending} onClick={() => setEdit(null)}>
              {t("policies.content.discard")}
            </button>
            {dirty ? <span className="text-sm text-warn">{t("policies.content.unsaved")}</span> : null}
            {problems.length > 0 ? (
              <span className="text-sm text-danger" data-testid="local-problems">
                {t("policies.content.localProblems", { count: problems.length })}
              </span>
            ) : null}
            {v.state !== "draft" ? <p className="hint w-full">{t("policies.content.backToDraft")}</p> : null}
          </div>
        ) : null}
        {save.isError ? <ProblemAlert error={save.error} /> : null}
        {problems.length > 0 ? (
          <ul className="list-disc ps-5 text-sm text-danger">
            {problems.map((p) => (
              <li key={`${p.path}:${p.key}`}>
                <code>{p.path}</code> {t(p.key)}
              </li>
            ))}
          </ul>
        ) : null}
      </section>

      <div className="mb-4">
        <ReportPanel version={v} />
      </div>
      {v.source || v.hujson ? <DiffPanel version={v} others={list.data?.items ?? []} /> : null}

      {/* ---- hộp xác nhận */}
      <ConfirmDialog
        isOpen={dialog === "approve"}
        onOpenChange={(o) => {
          if (!o) setDialog(null);
        }}
        title={t("policies.approve.title", { n: v.version })}
        description={
          <div className="space-y-2">
            <p>{t(fourEyes ? "policies.approve.peer" : "policies.approve.self")}</p>
            <p>
              {t("policies.approve.sha")} <code className="break-all">{v.content_sha256}</code>
            </p>
          </div>
        }
        confirmLabel={t("policies.actions.approve")}
        canConfirm={reviewed}
        pending={transition.isPending}
        error={transition.isError ? transition.error : undefined}
        onConfirm={() => transition.mutate({ action: "approve" })}
      >
        <label className="flex items-start gap-2 text-sm">
          <input type="checkbox" checked={reviewed} onChange={(e) => setReviewed(e.target.checked)} />
          <span>{t("policies.approve.reviewed")}</span>
        </label>
      </ConfirmDialog>
      <ConfirmDialog
        isOpen={dialog === "reject"}
        onOpenChange={(o) => {
          if (!o) setDialog(null);
        }}
        title={t("policies.reject.title", { n: v.version })}
        description={<p>{t("policies.reject.description")}</p>}
        confirmLabel={t("policies.actions.reject")}
        destructive
        canConfirm={reason.trim() !== ""}
        pending={transition.isPending}
        error={transition.isError ? transition.error : undefined}
        onConfirm={() => transition.mutate({ action: "reject" })}
      >
        <div>
          <label htmlFor="pol-reject-reason" className="label">
            {t("policies.reject.reason")}
          </label>
          <textarea id="pol-reject-reason" className="input" rows={3} maxLength={2000} value={reason} onChange={(e) => setReason(e.target.value)} />
        </div>
      </ConfirmDialog>
      <ConfirmDialog
        isOpen={dialog === "apply" || dialog === "rollback"}
        onOpenChange={(o) => {
          if (!o) setDialog(null);
        }}
        title={dialog === "rollback" ? t("policies.rollback.title", { n: v.version }) : t("policies.apply.title", { n: v.version })}
        description={
          <div className="space-y-2">
            <p>{dialog === "rollback" ? t("policies.rollback.description") : t("policies.apply.description")}</p>
            {dialog === "apply" && staleBase ? <p className="text-warn">{t("policies.staleBase.body")}</p> : null}
            {current.data?.apply_step_up ? <p className="text-muted">{t("policies.apply.stepUp")}</p> : null}
            <p className="text-muted">{t("policies.apply.converged")}</p>
          </div>
        }
        confirmLabel={dialog === "rollback" ? t("policies.actions.rollback") : t("policies.actions.apply")}
        pending={accept.isPending}
        error={accept.isError ? accept.error : undefined}
        onConfirm={() => {
          if (dialog === "apply" || dialog === "rollback") accept.mutate(dialog);
        }}
      >
        {staleBaseError ? (
          <p role="alert" className="text-sm text-warn" data-testid="stale-base-dialog">
            {t("policies.staleBase.title")}
          </p>
        ) : null}
      </ConfirmDialog>
    </Page>
  );
}

/** Tiền tố key của các truy vấn policies của tenant (để invalidate theo nhóm). */
function groupKey(tenantId: string, part: "list" | "current" | "diff") {
  return [...policyKeys.all(tenantId), part] as const;
}
