// Enrollment key + hàng chờ duyệt (P4-T08, §12.3 "Enrollment Key Management", §7.4 phương thức B và "Phê duyệt
// enrollment"): danh sách yêu cầu/key của tenant (lọc trạng thái, phân trang cursor), hàng chờ duyệt (`pending_approval` —
// duyệt/từ chối, người quyết khác người yêu cầu), thu hồi hai pha, tạo pre-auth key: một lần, hạn ≤ 15 phút qua
// POST /enrollment/requests; tùy chọn đặc quyền (gắn tag từ danh mục, reusable, ephemeral, cho thành viên khác, chỉ-tag)
// chỉ hiện với `tenant.enrollment:issue_privileged` và đi qua POST /enrollment/keys. Key hiển thị MỘT lần (Credential.tsx);
// replay sau hạn ⇒ 410 secret_no_longer_available ⇒ đề nghị thu hồi rồi tạo lại.
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, call } from "../../api/client";
import { ApiError } from "../../api/problem";
import { queryKeys } from "../../api/queryClient";
import { can } from "../../auth/permissions";
import { Page } from "../../components/Page";
import { ModalDialog } from "../../ui/Dialog";
import { QueryBlock } from "../../ui/Data";
import { useUsers } from "../people/api";
import { useTenant } from "../TenantScope";
import { createKey, createRequest, useEnrollmentList, useIssueMutation, useMemberNames, type NewKeyBody, type NewRequestBody } from "./api";
import { KeyRevealDialog, WebAuthCommand } from "./Credential";
import { LabelField, TtlField, WizardError } from "./AddDevicePage";
import { DEVICE_LABEL_RE, ENROLLMENT_STATUSES, TTL_MAX, type EnrollmentIssue, type EnrollmentStatus } from "./model";
import { RequestTable } from "./RequestTable";

export function KeysPage() {
  const { t } = useTranslation();
  const { tenantId, role, membershipId, readOnly } = useTenant();
  const canCreate = can(role, "tenant.enrollment:request") || can(role, "tenant.enrollment:issue_privileged");
  const canApprove = can(role, "tenant.enrollment:approve");
  const names = useMemberNames(tenantId, can(role, "tenant.user:read"));
  const [status, setStatus] = useState<EnrollmentStatus | "">("");
  const [cursors, setCursors] = useState<{ key: string; stack: string[] }>({ key: "", stack: [""] });
  const stack = cursors.key === status ? cursors.stack : [""];
  const cursor = stack[stack.length - 1] ?? "";
  const list = useEnrollmentList(tenantId, { status: status || undefined, cursor: cursor || undefined, limit: 50 });
  const queue = useEnrollmentList(tenantId, { status: "pending_approval" }, canApprove);
  const [creating, setCreating] = useState(false);
  const [keyIssue, setKeyIssue] = useState<EnrollmentIssue | null>(null);
  const [webIssue, setWebIssue] = useState<EnrollmentIssue | null>(null);
  const onIssued = (issue: EnrollmentIssue) => {
    if (issue.credential?.kind === "preauth_key") setKeyIssue(issue);
    else if (issue.credential) setWebIssue(issue);
  };
  const tableProps = { tenantId, role, membershipId, readOnly, names, wide: true, onIssued } as const;

  return (
    <Page
      title={t("nav.tenant.enrollmentKeys")}
      actions={
        canCreate ? (
          <button
            type="button"
            className="btn-primary"
            disabled={readOnly}
            onClick={() => {
              setCreating(true);
            }}
          >
            {t("enroll.key.create")}
          </button>
        ) : null
      }
    >
      <p className="mb-4 text-sm text-muted">{t("enroll.keys.intro")}</p>
      {readOnly && canCreate ? <p className="mb-3 text-sm text-muted">{t("ui.readOnlyActions")}</p> : null}
      {webIssue?.credential ? (
        <section className="mb-4 rounded-lg border border-line bg-surface p-4" data-testid="issued-web">
          <WebAuthCommand credential={webIssue.credential} />
          <button
            type="button"
            className="btn-secondary mt-3"
            onClick={() => {
              setWebIssue(null);
            }}
          >
            {t("enroll.issued.dismiss")}
          </button>
        </section>
      ) : null}
      {canApprove ? (
        <section aria-labelledby="enroll-queue" className="mb-8">
          <h2 id="enroll-queue" className="mb-2 text-lg font-semibold">
            {t("enroll.queue.title")}
          </h2>
          <QueryBlock query={queue}>
            {(data) => <RequestTable {...tableProps} items={data.items} caption={t("enroll.queue.title")} empty={t("enroll.queue.empty")} testId="approval-queue" />}
          </QueryBlock>
        </section>
      ) : null}
      <section aria-labelledby="enroll-all">
        <div className="mb-2 flex flex-wrap items-end justify-between gap-3">
          <h2 id="enroll-all" className="text-lg font-semibold">
            {t("enroll.keys.all")}
          </h2>
          <div>
            <label htmlFor="enroll-status" className="block text-xs font-medium text-muted">
              {t("enroll.col.status")}
            </label>
            <select
              id="enroll-status"
              className="select"
              value={status}
              onChange={(e) => {
                const v = ENROLLMENT_STATUSES.find((s) => s === e.target.value) ?? "";
                setStatus(v);
                setCursors({ key: v, stack: [""] });
              }}
            >
              <option value="">{t("common.all")}</option>
              {ENROLLMENT_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {t(`status.enrollment.${s}`)}
                </option>
              ))}
            </select>
          </div>
        </div>
        <QueryBlock query={list}>
          {(data) => <RequestTable {...tableProps} items={data.items} caption={t("enroll.keys.all")} empty={t("enroll.keys.empty")} testId="all-requests" />}
        </QueryBlock>
        <nav aria-label={t("ui.pagination")} className="mt-4 flex gap-2">
          <button type="button" className="btn-secondary" disabled={stack.length <= 1} onClick={() => setCursors({ key: status, stack: stack.slice(0, -1) })}>
            {t("ui.prevPage")}
          </button>
          <button
            type="button"
            className="btn-secondary"
            disabled={!list.data?.next_cursor}
            onClick={() => {
              const next = list.data?.next_cursor;
              if (next) setCursors({ key: status, stack: [...stack, next] });
            }}
          >
            {t("ui.nextPage")}
          </button>
        </nav>
      </section>
      <CreateKeyDialog
        isOpen={creating}
        onClose={() => {
          setCreating(false);
        }}
        onIssued={(issue) => {
          setCreating(false);
          onIssued(issue);
        }}
      />
      <KeyRevealDialog
        issue={keyIssue}
        onClose={() => {
          setKeyIssue(null);
        }}
      />
    </Page>
  );
}

type Owner = "self" | "member" | "tags";

function CreateKeyDialog({ isOpen, onClose, onIssued }: { isOpen: boolean; onClose: () => void; onIssued: (i: EnrollmentIssue) => void }) {
  const { t } = useTranslation();
  return (
    <ModalDialog
      isOpen={isOpen}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title={t("enroll.key.createTitle")}
    >
      <CreateKeyForm onCancel={onClose} onIssued={onIssued} />
    </ModalDialog>
  );
}

function CreateKeyForm({ onCancel, onIssued }: { onCancel: () => void; onIssued: (i: EnrollmentIssue) => void }) {
  const { t } = useTranslation();
  const { tenantId, role, membershipId, readOnly } = useTenant();
  const privileged = can(role, "tenant.enrollment:issue_privileged");
  const canSelf = can(role, "tenant.enrollment:request");
  const [owner, setOwner] = useState<Owner>(canSelf ? "self" : "member");
  const [target, setTarget] = useState("");
  const [tags, setTags] = useState<string[]>([]);
  const [reusable, setReusable] = useState(false);
  const [ephemeral, setEphemeral] = useState(false);
  const [label, setLabel] = useState("");
  const [ttl, setTtl] = useState(String(TTL_MAX));
  const [pending, setPending] = useState<string | null>(null);
  const users = useUsers(tenantId, {}, { enabled: privileged && can(role, "tenant.user:read"), limit: 200 });
  const catalog = useQuery({
    queryKey: queryKeys.tenant(tenantId, "tags", "options"),
    queryFn: () => call(api.GET("/tenants/{tenantId}/tags", { params: { path: { tenantId }, query: { limit: 200 } } })),
    enabled: privileged && can(role, "tenant.tag:read"),
    staleTime: 60_000,
  });
  const members = (users.data?.items ?? []).filter((m) => m.status === "active" && m.id !== membershipId);
  const labelBad = label !== "" && !DEVICE_LABEL_RE.test(label);
  const n = Number(ttl);
  const ttlBad = !Number.isInteger(n) || n < 1 || n > TTL_MAX;
  const usesPrivilege = privileged && (owner !== "self" || tags.length > 0 || reusable || ephemeral);
  const ownerBad = (owner === "member" && target === "") || (owner === "tags" && tags.length === 0) || (owner === "self" && !canSelf);

  const own = useIssueMutation(tenantId, (body: NewRequestBody, key: string) => createRequest(tenantId, body, key), (i) => {
    if (!i.credential) setPending(i.request.id);
    else onIssued(i);
  });
  const priv = useIssueMutation(tenantId, (body: NewKeyBody, key: string) => createKey(tenantId, body, key), onIssued);
  const busy = own.isPending || priv.isPending;
  const error = usesPrivilege ? priv.error : own.error;

  const submit = () => {
    if (labelBad || ttlBad || ownerBad || busy || readOnly) return;
    const common = { ...(label ? { device_label: label } : {}), ttl_minutes: n };
    if (usesPrivilege) {
      const target_membership_id = owner === "self" ? membershipId : owner === "member" ? target : null;
      priv.mutate({ target_membership_id, tags, reusable, ephemeral, ...common });
    } else {
      own.mutate({ method: "preauth_key", ...common });
    }
  };

  if (pending) {
    return (
      <div className="space-y-3">
        <p role="status" data-testid="pending-approval">
          {t("enroll.pendingApproval.body")}
        </p>
        <div className="flex justify-end">
          <button type="button" className="btn-secondary" onClick={onCancel}>
            {t("common.dismiss")}
          </button>
        </div>
      </div>
    );
  }
  const tagOptions = catalog.data?.items.map((x) => x.name) ?? [];
  return (
    <form
      className="space-y-3"
      noValidate
      onSubmit={(e) => {
        e.preventDefault();
        submit();
      }}
    >
      <p className="text-muted">{t("enroll.key.createHint", { max: TTL_MAX })}</p>
      {privileged ? (
        <fieldset className="space-y-1 text-sm" data-testid="key-owner">
          <legend className="font-semibold">{t("enroll.key.owner")}</legend>
          {(["self", "member", "tags"] as const).map((o) =>
            o === "self" && !canSelf ? null : (
              <label key={o} className="flex items-center gap-2">
                <input
                  type="radio"
                  name="key-owner"
                  checked={owner === o}
                  onChange={() => {
                    setOwner(o);
                  }}
                />
                {t(`enroll.key.owners.${o}`)}
              </label>
            ),
          )}
        </fieldset>
      ) : null}
      {privileged && owner === "member" ? (
        <div>
          <label htmlFor="key-target" className="label">
            {t("enroll.key.member")}
          </label>
          <select
            id="key-target"
            className="select w-full py-2"
            value={target}
            onChange={(e) => {
              setTarget(e.target.value);
            }}
          >
            <option value="">{t("enroll.key.pickMember")}</option>
            {members.map((m) => (
              <option key={m.id} value={m.id}>
                {m.email ? `${m.display_name} <${m.email}>` : m.display_name}
              </option>
            ))}
          </select>
        </div>
      ) : null}
      {privileged ? (
        <fieldset className="text-sm" data-testid="key-tags">
          <legend className="font-semibold">{t("enroll.key.tags")}</legend>
          <p className="hint">{t("enroll.key.tagsHint")}</p>
          {catalog.isError ? <WizardError error={catalog.error} /> : null}
          {catalog.isSuccess && tagOptions.length === 0 ? <p className="text-muted">{t("enroll.key.noTags")}</p> : null}
          <div className="mt-1 flex flex-wrap gap-3">
            {tagOptions.map((tag) => (
              <label key={tag} className="flex items-center gap-1 font-mono text-xs">
                <input
                  type="checkbox"
                  checked={tags.includes(tag)}
                  onChange={(e) => {
                    const on = e.target.checked;
                    setTags((cur) => (on ? [...cur, tag] : cur.filter((x) => x !== tag)));
                  }}
                />
                {tag}
              </label>
            ))}
          </div>
        </fieldset>
      ) : null}
      {privileged ? (
        <div className="space-y-1 text-sm">
          <label className="flex items-start gap-2">
            <input
              type="checkbox"
              className="mt-1"
              checked={reusable}
              onChange={(e) => {
                setReusable(e.target.checked);
              }}
            />
            <span>
              {t("enroll.key.reusable")}
              <span className="block text-muted">{t("enroll.key.reusableHint")}</span>
            </span>
          </label>
          <label className="flex items-start gap-2">
            <input
              type="checkbox"
              className="mt-1"
              checked={ephemeral}
              onChange={(e) => {
                setEphemeral(e.target.checked);
              }}
            />
            <span>
              {t("enroll.key.ephemeral")}
              <span className="block text-muted">{t("enroll.key.ephemeralHint")}</span>
            </span>
          </label>
        </div>
      ) : null}
      <LabelField value={label} onChange={setLabel} bad={labelBad} />
      <TtlField value={ttl} onChange={setTtl} bad={ttlBad} />
      {error ? <KeyError error={error} /> : null}
      <div className="flex justify-end gap-2 pt-2">
        <button type="button" className="btn-secondary" disabled={busy} onClick={onCancel}>
          {t("ui.cancel")}
        </button>
        <button type="submit" className="btn-primary" disabled={labelBad || ttlBad || ownerBad || busy || readOnly}>
          {busy ? t("common.working") : t("enroll.key.submit")}
        </button>
      </div>
    </form>
  );
}

function KeyError({ error }: { error: unknown }) {
  const { t } = useTranslation();
  return (
    <div className="space-y-2">
      <WizardError error={error} />
      {error instanceof ApiError && error.code === "secret_no_longer_available" ? (
        <p className="text-sm" data-testid="secret-gone">
          {t("enroll.key.secretGone")}
        </p>
      ) : null}
    </div>
  );
}
