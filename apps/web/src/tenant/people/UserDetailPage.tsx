// Chi tiết thành viên (P4-T09a, §12.3 — API của P4-T09): GET /users/{id} (+ ETag) và các thao tác
//   - khóa / mở khóa: PATCH /users/{id} {status} (If-Match) — khóa thu hồi mọi session Portal, không đụng node;
//   - thu hồi session: DELETE /users/{id}/sessions;
//   - đổi role: PUT /users/{id}/role (giữa các role dưới Admin — tenant.membership:assign) hoặc PUT /users/{id}/admin-role
//     (chạm Tenant Admin / hạ Owner — chỉ Owner, step-up) — operation chọn theo role hiện tại + role mới (§8.4 bất biến 4);
//   - chuyển quyền sở hữu: POST /ownership-transfer (chỉ Owner, step-up);
//   - offboard: DELETE /users/{id} (gõ lại email/tên) ⇒ 202 + job `member.offboard`; màn hình poll tới applied/failed và
//     chỉ báo "đã áp dụng" khi job đã xác minh (node + pre-auth key hết hạn, IdP vô hiệu — T-17).
// Nút chỉ hiện theo quyền của role và quy tắc 3a (model.ts) — server vẫn quyết định: 403 (3a, Owner cuối), 409 (đã
// offboard), 412 (bản đã cũ ⇒ tải lại), 401 reauth_required (step-up ⇒ nút "Xác thực lại").
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useParams } from "react-router";
import { api, call, callWithResponse } from "../../api/client";
import { ifMatch, isStaleVersion, type Versioned } from "../../api/etag";
import { tenantJobFromLocation, useTenantJob } from "../../api/jobs";
import { ApiError } from "../../api/problem";
import { isUuid, queryKeys } from "../../api/queryClient";
import { can } from "../../auth/permissions";
import { Loading, Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { NotFoundPage } from "../../pages/StatusPages";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { Field } from "../../ui/Data";
import { StatusBadge, useCodeText } from "../../ui/Status";
import { useTenant } from "../TenantScope";
import { invalidatePeople, peopleKeys, useUser } from "./api";
import {
  assignableRoles,
  canActOnMember,
  canTransferOwnership,
  offboardConfirmValue,
  offboardTone,
  outranks,
  roleOperation,
  type AdminRoleTarget,
  type Membership,
  type RoleBelowAdmin,
} from "./model";
import { MemberStatus, RoleName } from "./PeopleBits";

export function UserDetailPage() {
  const { membershipId: raw = "" } = useParams();
  const id = raw.toLowerCase();
  if (!isUuid(id)) return <NotFoundPage />;
  return <UserDetail key={id} membershipId={id} />;
}

function UserDetail({ membershipId }: { membershipId: string }) {
  const { t } = useTranslation();
  const { tenantId, role, membershipId: me, readOnly } = useTenant();
  const user = useUser(tenantId, membershipId);
  if (user.error instanceof ApiError && user.error.status === 404) return <NotFoundPage />;
  if (user.isPending) return <Loading />;
  if (user.isError) {
    return (
      <Page title={t("nav.tenant.users")}>
        <ProblemAlert error={user.error} onRetry={() => void user.refetch()} />
      </Page>
    );
  }
  const m = user.data.data;
  const has = (p: string) => can(role, p);
  const actOn = canActOnMember(role, me, m);
  const roles = assignableRoles(role, has, m, me);
  const transfer = canTransferOwnership(role, has, m, me);
  const manage = has("tenant.user:manage") && actOn;
  const anyAction = manage || roles.length > 0 || transfer;
  const managerRole = has("tenant.user:manage") || has("tenant.membership:assign");
  return (
    <Page title={m.display_name}>
      <p className="-mt-4 mb-4">
        <Link to={`/t/${tenantId}/users`} className="link text-sm">
          {t("people.users.back")}
        </Link>
      </p>
      {readOnly ? <p className="mb-3 text-sm text-muted">{t("ui.readOnlyActions")}</p> : null}
      {m.offboarding ? <OffboardPanel member={m} /> : null}
      <section className="card" aria-labelledby="user-info">
        <h2 id="user-info" className="font-semibold">
          {t("people.user.info")}
        </h2>
        <dl className="mt-3 grid gap-4 sm:grid-cols-2">
          <Field label={t("people.col.name")}>
            {m.display_name}
            {m.id === me ? <span className="ms-2 text-xs text-muted">{t("people.you")}</span> : null}
          </Field>
          <Field label={t("people.col.email")}>{m.email ?? <span className="text-muted">{t("people.user.noEmail")}</span>}</Field>
          <Field label={t("people.col.role")}>
            <span data-testid="user-role">
              <RoleName role={m.role} />
            </span>
          </Field>
          <Field label={t("people.col.status")}>
            <MemberStatus member={m} />
          </Field>
          <Field label={t("people.user.headscaleUser")}>
            <code className="text-xs">{m.headscale_username}</code>
          </Field>
          <Field label={t("people.user.profileSource")}>{t("people.user.profileFromIdp")}</Field>
        </dl>
      </section>
      {anyAction ? (
        <>
          {manage ? <AccessActions member={m} etag={user.data.etag} disabled={readOnly} /> : null}
          {roles.length > 0 ? <RoleForm member={m} etag={user.data.etag} roles={roles} disabled={readOnly} /> : null}
          {transfer ? <OwnershipTransfer member={m} disabled={readOnly} /> : null}
          {manage ? <OffboardAction member={m} disabled={readOnly} /> : null}
        </>
      ) : managerRole && m.status !== "offboarded" ? (
        <p className="mt-4 text-sm text-muted" data-testid="no-actions">
          {m.id === me ? t("people.user.selfNoActions") : t("people.user.ruleNoActions")}
        </p>
      ) : null}
      {m.status === "offboarded" && m.offboarding?.state === "failed" && has("tenant.user:manage") && m.id !== me && outranks(role, m.role) ? (
        <OffboardAction member={m} disabled={readOnly} retry />
      ) : null}
    </Page>
  );
}

/** Cập nhật cache sau một lệnh sửa trả thành viên + ETag mới; 412 ⇒ tải lại bản mới (người dùng quyết định lại). */
function useStore(membershipId: string) {
  const { tenantId } = useTenant();
  const queryClient = useQueryClient();
  return {
    store: (data: Membership, etag: string | null) => {
      queryClient.setQueryData<Versioned<Membership>>(peopleKeys.user(tenantId, membershipId), { data, etag });
      void invalidatePeople(queryClient, tenantId, "users");
    },
    refresh: () => Promise.all([invalidatePeople(queryClient, tenantId, "user", membershipId), invalidatePeople(queryClient, tenantId, "users")]),
    onError: (e: unknown) => {
      if (isStaleVersion(e)) void invalidatePeople(queryClient, tenantId, "user", membershipId);
    },
  };
}

function AccessActions({ member, etag, disabled }: { member: Membership; etag: string | null; disabled: boolean }) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const s = useStore(member.id);
  const [open, setOpen] = useState<"lock" | "unlock" | "sessions" | null>(null);
  const path = { tenantId, membershipId: member.id };
  const status = useMutation({
    mutationFn: (next: "active" | "locked") =>
      callWithResponse(api.PATCH("/tenants/{tenantId}/users/{membershipId}", { params: { path, header: ifMatch(etag) }, body: { status: next } })),
    onSuccess: (r) => {
      setOpen(null);
      s.store(r.data, r.response.headers.get("ETag"));
    },
    onError: s.onError,
  });
  const sessions = useMutation({
    mutationFn: () => call(api.DELETE("/tenants/{tenantId}/users/{membershipId}/sessions", { params: { path } })),
    onSuccess: () => {
      setOpen(null);
    },
  });
  const close = (o: boolean) => {
    if (!o) {
      setOpen(null);
      status.reset();
    }
  };
  const locked = member.status === "locked";
  return (
    <section className="card mt-4" aria-labelledby="user-access">
      <h2 id="user-access" className="font-semibold">
        {t("people.access.title")}
      </h2>
      <p className="mt-1 text-sm text-muted">{t("people.access.description")}</p>
      <div className="mt-3 flex flex-wrap gap-2">
        <button type="button" className="btn-secondary" disabled={disabled} onClick={() => setOpen(locked ? "unlock" : "lock")}>
          {locked ? t("people.access.unlock") : t("people.access.lock")}
        </button>
        <button type="button" className="btn-secondary" disabled={disabled} onClick={() => setOpen("sessions")}>
          {t("people.access.revokeSessions")}
        </button>
      </div>
      {sessions.isSuccess ? (
        <p role="status" className="mt-2 text-sm" data-testid="sessions-revoked">
          {t("people.access.sessionsRevoked")}
        </p>
      ) : null}
      <ConfirmDialog
        isOpen={open === "lock" || open === "unlock"}
        onOpenChange={close}
        title={open === "unlock" ? t("people.access.unlockTitle", { name: member.display_name }) : t("people.access.lockTitle", { name: member.display_name })}
        description={<p>{open === "unlock" ? t("people.access.unlockDesc") : t("people.access.lockDesc")}</p>}
        confirmLabel={open === "unlock" ? t("people.access.unlock") : t("people.access.lock")}
        destructive={open === "lock"}
        pending={status.isPending}
        error={status.isError ? status.error : undefined}
        onConfirm={() => status.mutate(open === "unlock" ? "active" : "locked")}
      />
      <ConfirmDialog
        isOpen={open === "sessions"}
        onOpenChange={(o) => {
          if (!o) {
            setOpen(null);
            sessions.reset();
          }
        }}
        title={t("people.access.sessionsTitle", { name: member.display_name })}
        description={<p>{t("people.access.sessionsDesc")}</p>}
        confirmLabel={t("people.access.revokeSessions")}
        destructive
        pending={sessions.isPending}
        error={sessions.isError ? sessions.error : undefined}
        onConfirm={() => sessions.mutate()}
      />
    </section>
  );
}

function RoleForm({ member, etag, roles, disabled }: { member: Membership; etag: string | null; roles: string[]; disabled: boolean }) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const s = useStore(member.id);
  const selectId = useId();
  const [next, setNext] = useState(roles[0] ?? "");
  const [confirming, setConfirming] = useState(false);
  const op = roleOperation(member.role, next);
  const change = useMutation({
    mutationFn: (target: string) => {
      const params = { path: { tenantId, membershipId: member.id }, header: ifMatch(etag) };
      return roleOperation(member.role, target) === "role"
        ? callWithResponse(api.PUT("/tenants/{tenantId}/users/{membershipId}/role", { params, body: { role: target as RoleBelowAdmin } }))
        : callWithResponse(api.PUT("/tenants/{tenantId}/users/{membershipId}/admin-role", { params, body: { role: target as AdminRoleTarget } }));
    },
    onSuccess: (r) => {
      setConfirming(false);
      s.store(r.data, r.response.headers.get("ETag"));
    },
    onError: s.onError,
  });
  const value = roles.includes(next) ? next : (roles[0] ?? "");
  return (
    <section className="card mt-4" aria-labelledby="user-role-title">
      <h2 id="user-role-title" className="font-semibold">
        {t("people.role.title")}
      </h2>
      <p className="mt-1 text-sm text-muted">{t("people.role.description")}</p>
      <div className="mt-3 flex flex-wrap items-end gap-2">
        <div>
          <label htmlFor={selectId} className="label">
            {t("people.role.newRole")}
          </label>
          <select id={selectId} className="select" value={value} disabled={disabled} onChange={(e) => setNext(e.target.value)}>
            {roles.map((r) => (
              <option key={r} value={r}>
                {t(`roles.${r}`)}
              </option>
            ))}
          </select>
        </div>
        <button type="button" className="btn-primary" disabled={disabled || value === ""} onClick={() => setConfirming(true)}>
          {t("people.role.submit")}
        </button>
      </div>
      {op === "admin-role" ? <p className="hint mt-2">{t("people.role.adminHint")}</p> : null}
      {change.isSuccess ? (
        <p role="status" className="mt-2 text-sm" data-testid="role-changed">
          {t("people.role.done")}
        </p>
      ) : null}
      <ConfirmDialog
        isOpen={confirming}
        onOpenChange={(o) => {
          if (!o) {
            setConfirming(false);
            change.reset();
          }
        }}
        title={t("people.role.confirmTitle", { name: member.display_name })}
        description={
          <div className="space-y-2">
            <p>
              <RoleName role={member.role} /> {"→"} <strong>{value ? <RoleName role={value} /> : null}</strong>
            </p>
            <p className="text-muted">{t("people.role.sessionsNote")}</p>
            {roleOperation(member.role, value) === "admin-role" ? <p className="text-muted">{t("people.role.adminHint")}</p> : null}
          </div>
        }
        confirmLabel={t("people.role.submit")}
        pending={change.isPending}
        error={change.isError ? change.error : undefined}
        onConfirm={() => change.mutate(value)}
      />
    </section>
  );
}

function OwnershipTransfer({ member, disabled }: { member: Membership; disabled: boolean }) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const queryClient = useQueryClient();
  const s = useStore(member.id);
  const keepId = useId();
  const [open, setOpen] = useState(false);
  const [keep, setKeep] = useState(false);
  const transfer = useMutation({
    mutationFn: () =>
      call(
        api.POST("/tenants/{tenantId}/ownership-transfer", {
          params: { path: { tenantId } },
          body: { membership_id: member.id, previous_owner_role: keep ? "tenant_owner" : "tenant_admin" },
        }),
      ),
    onSuccess: async () => {
      setOpen(false);
      await s.refresh();
      // role của chính người gọi đổi (và session của cả hai bị thu hồi) ⇒ đọc lại phiên
      void queryClient.invalidateQueries({ queryKey: queryKeys.session() });
    },
  });
  return (
    <section className="card mt-4" aria-labelledby="user-owner">
      <h2 id="user-owner" className="font-semibold">
        {t("people.owner.title")}
      </h2>
      <p className="mt-1 text-sm text-muted">{t("people.owner.description")}</p>
      <button type="button" className="btn-secondary mt-3" disabled={disabled} onClick={() => setOpen(true)}>
        {t("people.owner.open")}
      </button>
      <ConfirmDialog
        isOpen={open}
        onOpenChange={(o) => {
          if (!o) {
            setOpen(false);
            setKeep(false);
            transfer.reset();
          }
        }}
        title={t("people.owner.confirmTitle", { name: member.display_name })}
        description={
          <div className="space-y-2">
            <p>{t("people.owner.confirmDesc")}</p>
            <p className="text-muted">{t("people.owner.stepUp")}</p>
          </div>
        }
        typedConfirmation={{ expected: offboardConfirmValue(member), label: t("people.owner.typeLabel") }}
        confirmLabel={t("people.owner.submit")}
        destructive
        pending={transfer.isPending}
        error={transfer.isError ? transfer.error : undefined}
        onConfirm={() => transfer.mutate()}
      >
        <label htmlFor={keepId} className="flex items-center gap-2 text-sm">
          <input id={keepId} type="checkbox" checked={keep} onChange={(e) => setKeep(e.target.checked)} />
          {t("people.owner.keep")}
        </label>
      </ConfirmDialog>
    </section>
  );
}

function OffboardAction({ member, disabled, retry = false }: { member: Membership; disabled: boolean; retry?: boolean }) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const s = useStore(member.id);
  const [open, setOpen] = useState(false);
  const offboard = useMutation({
    mutationFn: () =>
      callWithResponse(api.DELETE("/tenants/{tenantId}/users/{membershipId}", { params: { path: { tenantId, membershipId: member.id } } })),
    onSuccess: (r) => {
      setOpen(false);
      const jobId = tenantJobFromLocation(r.response.headers.get("Location"), tenantId);
      // 202: trạng thái hiện tại (pending) + job của Location; ETag của bản mới đọc lại ở lần poll kế tiếp
      s.store({ ...r.data, offboarding: r.data.offboarding ?? (jobId ? { state: "pending", job_id: jobId } : undefined) }, null);
      void s.refresh();
    },
  });
  const expected = offboardConfirmValue(member);
  return (
    <section className="card mt-4 border-danger/40" aria-labelledby="user-offboard">
      <h2 id="user-offboard" className="font-semibold">
        {retry ? t("people.offboard.retryTitle") : t("people.offboard.title")}
      </h2>
      <p className="mt-1 text-sm text-muted">{retry ? t("people.offboard.retryDescription") : t("people.offboard.description")}</p>
      <button type="button" className="btn-danger mt-3" disabled={disabled} onClick={() => setOpen(true)}>
        {retry ? t("people.offboard.retry") : t("people.offboard.open")}
      </button>
      <ConfirmDialog
        isOpen={open}
        onOpenChange={(o) => {
          if (!o) {
            setOpen(false);
            offboard.reset();
          }
        }}
        title={t("people.offboard.confirmTitle", { name: member.display_name })}
        description={
          <div className="space-y-2">
            <p>{t("people.offboard.confirmDesc")}</p>
            <ul className="list-disc ps-5">
              <li>{t("people.offboard.effects.sessions")}</li>
              <li>{t("people.offboard.effects.groups")}</li>
              <li>{t("people.offboard.effects.nodes")}</li>
              <li>{t("people.offboard.effects.idp")}</li>
            </ul>
            <p className="text-muted">{t("people.offboard.final")}</p>
          </div>
        }
        typedConfirmation={{ expected, label: t("people.offboard.typeLabel") }}
        confirmLabel={t("people.offboard.submit")}
        destructive
        pending={offboard.isPending}
        error={offboard.isError ? offboard.error : undefined}
        onConfirm={() => offboard.mutate()}
      />
    </section>
  );
}

/** Trạng thái hai pha (T-17): pending ⇒ "CHƯA xong" (node/key có thể còn hiệu lực), applied ⇒ đã xác minh, failed ⇒ thử lại.
 * Kèm job `member.offboard` (GET /jobs/{id}) khi role đọc được job. */
function OffboardPanel({ member }: { member: Membership }) {
  const { t } = useTranslation();
  const { tenantId, role } = useTenant();
  const text = useCodeText();
  const o = member.offboarding;
  const job = useTenantJob(tenantId, o && can(role, "tenant.job:read") ? o.job_id : null);
  if (!o) return null;
  return (
    <div role="status" aria-live="polite" className="mb-4 rounded-md border border-line bg-surface p-4" data-testid="offboard-panel" data-state={o.state}>
      <p className="font-medium">
        <StatusBadge tone={offboardTone(o.state)} status={`offboard-${o.state}`}>
          {text("people.offboard.state", o.state)}
        </StatusBadge>{" "}
        {t(`people.offboard.explain.${o.state}`)}
      </p>
      <p className="mt-1 text-sm text-muted">
        {t("people.offboard.job")} <code>{o.job_id}</code>
        {job.data ? (
          <>
            {" · "}
            <StatusBadge status={job.data.status} testId="offboard-job-status">
              {text("status.job", job.data.status)}
            </StatusBadge>
            {job.data.error ? (
              <span className="ms-1 text-xs text-muted" data-code={job.data.error.code}>
                {t("ui.jobErrorCode", { code: job.data.error.code })}
              </span>
            ) : null}
          </>
        ) : null}
      </p>
    </div>
  );
}
