// Nhân sự nền tảng (§12.2 "Platform roles — Gán SA: 2P"; §8.4 bất biến 3, §8.5): GET /platform/users; tạo (POST — `sub`
// của IdP platform + role DƯỚI Super Admin, Idempotency-Key), sửa role/trạng thái (PATCH, If-Match), khóa (DELETE,
// If-Match) — platform.user:assign, step-up; gán/gỡ Super Admin LUÔN 2P (PUT …/super-admin-role ⇒ 202 + yêu cầu phê
// duyệt — một Super Admin khác duyệt). Không ai tự sửa mình; hàng đang là SA không sửa/khóa được ở đây (điều kiện
// excludes_super_admin). UI ẩn nút theo các quy tắc đó; server mới quyết định (403/412/409).
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { api, call, callWithResponse } from "../../api/client";
import { ifMatch } from "../../api/etag";
import { useIdempotentMutation } from "../../api/idempotency";
import { approvalFromLocation } from "../../api/jobs";
import { useCursorPager } from "../../api/pagination";
import { can } from "../../auth/permissions";
import { useSession } from "../../auth/session";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { EmptyState, Pager, QueryBlock } from "../../ui/Data";
import { SelectField, TextField } from "../../ui/Form";
import { FormDialog } from "../../ui/FormDialog";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { Page } from "../../components/Page";
import { invalidatePlatform } from "../api";
import {
  ASSIGNABLE_ROLES,
  isOneOf,
  PLATFORM_ROLES,
  PLATFORM_USER_STATUSES,
  usePlatformUsers,
  type PlatformAssignableRole,
  type PlatformRole,
  type PlatformUser,
  type PlatformUserStatus,
} from "../opsApi";
import { usePlatformRole } from "../PlatformScope";

type Dialog = { kind: "create" } | { kind: "edit" | "disable" | "grantSA" | "revokeSA"; user: PlatformUser };

/** Thao tác hiện trên một hàng (UX — server quyết định). */
export function userActions(role: string | null, me: string | undefined, u: PlatformUser): ("edit" | "disable" | "grantSA" | "revokeSA")[] {
  if (me !== undefined && u.identity_id === me) return [];
  const out: ("edit" | "disable" | "grantSA" | "revokeSA")[] = [];
  const assign = can(role, "platform.user:assign");
  const sa = can(role, "platform.user:assign_super_admin");
  if (u.role === "super_admin") {
    if (sa) out.push("revokeSA");
    return out;
  }
  if (assign) out.push("edit");
  if (assign && u.status === "active") out.push("disable");
  if (sa && u.status === "active") out.push("grantSA");
  return out;
}

export function PlatformUsersPage() {
  const { t } = useTranslation();
  const role = usePlatformRole();
  const me = useSession().data?.principal.identity_id;
  const [status, setStatus] = useState<PlatformUserStatus | "">("");
  const [roleFilter, setRoleFilter] = useState<PlatformRole | "">("");
  const pager = useCursorPager(`${status}|${roleFilter}`);
  const list = usePlatformUsers({ status: status || undefined, role: roleFilter || undefined, cursor: pager.cursor });
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const close = () => {
    setDialog(null);
  };

  return (
    <Page
      title={t("nav.platform.users")}
      actions={
        can(role, "platform.user:assign") ? (
          <button
            type="button"
            className="btn-primary"
            onClick={() => {
              setDialog({ kind: "create" });
            }}
          >
            {t("platform.users.create")}
          </button>
        ) : null
      }
    >
      <p className="mb-4 text-sm text-muted">{t("platform.users.intro")}</p>
      <div className="mb-4 flex flex-wrap items-end gap-3">
        <div>
          <label htmlFor="pu-status" className="label">
            {t("platform.users.status")}
          </label>
          <select
            id="pu-status"
            className="select"
            value={status}
            onChange={(e) => {
              setStatus(isOneOf(PLATFORM_USER_STATUSES, e.target.value) ? e.target.value : "");
            }}
          >
            <option value="">{t("common.all")}</option>
            {PLATFORM_USER_STATUSES.map((s) => (
              <option key={s} value={s}>
                {t(`status.platformUser.${s}`)}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="pu-role" className="label">
            {t("platform.users.role")}
          </label>
          <select
            id="pu-role"
            className="select"
            value={roleFilter}
            onChange={(e) => {
              setRoleFilter(isOneOf(PLATFORM_ROLES, e.target.value) ? e.target.value : "");
            }}
          >
            <option value="">{t("common.all")}</option>
            {PLATFORM_ROLES.map((r) => (
              <option key={r} value={r}>
                {t(`roles.${r}`)}
              </option>
            ))}
          </select>
        </div>
      </div>
      <QueryBlock query={list}>
        {(data) =>
          data.items.length === 0 ? (
            <EmptyState>{t("platform.users.empty")}</EmptyState>
          ) : (
            <>
              <div className="overflow-x-auto rounded-lg border border-line bg-surface">
                <table className="data-table">
                  <caption className="sr-only">{t("nav.platform.users")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{t("platform.users.col.name")}</th>
                      <th scope="col">{t("platform.users.col.role")}</th>
                      <th scope="col">{t("platform.users.col.status")}</th>
                      <th scope="col">{t("platform.users.col.lastLogin")}</th>
                      <th scope="col">{t("platform.users.col.actions")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((u) => {
                      const acts = userActions(role, me, u);
                      const self = me !== undefined && u.identity_id === me;
                      return (
                        <tr key={u.id} data-testid="platform-user" data-subject={u.subject}>
                          <th scope="row" className="font-normal">
                            <span className="font-medium">{u.display_name}</span>
                            {self ? <span className="ms-1 text-muted">{t("platform.approvals.you")}</span> : null}
                            {u.email ? <span className="hint block">{u.email}</span> : null}
                            <code className="hint block">{u.subject}</code>
                          </th>
                          <td>
                            <StatusBadge tone={u.role === "super_admin" ? "info" : "neutral"}>{t(`roles.${u.role}`)}</StatusBadge>
                          </td>
                          <td>
                            <StatusBadge status={u.status}>{t(`status.platformUser.${u.status}`)}</StatusBadge>
                            {u.identity_status && u.identity_status !== "active" ? (
                              <span className="hint block">{t("platform.users.identityStatus", { status: u.identity_status })}</span>
                            ) : null}
                          </td>
                          <td>
                            <Timestamp iso={u.last_login_at} />
                          </td>
                          <td>
                            {self ? (
                              <span className="text-xs text-muted">{t("platform.users.selfNote")}</span>
                            ) : acts.length === 0 ? null : (
                              <div className="flex flex-wrap gap-1" role="group" aria-label={t("platform.users.rowActions", { name: u.display_name })}>
                                {acts.map((a) => (
                                  <button
                                    key={a}
                                    type="button"
                                    className={a === "disable" ? "btn-secondary text-danger" : "btn-secondary"}
                                    aria-label={t(`platform.users.actLabel.${a}`, { name: u.display_name })}
                                    onClick={() => {
                                      setDialog({ kind: a, user: u });
                                    }}
                                  >
                                    {t(`platform.users.act.${a}`)}
                                  </button>
                                ))}
                              </div>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              <Pager pager={pager} nextCursor={data.next_cursor} label={t("platform.users.pagination")} />
            </>
          )
        }
      </QueryBlock>
      {dialog?.kind === "create" ? <CreateUser onClose={close} /> : null}
      {dialog?.kind === "edit" ? <EditUser user={dialog.user} onClose={close} /> : null}
      {dialog?.kind === "disable" ? <DisableUser user={dialog.user} onClose={close} /> : null}
      {dialog?.kind === "grantSA" || dialog?.kind === "revokeSA" ? <SuperAdminChange user={dialog.user} grant={dialog.kind === "grantSA"} onClose={close} /> : null}
    </Page>
  );
}

const SUB_MAX = 255;

function roleOptions(t: (k: string) => string) {
  return ASSIGNABLE_ROLES.map((r) => ({ value: r, label: t(`roles.${r}`) }));
}

function CreateUser({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [subject, setSubject] = useState("");
  const [role, setRole] = useState<PlatformAssignableRole>("platform_viewer");
  const [name, setName] = useState("");
  const create = useIdempotentMutation({
    mutationFn: (body: { subject: string; role: PlatformAssignableRole; display_name?: string }, key: string) =>
      call(api.POST("/platform/users", { params: { header: { "Idempotency-Key": key } }, body })),
    onSuccess: async () => {
      await invalidatePlatform(queryClient, "users");
      onClose();
    },
  });
  const sub = subject.trim();
  const ok = sub.length > 0 && sub.length <= SUB_MAX && name.trim().length <= 128;
  return (
    <FormDialog
      isOpen
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
      title={t("platform.users.createTitle")}
      description={<p>{t("platform.users.createDesc")}</p>}
      submitLabel={t("platform.users.create")}
      canSubmit={ok}
      pending={create.isPending}
      error={create.error}
      onSubmit={() => {
        create.mutate({ subject: sub, role, ...(name.trim() ? { display_name: name.trim() } : {}) });
      }}
    >
      <TextField label={t("platform.users.subject")} hint={t("platform.users.subjectHint")} value={subject} onChange={setSubject} maxLength={SUB_MAX} mono autoFocus />
      <SelectField label={t("platform.users.role")} hint={t("platform.users.roleHint")} value={role} onChange={setRole} options={roleOptions(t)} />
      <TextField label={t("platform.users.displayName")} value={name} onChange={setName} maxLength={128} />
    </FormDialog>
  );
}

function EditUser({ user, onClose }: { user: PlatformUser; onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const current: PlatformAssignableRole = isOneOf(ASSIGNABLE_ROLES, user.role) ? user.role : "platform_viewer";
  const [role, setRole] = useState<PlatformAssignableRole>(current);
  const [status, setStatus] = useState<PlatformUserStatus>(user.status);
  const body = { ...(role !== user.role ? { role } : {}), ...(status !== user.status ? { status } : {}) };
  const save = useMutation({
    mutationFn: () =>
      call(
        api.PATCH("/platform/users/{platformUserId}", {
          params: { path: { platformUserId: user.id }, header: ifMatch(user.etag) },
          body,
        }),
      ),
    onSuccess: async () => {
      await invalidatePlatform(queryClient, "users");
      onClose();
    },
    onError: async () => {
      await invalidatePlatform(queryClient, "users");
    },
  });
  return (
    <FormDialog
      isOpen
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
      title={t("platform.users.editTitle", { name: user.display_name })}
      description={<p>{t("platform.users.editDesc")}</p>}
      submitLabel={t("platform.users.save")}
      canSubmit={Object.keys(body).length > 0}
      pending={save.isPending}
      error={save.error}
      onSubmit={() => {
        save.mutate();
      }}
    >
      <SelectField label={t("platform.users.role")} hint={t("platform.users.roleHint")} value={role} onChange={setRole} options={roleOptions(t)} autoFocus />
      <SelectField
        label={t("platform.users.status")}
        value={status}
        onChange={setStatus}
        options={PLATFORM_USER_STATUSES.map((s) => ({ value: s, label: t(`status.platformUser.${s}`) }))}
      />
    </FormDialog>
  );
}

function DisableUser({ user, onClose }: { user: PlatformUser; onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const del = useMutation({
    mutationFn: () =>
      call(api.DELETE("/platform/users/{platformUserId}", { params: { path: { platformUserId: user.id }, header: ifMatch(user.etag) } })),
    onSuccess: async () => {
      await invalidatePlatform(queryClient, "users");
      onClose();
    },
    onError: async () => {
      await invalidatePlatform(queryClient, "users");
    },
  });
  return (
    <ConfirmDialog
      isOpen
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
      title={t("platform.users.disableTitle", { name: user.display_name })}
      description={<p>{t("platform.users.disableDesc")}</p>}
      confirmLabel={t("platform.users.act.disable")}
      destructive
      pending={del.isPending}
      error={del.error}
      onConfirm={() => {
        del.mutate();
      }}
    />
  );
}

/** Gán (grant) hoặc gỡ Super Admin — luôn 2P: 202 + Location của yêu cầu phê duyệt ⇒ trang phê duyệt. */
function SuperAdminChange({ user, grant, onClose }: { user: PlatformUser; grant: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");
  const [after, setAfter] = useState<PlatformAssignableRole>("platform_operator");
  const req = useMutation({
    mutationFn: () =>
      callWithResponse(
        api.PUT("/platform/users/{platformUserId}/super-admin-role", {
          params: { path: { platformUserId: user.id } },
          body: grant ? { super_admin: true, reason: reason.trim() } : { super_admin: false, role_after: after, reason: reason.trim() },
        }),
      ),
    onSuccess: async (r) => {
      await invalidatePlatform(queryClient, "approvals");
      onClose();
      void navigate(`/platform/approvals/${approvalFromLocation(r.response.headers.get("Location")) ?? r.data.id}`, { state: { requested: true } });
    },
  });
  const ok = reason.trim().length > 0 && reason.length <= 1000;
  return (
    <FormDialog
      isOpen
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
      title={t(grant ? "platform.users.grantTitle" : "platform.users.revokeTitle", { name: user.display_name })}
      description={
        <div className="space-y-2">
          <p>{t(grant ? "platform.users.grantDesc" : "platform.users.revokeDesc")}</p>
          <p className="font-medium">{t("platform.users.twoPerson")}</p>
        </div>
      }
      submitLabel={t("platform.users.requestApproval")}
      destructive={grant}
      canSubmit={ok}
      pending={req.isPending}
      error={req.error}
      onSubmit={() => {
        req.mutate();
      }}
    >
      {grant ? null : (
        <SelectField label={t("platform.users.roleAfter")} value={after} onChange={setAfter} options={roleOptions(t)} autoFocus />
      )}
      <TextField label={t("platform.users.reason")} value={reason} onChange={setReason} rows={3} maxLength={1000} autoFocus={grant} />
    </FormDialog>
  );
}
