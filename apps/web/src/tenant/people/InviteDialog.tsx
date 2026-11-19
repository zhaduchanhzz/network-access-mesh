// Mời thành viên (P4-T09a — POST /tenants/{t}/invitations, P3-T05a): email + role + hạn; Idempotency-Key theo nội dung
// (gửi lại sau lỗi mạng ⇒ cùng khóa, sửa nội dung ⇒ khóa mới). Role chỉ gồm role người gọi được mời theo quy tắc 3a
// (Owner mời được Admin; Admin chỉ mời role dưới Admin) — server vẫn kiểm (`GuardInvitationRole` ⇒ 403). Mỗi lời mời
// còn chạy job `member.idp_invite` (IdP do nền tảng host: tạo/tìm tài khoản, gửi thư required actions — P4-T09):
// trạng thái job hiện ở trang Lời mời.
import { useQueryClient } from "@tanstack/react-query";
import { useId, useState, type SyntheticEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, call } from "../../api/client";
import { useIdempotentMutation } from "../../api/idempotency";
import { ModalDialog } from "../../ui/Dialog";
import { useTenant } from "../TenantScope";
import { invalidatePeople } from "./api";
import { invitableRoles, type Invitation, type InvitationRole } from "./model";
import { ActionError, RoleName } from "./PeopleBits";

export const DEFAULT_INVITE_HOURS = 168;
const EMAIL_RE = /^[^\s@]+@[^\s@]+$/;

export function InviteDialog({ isOpen, onOpenChange, onCreated }: { isOpen: boolean; onOpenChange: (o: boolean) => void; onCreated: (i: Invitation) => void }) {
  const { t } = useTranslation();
  return (
    <ModalDialog isOpen={isOpen} onOpenChange={onOpenChange} title={t("people.invite.title")}>
      <InviteForm
        onCancel={() => {
          onOpenChange(false);
        }}
        onCreated={onCreated}
      />
    </ModalDialog>
  );
}

function InviteForm({ onCancel, onCreated }: { onCancel: () => void; onCreated: (i: Invitation) => void }) {
  const { t } = useTranslation();
  const { tenantId, role } = useTenant();
  const queryClient = useQueryClient();
  const roles = invitableRoles(role);
  const [email, setEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<InvitationRole | "">(roles.includes("end_user") ? "end_user" : (roles[0] ?? ""));
  const [hours, setHours] = useState(String(DEFAULT_INVITE_HOURS));
  const ids = { email: useId(), role: useId(), hours: useId(), emailErr: useId(), hoursErr: useId() };
  const emailBad = email !== "" && (!EMAIL_RE.test(email.trim()) || email.trim().length > 320);
  const n = Number(hours);
  const hoursBad = !Number.isInteger(n) || n < 1 || n > 720;

  const create = useIdempotentMutation({
    mutationFn: (body: { email: string; role: InvitationRole; expires_in_hours: number }, key: string) =>
      call(api.POST("/tenants/{tenantId}/invitations", { params: { path: { tenantId }, header: { "Idempotency-Key": key } }, body })),
    onSuccess: async (inv) => {
      await invalidatePeople(queryClient, tenantId, "invitations");
      onCreated(inv);
    },
  });
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    if (email.trim() === "" || emailBad || hoursBad || inviteRole === "" || create.isPending) return;
    create.mutate({ email: email.trim(), role: inviteRole, expires_in_hours: n });
  };
  if (roles.length === 0) return <p>{t("people.invite.noRoles")}</p>;
  return (
    <form className="space-y-3" onSubmit={submit} noValidate>
      <p className="text-muted">{t("people.invite.description")}</p>
      <div>
        <label htmlFor={ids.email} className="label">
          {t("people.invite.email")}
        </label>
        <input
          id={ids.email}
          className="input"
          type="email"
          autoComplete="off"
          autoFocus
          maxLength={320}
          value={email}
          aria-invalid={emailBad}
          aria-describedby={emailBad ? ids.emailErr : undefined}
          onChange={(e) => {
            setEmail(e.target.value);
          }}
        />
        {emailBad ? (
          <p id={ids.emailErr} className="field-error">
            {t("people.invite.emailInvalid")}
          </p>
        ) : null}
      </div>
      <div>
        <label htmlFor={ids.role} className="label">
          {t("people.col.role")}
        </label>
        <select
          id={ids.role}
          className="select"
          value={inviteRole}
          onChange={(e) => {
            setInviteRole(e.target.value as InvitationRole);
          }}
        >
          {roles.map((r) => (
            <option key={r} value={r}>
              {t(`roles.${r}`)}
            </option>
          ))}
        </select>
        <p className="hint">{t("people.invite.roleHint")}</p>
      </div>
      <div>
        <label htmlFor={ids.hours} className="label">
          {t("people.invite.hours")}
        </label>
        <input
          id={ids.hours}
          className="input"
          type="number"
          min={1}
          max={720}
          value={hours}
          aria-invalid={hoursBad}
          aria-describedby={hoursBad ? ids.hoursErr : undefined}
          onChange={(e) => {
            setHours(e.target.value);
          }}
        />
        {hoursBad ? (
          <p id={ids.hoursErr} className="field-error">
            {t("people.invite.hoursInvalid")}
          </p>
        ) : null}
      </div>
      {inviteRole !== "" ? (
        <p className="text-sm">
          {t("people.invite.summary")} <strong>{email.trim() || "—"}</strong> · <RoleName role={inviteRole} />
        </p>
      ) : null}
      <ActionError error={create.isError ? create.error : null} />
      <div className="flex justify-end gap-2 pt-2">
        <button type="button" className="btn-secondary" disabled={create.isPending} onClick={onCancel}>
          {t("ui.cancel")}
        </button>
        <button type="submit" className="btn-primary" disabled={email.trim() === "" || emailBad || hoursBad || create.isPending}>
          {create.isPending ? t("common.working") : t("people.invite.submit")}
        </button>
      </div>
    </form>
  );
}
