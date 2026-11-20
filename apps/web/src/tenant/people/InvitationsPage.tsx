// Invitations (P4-T09a, §12.3 — API của P3-T05a, job của P4-T09): GET /invitations (lọc trạng thái hiệu lực, con trỏ),
// mời (POST, Idempotency-Key), gửi lại (POST …/resend — token và hạn mới, link cũ mất hiệu lực), thu hồi (DELETE).
// Cột "IdP": job `member.idp_invite` mới nhất của lời mời (GET /jobs?kind=member.idp_invite, ghép theo resource) — với IdP
// do nền tảng host, job tạo/tìm tài khoản và gửi thư required actions; lời mời vừa tạo/gửi lại ⇒ poll tới khi job kết
// thúc. Gửi lại / thu hồi chỉ hiện với lời mời có role thấp hơn hẳn role người gọi (quy tắc 3a; Owner không giới hạn) —
// server vẫn quyết định (403/409).
// G4b-E1: lời mời có hai pha — (1) lời mời đã tạo (POST trả 201), (2) tài khoản IdP + thư thiết lập (job, có thể thất
// bại sau đó) ⇒ thông báo sau khi mời/gửi lại không khẳng định thư IdP đã đi: nói theo trạng thái job, job thất bại ⇒
// cảnh báo kèm câu hướng dẫn đã dịch theo mã lỗi (`people.invitations.idpError.<code>`; mã thô chỉ ở tooltip).
// G4b-E16: lời mời không có người mời = lời mời Owner do provision tạo (bước cấu hình tenant).
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useLocation, useSearchParams } from "react-router";
import { api, call } from "../../api/client";
import { useCursorPager } from "../../api/pagination";
import { can } from "../../auth/permissions";
import { Page } from "../../components/Page";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { EmptyState, Pager, QueryBlock } from "../../ui/Data";
import type { Job } from "../../api/jobs";
import { StatusBadge, useCodeText } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { useTenant } from "../TenantScope";
import { invalidatePeople, useInvitations, useInviteJobs } from "./api";
import { DEFAULT_INVITE_HOURS, InviteDialog } from "./InviteDialog";
import { INVITATION_STATUSES, invitationTone, outranks, type Invitation } from "./model";
import { RoleName } from "./PeopleBits";

type Action = { kind: "resend" | "revoke"; invitation: Invitation } | null;
/** Lời mời vừa tạo / gửi lại mà trang đang theo dõi job IdP của nó. */
type Watch = { id: string; kind: "created" | "resent" };

/** Job IdP đã kết thúc không thành công (trạng thái cuối khác `succeeded`). */
function idpFailed(job: Job | undefined): boolean {
  return job !== undefined && (job.status === "failed" || job.status === "cancelled" || job.status === "rolled_back");
}

/** Câu hướng dẫn đã dịch cho mã lỗi của job `member.idp_invite` (mã lạ ⇒ câu chung); mã thô ở tooltip. */
function IdpErrorText({ job }: { job: Job }) {
  const text = useCodeText();
  const code = job.error?.code;
  return (
    <span title={code} data-testid="idp-error" data-code={code}>
      {text("people.invitations.idpError", code ?? "unknown", "people.invitations.idpError.other")}
    </span>
  );
}

/** Thông báo sau khi mời / gửi lại: pha 1 (lời mời) đã xong; pha 2 (IdP) theo trạng thái job — thất bại ⇒ cảnh báo. */
function WatchBanner({ watch, job, jobsKnown }: { watch: Watch; job: Job | undefined; jobsKnown: boolean }) {
  const { t } = useTranslation();
  const head = t(watch.kind === "created" ? "people.invitations.banner.created" : "people.invitations.banner.resent");
  if (job && idpFailed(job)) {
    return (
      <div role="alert" className="mb-4 rounded-md border border-warn/40 bg-warn-bg p-3 text-sm" data-testid="invitation-created" data-idp="failed">
        <p>
          {head} <strong>{t("people.invitations.banner.failed")}</strong>
        </p>
        <p className="mt-1">
          <IdpErrorText job={job} />
        </p>
      </div>
    );
  }
  const phase2 = !jobsKnown ? "background" : job?.status === "succeeded" ? "done" : "processing";
  return (
    <p role="status" className="mb-4 rounded-md border border-line bg-surface p-3 text-sm" data-testid="invitation-created" data-idp={phase2}>
      {head} {t(`people.invitations.banner.${phase2}`)}
    </p>
  );
}

export function InvitationsPage() {
  const { t } = useTranslation();
  const text = useCodeText();
  const { tenantId, role, readOnly } = useTenant();
  const queryClient = useQueryClient();
  const location = useLocation();
  const [params, setParams] = useSearchParams();
  const status = INVITATION_STATUSES.find((s) => s === params.get("status"));
  const pager = useCursorPager(status ?? "");
  const list = useInvitations(tenantId, { status, cursor: pager.cursor });
  const [inviting, setInviting] = useState(false);
  const [watch, setWatch] = useState<Watch | null>(() => {
    const created = (location.state as { created?: unknown } | null)?.created;
    return typeof created === "string" ? { id: created, kind: "created" } : null;
  });
  const jobs = useInviteJobs(tenantId, can(role, "tenant.job:read"), watch?.id ?? null);
  const [action, setAction] = useState<Action>(null);

  const act = useMutation({
    mutationFn: async (a: NonNullable<Action>) => {
      const path = { tenantId, invitationId: a.invitation.id };
      if (a.kind === "revoke") {
        await call(api.DELETE("/tenants/{tenantId}/invitations/{invitationId}", { params: { path } }));
      } else {
        await call(api.POST("/tenants/{tenantId}/invitations/{invitationId}/resend", { params: { path }, body: { expires_in_hours: DEFAULT_INVITE_HOURS } }));
      }
      return a;
    },
    onSuccess: async (a) => {
      setAction(null);
      if (a.kind === "resend") setWatch({ id: a.invitation.id, kind: "resent" });
      await Promise.all([invalidatePeople(queryClient, tenantId, "invitations"), invalidatePeople(queryClient, tenantId, "invite-jobs")]);
    },
  });

  return (
    <Page
      title={t("nav.tenant.invitations")}
      actions={
        <button type="button" className="btn-primary" disabled={readOnly} onClick={() => setInviting(true)}>
          {t("people.invite.open")}
        </button>
      }
    >
      {readOnly ? <p className="mb-3 text-sm text-muted">{t("ui.readOnlyActions")}</p> : null}
      <p className="mb-4 text-sm text-muted">{t("people.invitations.intro")}</p>
      {watch ? <WatchBanner watch={watch} job={jobs.data?.get(watch.id)} jobsKnown={jobs.isSuccess} /> : null}
      <div className="mb-4">
        <label htmlFor="inv-status" className="label">
          {t("people.col.status")}
        </label>
        <select
          id="inv-status"
          className="select"
          value={status ?? ""}
          onChange={(e) => {
            setParams(e.target.value ? { status: e.target.value } : {}, { replace: true });
          }}
        >
          <option value="">{t("common.all")}</option>
          {INVITATION_STATUSES.map((s) => (
            <option key={s} value={s}>
              {t(`people.invitationStatus.${s}`)}
            </option>
          ))}
        </select>
      </div>
      <QueryBlock query={list}>
        {(page) =>
          page.items.length === 0 ? (
            <EmptyState>{t("people.invitations.empty")}</EmptyState>
          ) : (
            <div className="relative overflow-x-auto">
              <table className="data-table" data-testid="invitations-table">
                <caption className="sr-only">{t("nav.tenant.invitations")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("people.col.email")}</th>
                    <th scope="col">{t("people.col.role")}</th>
                    <th scope="col">{t("people.col.status")}</th>
                    <th scope="col">{t("people.invitations.expires")}</th>
                    <th scope="col">{t("people.invitations.invitedBy")}</th>
                    {jobs.isSuccess ? <th scope="col">{t("people.invitations.idp")}</th> : null}
                    <th scope="col">{t("people.col.actions")}</th>
                  </tr>
                </thead>
                <tbody>
                  {page.items.map((inv) => {
                    const job = jobs.data?.get(inv.id);
                    const mine = outranks(role, inv.role) && !readOnly;
                    return (
                      <tr key={inv.id} data-testid="invitation-row" data-invitation={inv.id}>
                        <td>{inv.email}</td>
                        <td>
                          <RoleName role={inv.role} />
                        </td>
                        <td>
                          <StatusBadge tone={invitationTone(inv.status)} status={inv.status}>
                            {text("people.invitationStatus", inv.status)}
                          </StatusBadge>
                        </td>
                        <td>
                          <Timestamp iso={inv.expires_at} relative={inv.status === "pending"} />
                        </td>
                        <td>{inv.invited_by?.display_name ?? <span className="text-muted">{t("people.invitations.byPlatform")}</span>}</td>
                        {jobs.isSuccess ? (
                          <td data-testid="invitation-idp">
                            {job ? (
                              <>
                                <StatusBadge status={job.status}>{text("status.job", job.status)}</StatusBadge>
                                {job.error && job.status !== "succeeded" ? (
                                  <p className="mt-1 max-w-xs text-xs">
                                    <IdpErrorText job={job} />
                                  </p>
                                ) : null}
                              </>
                            ) : (
                              <span className="text-muted">{t("people.invitations.noJob")}</span>
                            )}
                          </td>
                        ) : null}
                        <td className="space-x-2 whitespace-nowrap">
                          {mine && (inv.status === "pending" || inv.status === "expired") ? (
                            <button type="button" className="link" onClick={() => setAction({ kind: "resend", invitation: inv })}>
                              {t("people.invitations.resend")}
                            </button>
                          ) : null}
                          {mine && inv.status === "pending" ? (
                            <button type="button" className="link text-danger" onClick={() => setAction({ kind: "revoke", invitation: inv })}>
                              {t("people.invitations.revoke")}
                            </button>
                          ) : null}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )
        }
      </QueryBlock>
      <Pager pager={pager} nextCursor={list.data?.next_cursor} label={t("ui.pagination")} />
      <InviteDialog
        isOpen={inviting}
        onOpenChange={setInviting}
        onCreated={(inv) => {
          setInviting(false);
          setWatch({ id: inv.id, kind: "created" });
          void invalidatePeople(queryClient, tenantId, "invite-jobs");
        }}
      />
      <ConfirmDialog
        isOpen={action !== null}
        onOpenChange={(o) => {
          if (!o) {
            setAction(null);
            act.reset();
          }
        }}
        title={
          action?.kind === "revoke"
            ? t("people.invitations.revokeTitle", { email: action.invitation.email })
            : t("people.invitations.resendTitle", { email: action?.invitation.email ?? "" })
        }
        description={<p>{action?.kind === "revoke" ? t("people.invitations.revokeDesc") : t("people.invitations.resendDesc")}</p>}
        confirmLabel={action?.kind === "revoke" ? t("people.invitations.revoke") : t("people.invitations.resend")}
        destructive={action?.kind === "revoke"}
        pending={act.isPending}
        error={act.isError ? act.error : undefined}
        onConfirm={() => {
          if (action) act.mutate(action);
        }}
      />
    </Page>
  );
}
