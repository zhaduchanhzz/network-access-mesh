// Users (P4-T09a, §12.3): GET /tenants/{t}/users — tìm theo tên/email, lọc role và trạng thái (query string ⇒ deep link),
// phân trang con trỏ; mỗi dòng: role, trạng thái membership và trạng thái hai pha của offboard (job `member.offboard`
// mới nhất — pending/applied/failed, poll khi còn pending). Nút "Mời" mở hộp mời (POST /invitations — quyền
// tenant.invitation:manage). Thao tác trên một thành viên ở trang chi tiết.
import { useState, type SyntheticEvent } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate, useSearchParams } from "react-router";
import { useCursorPager } from "../../api/pagination";
import { can } from "../../auth/permissions";
import { FOCUS_HEADING, Page } from "../../components/Page";
import { EmptyState, Pager, QueryBlock } from "../../ui/Data";
import { useTenant } from "../TenantScope";
import { useUsers } from "./api";
import { InviteDialog } from "./InviteDialog";
import { MEMBERSHIP_STATUSES, TENANT_ROLES } from "./model";
import { MemberStatus, RoleName } from "./PeopleBits";

export function UsersPage() {
  const { t } = useTranslation();
  const { tenantId, role, membershipId, readOnly } = useTenant();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const f = {
    q: (params.get("q") ?? "").slice(0, 64),
    role: TENANT_ROLES.find((r) => r === params.get("role")) ?? "",
    status: MEMBERSHIP_STATUSES.find((s) => s === params.get("status")) ?? "",
  };
  const pager = useCursorPager(JSON.stringify(f));
  const users = useUsers(tenantId, { ...f, cursor: pager.cursor });
  const [inviting, setInviting] = useState(false);
  const canInvite = can(role, "tenant.invitation:manage");

  const update = (next: Partial<typeof f>) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries({ ...f, ...next })) if (v) p.set(k, v);
    setParams(p, { replace: true });
  };

  return (
    <Page
      title={t("nav.tenant.users")}
      actions={
        canInvite ? (
          <button type="button" className="btn-primary" disabled={readOnly} onClick={() => setInviting(true)}>
            {t("people.invite.open")}
          </button>
        ) : null
      }
    >
      {readOnly ? <p className="mb-3 text-sm text-muted">{t("ui.readOnlyActions")}</p> : null}
      <UserFilters key={f.q} q={f.q} role={f.role} status={f.status} onChange={update} />
      <QueryBlock query={users}>
        {(page) =>
          page.items.length === 0 ? (
            <EmptyState>{f.q || f.role || f.status ? t("people.users.emptyFiltered") : t("people.users.empty")}</EmptyState>
          ) : (
            <div className="relative overflow-x-auto">
              <table className="data-table" data-testid="users-table">
                <caption className="sr-only">{t("nav.tenant.users")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("people.col.name")}</th>
                    <th scope="col">{t("people.col.role")}</th>
                    <th scope="col">{t("people.col.status")}</th>
                  </tr>
                </thead>
                <tbody>
                  {page.items.map((m) => (
                    <tr key={m.id} data-testid="user-row">
                      <td>
                        <Link to={`/t/${tenantId}/users/${m.id}`} className="link font-medium">
                          {m.display_name}
                        </Link>
                        {m.id === membershipId ? <span className="ms-2 text-xs text-muted">{t("people.you")}</span> : null}
                        {m.email ? <div className="text-xs text-muted">{m.email}</div> : null}
                      </td>
                      <td>
                        <RoleName role={m.role} />
                      </td>
                      <td>
                        <MemberStatus member={m} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        }
      </QueryBlock>
      <Pager pager={pager} nextCursor={users.data?.next_cursor} label={t("ui.pagination")} />
      {canInvite ? (
        <InviteDialog
          isOpen={inviting}
          onOpenChange={setInviting}
          onCreated={(inv) => {
            setInviting(false);
            void navigate(`/t/${tenantId}/invitations`, { state: { ...FOCUS_HEADING, created: inv.id } });
          }}
        />
      ) : null}
    </Page>
  );
}

function UserFilters({ q: initial, role, status, onChange }: { q: string; role: string; status: string; onChange: (f: { q?: string; role?: string; status?: string }) => void }) {
  const { t } = useTranslation();
  const [q, setQ] = useState(initial);
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    onChange({ q: q.trim() });
  };
  return (
    <form role="search" aria-label={t("people.users.filters")} className="mb-4 flex flex-wrap items-end gap-3" onSubmit={submit}>
      <div>
        <label htmlFor="users-q" className="label">
          {t("people.users.search")}
        </label>
        <input id="users-q" className="input" type="search" maxLength={64} value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <button type="submit" className="btn-primary">
        {t("common.search")}
      </button>
      <div>
        <label htmlFor="users-role" className="label">
          {t("people.col.role")}
        </label>
        <select id="users-role" className="select" value={role} onChange={(e) => onChange({ role: e.target.value })}>
          <option value="">{t("common.all")}</option>
          {TENANT_ROLES.map((r) => (
            <option key={r} value={r}>
              {t(`roles.${r}`)}
            </option>
          ))}
        </select>
      </div>
      <div>
        <label htmlFor="users-status" className="label">
          {t("people.col.status")}
        </label>
        <select id="users-status" className="select" value={status} onChange={(e) => onChange({ status: e.target.value })}>
          <option value="">{t("common.all")}</option>
          {MEMBERSHIP_STATUSES.map((s) => (
            <option key={s} value={s}>
              {t(`people.status.${s}`)}
            </option>
          ))}
        </select>
      </div>
    </form>
  );
}
