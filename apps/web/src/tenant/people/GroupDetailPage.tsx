// Chi tiết group (P4-T09a, §12.3 — API của P4-T09): GET /groups/{id} (+ ETag, kèm thành viên); sửa tên/mô tả (PATCH,
// If-Match), xóa (DELETE, If-Match, gõ lại tên), đặt thành viên (PUT …/members, If-Match — chỉ thành viên `active`).
// Group sensitive: PUT không đổi gì mà trả 202 + yêu cầu phê duyệt trong tenant (`tenant.group.set_members`, người gọi
// step-up); màn hình hiện yêu cầu đó (và mọi yêu cầu đang chờ của group) — poll GET /approvals/{id} tới khi người thứ
// hai duyệt (executed ⇒ đọc lại group) hoặc từ chối/hết hạn. 412 ⇒ bản đã cũ: tải lại để người dùng quyết định lại.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type SyntheticEvent } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate, useParams } from "react-router";
import { api, callWithResponse } from "../../api/client";
import { ifMatch, isStaleVersion, type Versioned } from "../../api/etag";
import { approvalFromLocation } from "../../api/jobs";
import { ApiError } from "../../api/problem";
import { isUuid } from "../../api/queryClient";
import { can } from "../../auth/permissions";
import { Loading, Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { NotFoundPage } from "../../pages/StatusPages";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { EmptyState, Field } from "../../ui/Data";
import { StatusBadge, useCodeText } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { useTenant } from "../TenantScope";
import { invalidatePeople, peopleKeys, useGroup, useGroupApprovals, useTenantApproval, useUsers } from "./api";
import { GroupFields, SensitiveBadge } from "./GroupsPage";
import {
  approvalMemberCount,
  GROUP_MEMBERS_MAX,
  GROUP_NAME_RE,
  memberSet,
  sameSet,
  SENSITIVE_MEMBERS_MAX,
  type ApprovalRequest,
  type Group,
  type GroupMember,
} from "./model";
import { ActionError, MemberStatus, RoleName } from "./PeopleBits";

export function GroupDetailPage() {
  const { groupId: raw = "" } = useParams();
  const id = raw.toLowerCase();
  if (!isUuid(id)) return <NotFoundPage />;
  return <GroupDetail key={id} groupId={id} />;
}

function GroupDetail({ groupId }: { groupId: string }) {
  const { t } = useTranslation();
  const { tenantId, role, readOnly } = useTenant();
  const queryClient = useQueryClient();
  const group = useGroup(tenantId, groupId);
  const canManage = can(role, "tenant.group:manage") && !readOnly;
  const canReadApprovals = can(role, "tenant.approval:read");
  const [requested, setRequested] = useState<ApprovalRequest | null>(null);
  const [editing, setEditing] = useState(false);
  const pendingApprovals = useGroupApprovals(tenantId, groupId, canReadApprovals);
  const store = (data: Group, etag: string | null) => {
    queryClient.setQueryData<Versioned<Group>>(peopleKeys.group(tenantId, groupId), { data, etag });
    void invalidatePeople(queryClient, tenantId, "groups");
  };

  if (group.error instanceof ApiError && group.error.status === 404) return <NotFoundPage />;
  if (group.isPending) return <Loading />;
  if (group.isError) {
    return (
      <Page title={t("nav.tenant.groups")}>
        <ProblemAlert error={group.error} onRetry={() => void group.refetch()} />
      </Page>
    );
  }
  const g = group.data.data;
  const etag = group.data.etag;
  const others = (pendingApprovals.data ?? []).filter((a) => a.id !== requested?.id);
  return (
    <Page title={g.name}>
      <p className="-mt-4 mb-4">
        <Link to={`/t/${tenantId}/groups`} className="link text-sm">
          {t("people.groups.back")}
        </Link>
      </p>
      {readOnly ? <p className="mb-3 text-sm text-muted">{t("ui.readOnlyActions")}</p> : null}
      {requested ? <ApprovalPanel approval={requested} groupId={groupId} canRead={canReadApprovals} /> : null}
      {others.length > 0 ? (
        <section className="card mb-4" aria-labelledby="group-pending" data-testid="group-pending-approvals">
          <h2 id="group-pending" className="font-semibold">
            {t("people.approval.pendingTitle")}
          </h2>
          <ul className="mt-2 space-y-1 text-sm">
            {others.map((a) => (
              <li key={a.id}>
                <code>{a.id}</code> {" · "}
                {t("people.approval.requestedBy", { name: a.requested_by.display_name })} {" · "}
                {t("people.approval.memberCount", { count: approvalMemberCount(a) ?? 0 })} {" · "}
                {t("people.approval.expires")} <Timestamp iso={a.expires_at} />
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      <section className="card" aria-labelledby="group-info">
        <h2 id="group-info" className="font-semibold">
          {t("people.groups.info")}
        </h2>
        <dl className="mt-3 grid gap-4 sm:grid-cols-2">
          <Field label={t("people.groups.name")}>
            <code>{g.name}</code> <span className="text-xs text-muted">{t("people.groups.policyName", { name: g.name })}</span>
          </Field>
          <Field label={t("people.groups.description")}>{g.description ?? <span className="text-muted">{t("common.none")}</span>}</Field>
          <Field label={t("people.groups.members")}>
            <span data-testid="group-member-count">{g.member_count}</span>
          </Field>
          <Field label={t("people.groups.source")}>{t(`people.groups.sources.${g.source}`)}</Field>
          <Field label={t("people.groups.sensitiveLabel")}>
            {g.sensitive ? <SensitiveBadge /> : t("people.groups.notSensitive")}
          </Field>
          <Field label={t("people.groups.updated")}>
            <Timestamp iso={g.updated_at} />
          </Field>
        </dl>
        {g.sensitive ? <p className="mt-3 text-sm text-muted">{t("people.groups.sensitiveExplain")}</p> : null}
      </section>
      <MembersSection
        group={g}
        etag={etag}
        canManage={canManage}
        editing={editing}
        onEdit={setEditing}
        onSaved={(r) => {
          setEditing(false);
          if (r.kind === "applied") store(r.group, r.etag);
          else {
            setRequested(r.approval);
            void invalidatePeople(queryClient, tenantId, "group-approvals", groupId);
          }
        }}
      />
      {canManage ? <EditGroup group={g} etag={etag} onSaved={store} /> : null}
      {canManage ? <DeleteGroup group={g} etag={etag} /> : null}
    </Page>
  );
}

/** Yêu cầu phê duyệt vừa tạo (202): trạng thái hiệu lực, người yêu cầu, hạn, số thành viên trong payload. */
function ApprovalPanel({ approval, groupId, canRead }: { approval: ApprovalRequest; groupId: string; canRead: boolean }) {
  const { t } = useTranslation();
  const text = useCodeText();
  const { tenantId } = useTenant();
  const queryClient = useQueryClient();
  const live = useTenantApproval(tenantId, approval.id, canRead);
  const a = live.data ?? approval;
  useEffect(() => {
    if (a.status === "executed") {
      void invalidatePeople(queryClient, tenantId, "group", groupId);
      void invalidatePeople(queryClient, tenantId, "groups");
      void invalidatePeople(queryClient, tenantId, "group-approvals", groupId);
    }
  }, [a.status, queryClient, tenantId, groupId]);
  return (
    <div role="status" aria-live="polite" className="mb-4 rounded-md border border-line bg-surface p-4" data-testid="approval-panel" data-status={a.status}>
      <p className="font-medium">
        <StatusBadge status={a.status} testId="approval-status">
          {text("status.approval", a.status)}
        </StatusBadge>{" "}
        {t(`people.approval.explain.${a.status}`)}
      </p>
      <dl className="mt-2 grid gap-2 text-sm sm:grid-cols-2">
        <Field label={t("people.approval.id")}>
          <code data-testid="approval-id">{a.id}</code>
        </Field>
        <Field label={t("people.approval.payload")}>{t("people.approval.memberCount", { count: approvalMemberCount(a) ?? 0 })}</Field>
        <Field label={t("people.approval.requester")}>{a.requested_by.display_name}</Field>
        <Field label={t("people.approval.expires")}>
          <Timestamp iso={a.expires_at} />
        </Field>
      </dl>
      {canRead ? (
        <p className="mt-2 text-sm">
          <Link to={`/t/${tenantId}/approvals`} className="link">
            {t("people.approval.queue")}
          </Link>
        </p>
      ) : null}
      {live.isError ? <ProblemAlert error={live.error} /> : null}
    </div>
  );
}

type SaveResult = { kind: "applied"; group: Group; etag: string | null } | { kind: "approval"; approval: ApprovalRequest };

function MembersSection({
  group,
  etag,
  canManage,
  editing,
  onEdit,
  onSaved,
}: {
  group: Group;
  etag: string | null;
  canManage: boolean;
  editing: boolean;
  onEdit: (e: boolean) => void;
  onSaved: (r: SaveResult) => void;
}) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const members = group.members ?? [];
  return (
    <section className="card mt-4" aria-labelledby="group-members">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 id="group-members" className="font-semibold">
          {t("people.groups.membersTitle")}
        </h2>
        {canManage && !editing ? (
          <button type="button" className="btn-secondary" onClick={() => onEdit(true)}>
            {t("people.groups.editMembers")}
          </button>
        ) : null}
      </div>
      {editing ? (
        <MembersEditor group={group} etag={etag} onCancel={() => onEdit(false)} onSaved={onSaved} />
      ) : members.length === 0 ? (
        <div className="mt-3">
          <EmptyState>{t("people.groups.noMembers")}</EmptyState>
        </div>
      ) : (
        <div className="mt-3 overflow-x-auto">
          <table className="data-table" data-testid="group-members-table">
            <caption className="sr-only">{t("people.groups.membersTitle")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("people.col.name")}</th>
                <th scope="col">{t("people.col.role")}</th>
                <th scope="col">{t("people.col.status")}</th>
              </tr>
            </thead>
            <tbody>
              {members.map((m) => (
                <tr key={m.membership_id} data-testid="group-member-row">
                  <td>
                    <Link to={`/t/${tenantId}/users/${m.membership_id}`} className="link">
                      {m.display_name}
                    </Link>
                    {m.email ? <div className="text-xs text-muted">{m.email}</div> : null}
                  </td>
                  <td>
                    <RoleName role={m.role} />
                  </td>
                  <td>
                    <MemberStatus member={{ status: m.status }} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/** Tập thành viên đang soạn: bỏ người đang có, thêm người tìm được (chỉ thành viên `active` — server cũng kiểm, 422). */
function MembersEditor({ group, etag, onCancel, onSaved }: { group: Group; etag: string | null; onCancel: () => void; onSaved: (r: SaveResult) => void }) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const queryClient = useQueryClient();
  const original = (group.members ?? []).map((m) => m.membership_id);
  const [draft, setDraft] = useState<Map<string, Pick<GroupMember, "membership_id" | "display_name" | "email" | "role">>>(
    () => new Map((group.members ?? []).map((m) => [m.membership_id, m])),
  );
  const [q, setQ] = useState("");
  const [search, setSearch] = useState("");
  const candidates = useUsers(tenantId, { q: search, status: "active" }, { limit: 20 });
  const ids = memberSet(draft.keys());
  const limit = group.sensitive ? SENSITIVE_MEMBERS_MAX : GROUP_MEMBERS_MAX;
  const changed = !sameSet(ids, original);

  const save = useMutation({
    mutationFn: async (membershipIds: string[]): Promise<SaveResult> => {
      const r = await callWithResponse(
        api.PUT("/tenants/{tenantId}/groups/{groupId}/members", {
          params: { path: { tenantId, groupId: group.id }, header: ifMatch(etag) },
          body: { membership_ids: membershipIds },
        }),
      );
      if (r.response.status === 202) {
        const approval = r.data as ApprovalRequest;
        const id = approvalFromLocation(r.response.headers.get("Location")) ?? approval.id;
        return { kind: "approval", approval: { ...approval, id } };
      }
      return { kind: "applied", group: r.data as Group, etag: r.response.headers.get("ETag") };
    },
    onSuccess: onSaved,
    onError: (e) => {
      if (isStaleVersion(e)) void invalidatePeople(queryClient, tenantId, "group", group.id);
    },
  });
  const remove = (id: string) => {
    setDraft((d) => {
      const n = new Map(d);
      n.delete(id);
      return n;
    });
  };
  const add = (m: Pick<GroupMember, "membership_id" | "display_name" | "email" | "role">) => {
    setDraft((d) => new Map(d).set(m.membership_id, m));
  };
  const submitSearch = (e: SyntheticEvent) => {
    e.preventDefault();
    setSearch(q.trim());
  };
  return (
    <div className="mt-3 space-y-4" data-testid="members-editor">
      {group.sensitive ? (
        <p className="rounded-md border border-line bg-bg p-3 text-sm" data-testid="sensitive-note">
          {t("people.groups.sensitiveEditNote")}
        </p>
      ) : null}
      <div>
        <h3 className="text-sm font-semibold">{t("people.groups.draftTitle", { count: ids.length })}</h3>
        {ids.length === 0 ? (
          <p className="mt-1 text-sm text-muted">{t("people.groups.draftEmpty")}</p>
        ) : (
          <ul className="mt-2 divide-y divide-line rounded-md border border-line" aria-label={t("people.groups.draftList")}>
            {[...draft.values()].map((m) => (
              <li key={m.membership_id} className="flex items-center justify-between gap-2 p-2 text-sm" data-testid="draft-member">
                <span>
                  {m.display_name}
                  {m.email ? <span className="ms-2 text-xs text-muted">{m.email}</span> : null}
                </span>
                <button
                  type="button"
                  className="link text-danger"
                  aria-label={t("people.groups.removeMember", { name: m.display_name })}
                  onClick={() => remove(m.membership_id)}
                >
                  {t("people.groups.remove")}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
      <div>
        <form role="search" aria-label={t("people.groups.findForm")} className="flex flex-wrap items-end gap-2" onSubmit={submitSearch}>
          <div>
            <label htmlFor="group-member-q" className="label">
              {t("people.groups.findMembers")}
            </label>
            <input id="group-member-q" className="input" type="search" maxLength={64} value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <button type="submit" className="btn-secondary">
            {t("common.search")}
          </button>
        </form>
        <p className="hint">{t("people.groups.onlyActive")}</p>
        {candidates.isError ? <ProblemAlert error={candidates.error} /> : null}
        {candidates.data ? (
          <ul className="mt-2 divide-y divide-line rounded-md border border-line" aria-label={t("people.groups.candidates")}>
            {candidates.data.items.map((m) => (
              <li key={m.id} className="flex items-center justify-between gap-2 p-2 text-sm" data-testid="candidate">
                <span>
                  {m.display_name}
                  {m.email ? <span className="ms-2 text-xs text-muted">{m.email}</span> : null}
                  <span className="ms-2 text-xs text-muted">
                    <RoleName role={m.role} />
                  </span>
                </span>
                <button
                  type="button"
                  className="btn-secondary"
                  disabled={draft.has(m.id)}
                  aria-label={t("people.groups.addMember", { name: m.display_name })}
                  onClick={() => add({ membership_id: m.id, display_name: m.display_name, email: m.email, role: m.role })}
                >
                  {draft.has(m.id) ? t("people.groups.added") : t("people.groups.add")}
                </button>
              </li>
            ))}
            {candidates.data.items.length === 0 ? <li className="p-2 text-sm text-muted">{t("people.groups.noCandidates")}</li> : null}
          </ul>
        ) : null}
      </div>
      {ids.length > limit ? (
        <p className="field-error" role="alert">
          {t("people.groups.tooMany", { max: limit })}
        </p>
      ) : null}
      <ActionError error={save.isError ? save.error : null} />
      {save.isError && isStaleVersion(save.error) ? <p className="text-sm">{t("people.groups.staleReloaded")}</p> : null}
      <div className="flex flex-wrap justify-end gap-2">
        <button type="button" className="btn-secondary" disabled={save.isPending} onClick={onCancel}>
          {t("ui.cancel")}
        </button>
        <button type="button" className="btn-primary" disabled={!changed || ids.length > limit || save.isPending} onClick={() => save.mutate(ids)}>
          {save.isPending ? t("common.working") : group.sensitive ? t("people.groups.requestApproval") : t("people.groups.saveMembers")}
        </button>
      </div>
    </div>
  );
}

function EditGroup({ group, etag, onSaved }: { group: Group; etag: string | null; onSaved: (g: Group, etag: string | null) => void }) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const queryClient = useQueryClient();
  const [name, setName] = useState(group.name);
  const [description, setDescription] = useState(group.description ?? "");
  const body: { name?: string; description?: string } = {};
  if (name !== group.name) body.name = name;
  if (description !== (group.description ?? "")) body.description = description;
  const dirty = Object.keys(body).length > 0;
  const update = useMutation({
    mutationFn: (b: { name?: string; description?: string }) =>
      callWithResponse(api.PATCH("/tenants/{tenantId}/groups/{groupId}", { params: { path: { tenantId, groupId: group.id }, header: ifMatch(etag) }, body: b })),
    onSuccess: (r) => onSaved(r.data, r.response.headers.get("ETag")),
    onError: (e) => {
      if (isStaleVersion(e)) void invalidatePeople(queryClient, tenantId, "group", group.id);
    },
  });
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    if (dirty && GROUP_NAME_RE.test(name) && !update.isPending) update.mutate(body);
  };
  return (
    <section className="card mt-4" aria-labelledby="group-edit">
      <h2 id="group-edit" className="font-semibold">
        {t("people.groups.editTitle")}
      </h2>
      <form className="mt-3 space-y-3" onSubmit={submit} noValidate>
        <GroupFields name={name} description={description} onName={setName} onDescription={setDescription} />
        {name !== group.name ? <p className="hint">{t("people.groups.renameNote")}</p> : null}
        <ActionError error={update.isError ? update.error : null} />
        {update.isSuccess && !dirty ? (
          <p role="status" className="text-sm">
            {t("people.groups.saved")}
          </p>
        ) : null}
        <button type="submit" className="btn-primary" disabled={!dirty || !GROUP_NAME_RE.test(name) || update.isPending}>
          {t("people.groups.save")}
        </button>
      </form>
    </section>
  );
}

function DeleteGroup({ group, etag }: { group: Group; etag: string | null }) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const remove = useMutation({
    mutationFn: () => callWithResponse(api.DELETE("/tenants/{tenantId}/groups/{groupId}", { params: { path: { tenantId, groupId: group.id }, header: ifMatch(etag) } })),
    onSuccess: async () => {
      setOpen(false);
      queryClient.removeQueries({ queryKey: peopleKeys.group(tenantId, group.id) });
      await invalidatePeople(queryClient, tenantId, "groups");
      void navigate(`/t/${tenantId}/groups`);
    },
    onError: (e) => {
      if (isStaleVersion(e)) void invalidatePeople(queryClient, tenantId, "group", group.id);
    },
  });
  return (
    <section className="card mt-4 border-danger/40" aria-labelledby="group-delete">
      <h2 id="group-delete" className="font-semibold">
        {t("people.groups.deleteTitle")}
      </h2>
      <p className="mt-1 text-sm text-muted">{group.sensitive && group.member_count > 0 ? t("people.groups.deleteSensitive") : t("people.groups.deleteDesc")}</p>
      <button type="button" className="btn-danger mt-3" onClick={() => setOpen(true)}>
        {t("people.groups.delete")}
      </button>
      <ConfirmDialog
        isOpen={open}
        onOpenChange={(o) => {
          if (!o) {
            setOpen(false);
            remove.reset();
          }
        }}
        title={t("people.groups.deleteConfirmTitle", { name: group.name })}
        description={<p>{t("people.groups.deleteConfirmDesc", { count: group.member_count })}</p>}
        typedConfirmation={{ expected: group.name, label: t("people.groups.typeName") }}
        confirmLabel={t("people.groups.delete")}
        destructive
        pending={remove.isPending}
        error={remove.isError ? remove.error : undefined}
        onConfirm={() => remove.mutate()}
      />
    </section>
  );
}
