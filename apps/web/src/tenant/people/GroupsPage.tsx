// Groups (P4-T09a, §12.3 — API của P4-T09): GET /groups (tìm theo tên, con trỏ) và tạo group (POST, Idempotency-Key —
// tên `^[a-z][a-z0-9-]{0,49}$`, render thành `group:<name>` của policy; trùng ⇒ 409). Group *sensitive*
// (TenantSettings.policy.sensitive_groups — khóa bảo mật, đổi ở thiết lập bảo mật của Owner) đánh dấu riêng: đổi thành
// viên của nó cần người thứ hai duyệt.
import { useQueryClient } from "@tanstack/react-query";
import { useId, useState, type SyntheticEvent } from "react";
import { useTranslation } from "react-i18next";
import { Link, useNavigate, useSearchParams } from "react-router";
import { api, callWithResponse } from "../../api/client";
import type { Versioned } from "../../api/etag";
import { useIdempotentMutation } from "../../api/idempotency";
import { useCursorPager } from "../../api/pagination";
import { can } from "../../auth/permissions";
import { Page } from "../../components/Page";
import { EmptyState, Pager, QueryBlock } from "../../ui/Data";
import { ModalDialog } from "../../ui/Dialog";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { useTenant } from "../TenantScope";
import { invalidatePeople, peopleKeys, useGroups } from "./api";
import { GROUP_DESCRIPTION_MAX, GROUP_NAME_RE, type Group } from "./model";
import { ActionError } from "./PeopleBits";

export function GroupsPage() {
  const { t } = useTranslation();
  const { tenantId, role, readOnly } = useTenant();
  const [params, setParams] = useSearchParams();
  const q = (params.get("q") ?? "").slice(0, 64);
  const pager = useCursorPager(q);
  const groups = useGroups(tenantId, { q, cursor: pager.cursor });
  const [creating, setCreating] = useState(false);
  const canManage = can(role, "tenant.group:manage");
  return (
    <Page
      title={t("nav.tenant.groups")}
      actions={
        canManage ? (
          <button type="button" className="btn-primary" disabled={readOnly} onClick={() => setCreating(true)}>
            {t("people.groups.create")}
          </button>
        ) : null
      }
    >
      {readOnly ? <p className="mb-3 text-sm text-muted">{t("ui.readOnlyActions")}</p> : null}
      <p className="mb-4 text-sm text-muted">{t("people.groups.intro")}</p>
      <GroupSearch key={q} q={q} onChange={(v) => setParams(v ? { q: v } : {}, { replace: true })} />
      <QueryBlock query={groups}>
        {(page) =>
          page.items.length === 0 ? (
            <EmptyState>{q ? t("people.groups.emptyFiltered") : t("people.groups.empty")}</EmptyState>
          ) : (
            <div className="overflow-x-auto">
              <table className="data-table" data-testid="groups-table">
                <caption className="sr-only">{t("nav.tenant.groups")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("people.col.name")}</th>
                    <th scope="col">{t("people.groups.description")}</th>
                    <th scope="col">{t("people.groups.members")}</th>
                    <th scope="col">{t("people.groups.source")}</th>
                    <th scope="col">{t("people.groups.updated")}</th>
                  </tr>
                </thead>
                <tbody>
                  {page.items.map((g) => (
                    <tr key={g.id} data-testid="group-row">
                      <td>
                        <Link to={`/t/${tenantId}/groups/${g.id}`} className="link font-mono font-medium">
                          {g.name}
                        </Link>
                        {g.sensitive ? (
                          <span className="ms-2">
                            <SensitiveBadge />
                          </span>
                        ) : null}
                      </td>
                      <td className="text-sm">{g.description ?? ""}</td>
                      <td>{g.member_count}</td>
                      <td>{t(`people.groups.sources.${g.source}`)}</td>
                      <td>
                        <Timestamp iso={g.updated_at} relative={false} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        }
      </QueryBlock>
      <Pager pager={pager} nextCursor={groups.data?.next_cursor} label={t("ui.pagination")} />
      {canManage ? <CreateGroupDialog isOpen={creating} onOpenChange={setCreating} /> : null}
    </Page>
  );
}

export function SensitiveBadge() {
  const { t } = useTranslation();
  return (
    <StatusBadge tone="warn" status="sensitive" testId="sensitive-badge">
      {t("people.groups.sensitive")}
    </StatusBadge>
  );
}

function GroupSearch({ q: initial, onChange }: { q: string; onChange: (q: string) => void }) {
  const { t } = useTranslation();
  const [q, setQ] = useState(initial);
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    onChange(q.trim());
  };
  return (
    <form role="search" aria-label={t("people.groups.search")} className="mb-4 flex flex-wrap items-end gap-3" onSubmit={submit}>
      <div>
        <label htmlFor="groups-q" className="label">
          {t("people.groups.search")}
        </label>
        <input id="groups-q" className="input" type="search" maxLength={64} value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      <button type="submit" className="btn-primary">
        {t("common.search")}
      </button>
    </form>
  );
}

function CreateGroupDialog({ isOpen, onOpenChange }: { isOpen: boolean; onOpenChange: (o: boolean) => void }) {
  const { t } = useTranslation();
  return (
    <ModalDialog isOpen={isOpen} onOpenChange={onOpenChange} title={t("people.groups.createTitle")}>
      <CreateGroupForm onCancel={() => onOpenChange(false)} />
    </ModalDialog>
  );
}

/** Tên + mô tả của group, kiểm cục bộ theo pattern của spec (chỉ để hướng dẫn — 409/422 của server hiện nguyên văn). */
export function GroupFields({
  name,
  description,
  onName,
  onDescription,
  disabled = false,
  autoFocus = false,
}: {
  name: string;
  description: string;
  onName: (v: string) => void;
  onDescription: (v: string) => void;
  disabled?: boolean;
  autoFocus?: boolean;
}) {
  const { t } = useTranslation();
  const ids = { name: useId(), nameHint: useId(), desc: useId() };
  const bad = name !== "" && !GROUP_NAME_RE.test(name);
  return (
    <>
      <div>
        <label htmlFor={ids.name} className="label">
          {t("people.groups.name")}
        </label>
        <input
          id={ids.name}
          className="input font-mono"
          autoComplete="off"
          spellCheck={false}
          autoFocus={autoFocus}
          maxLength={50}
          value={name}
          disabled={disabled}
          aria-invalid={bad}
          aria-describedby={ids.nameHint}
          onChange={(e) => onName(e.target.value.toLowerCase())}
        />
        <p id={ids.nameHint} className={bad ? "field-error" : "hint"}>
          {t("people.groups.nameHint")}
        </p>
      </div>
      <div>
        <label htmlFor={ids.desc} className="label">
          {t("people.groups.description")}
        </label>
        <textarea
          id={ids.desc}
          className="input"
          rows={2}
          maxLength={GROUP_DESCRIPTION_MAX}
          value={description}
          disabled={disabled}
          onChange={(e) => onDescription(e.target.value)}
        />
      </div>
    </>
  );
}

function CreateGroupForm({ onCancel }: { onCancel: () => void }) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const create = useIdempotentMutation({
    mutationFn: (body: { name: string; description?: string }, key: string) =>
      callWithResponse(api.POST("/tenants/{tenantId}/groups", { params: { path: { tenantId }, header: { "Idempotency-Key": key } }, body })),
    onSuccess: async (r) => {
      queryClient.setQueryData<Versioned<Group>>(peopleKeys.group(tenantId, r.data.id), { data: r.data, etag: r.response.headers.get("ETag") });
      await invalidatePeople(queryClient, tenantId, "groups");
      void navigate(`/t/${tenantId}/groups/${r.data.id}`);
    },
  });
  const ok = GROUP_NAME_RE.test(name);
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    if (!ok || create.isPending) return;
    create.mutate(description.trim() ? { name, description: description.trim() } : { name });
  };
  return (
    <form className="space-y-3" onSubmit={submit} noValidate>
      <GroupFields name={name} description={description} onName={setName} onDescription={setDescription} autoFocus />
      <ActionError error={create.isError ? create.error : null} />
      <div className="flex justify-end gap-2 pt-2">
        <button type="button" className="btn-secondary" disabled={create.isPending} onClick={onCancel}>
          {t("ui.cancel")}
        </button>
        <button type="submit" className="btn-primary" disabled={!ok || create.isPending}>
          {create.isPending ? t("common.working") : t("people.groups.createSubmit")}
        </button>
      </div>
    </form>
  );
}
