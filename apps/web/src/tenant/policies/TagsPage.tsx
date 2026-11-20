// Danh mục tag (P4-T11 — UI của P4-T15, §6.3 tenant_tags, §7.2 tagOwners): danh sách (purpose, tag nền tảng chỉ đọc),
// khai báo (Idempotency-Key; tên `tag:<chữ thường>` bất biến), sửa mô tả (If-Match = etag; 412 ⇒ tải lại), xóa (If-Match;
// còn được thiết bị/key/tài nguyên/policy tham chiếu ⇒ 409 — `detail` của server nêu số lượng). Mỗi thay đổi danh mục
// làm server enqueue một lần áp policy (trigger tag_change).
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, call } from "../../api/client";
import { ifMatch, isStaleVersion } from "../../api/etag";
import { useIdempotentMutation } from "../../api/idempotency";
import { useCursorPager } from "../../api/pagination";
import { ApiError } from "../../api/problem";
import { queryKeys } from "../../api/queryClient";
import { can } from "../../auth/permissions";
import { Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { EmptyState, Pager, QueryBlock } from "../../ui/Data";
import { ModalDialog } from "../../ui/Dialog";
import { Timestamp } from "../../ui/time";
import { useTenant } from "../TenantScope";
import { policyKeys } from "./api";
import { TAG_NAME_RE, type Tag } from "./model";

export function TagsPage() {
  const { t } = useTranslation();
  const { tenantId, role, readOnly } = useTenant();
  const queryClient = useQueryClient();
  const pager = useCursorPager("");
  const list = useQuery({
    queryKey: policyKeys.tags(tenantId, pager.cursor ?? ""),
    queryFn: () =>
      call(api.GET("/tenants/{tenantId}/tags", { params: { path: { tenantId }, query: { limit: 50, ...(pager.cursor ? { cursor: pager.cursor } : {}) } } })),
  });
  const [editing, setEditing] = useState<Tag | null>(null);
  const [deleting, setDeleting] = useState<Tag | null>(null);
  const canManage = can(role, "tenant.tag:manage") && !readOnly;
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: queryKeys.tenant(tenantId, "tags") });
    void queryClient.invalidateQueries({ queryKey: policyKeys.names(tenantId) });
  };
  const remove = useMutation({
    mutationFn: (tag: Tag) => call(api.DELETE("/tenants/{tenantId}/tags/{tagId}", { params: { path: { tenantId, tagId: tag.id }, header: ifMatch(tag.etag) } })),
    onSuccess: () => {
      setDeleting(null);
      refresh();
    },
  });
  return (
    <Page title={t("nav.tenant.tags")}>
      {readOnly ? <p className="mb-3 text-sm text-muted">{t("ui.readOnlyActions")}</p> : null}
      <p className="mb-4 text-sm text-muted">{t("tags.intro")}</p>
      {canManage ? <CreateTag onCreated={refresh} /> : null}
      <section aria-labelledby="tags-list" className="mt-6">
        <h2 id="tags-list" className="mb-2 font-semibold">
          {t("tags.catalog")}
        </h2>
        <QueryBlock query={list}>
          {(page) =>
            page.items.length === 0 ? (
              <EmptyState>{t("tags.empty")}</EmptyState>
            ) : (
              <>
                <div className="relative overflow-x-auto">
                  <table className="data-table" data-testid="tag-table">
                    <thead>
                      <tr>
                        <th scope="col">{t("tags.col.name")}</th>
                        <th scope="col">{t("tags.col.purpose")}</th>
                        <th scope="col">{t("tags.col.description")}</th>
                        <th scope="col">{t("tags.col.updated")}</th>
                        {canManage ? <th scope="col">{t("tags.col.actions")}</th> : null}
                      </tr>
                    </thead>
                    <tbody>
                      {page.items.map((tag) => (
                        <tr key={tag.id} data-tag={tag.name}>
                          <td className="font-mono">{tag.name}</td>
                          <td>
                            {t(`tags.purposes.${tag.purpose}`)}
                            {tag.platform_managed ? <span className="ms-1 badge">{t("tags.platformManaged")}</span> : null}
                          </td>
                          <td>{tag.description ?? ""}</td>
                          <td>
                            <Timestamp iso={tag.updated_at} />
                          </td>
                          {canManage ? (
                            <td className="whitespace-nowrap">
                              {tag.platform_managed ? (
                                <span className="text-xs text-muted">{t("tags.readOnly")}</span>
                              ) : (
                                <span className="flex gap-1">
                                  <button type="button" className="btn-secondary" aria-label={t("tags.editOf", { name: tag.name })} onClick={() => setEditing(tag)}>
                                    {t("tags.edit")}
                                  </button>
                                  <button
                                    type="button"
                                    className="btn-secondary"
                                    aria-label={t("tags.deleteOf", { name: tag.name })}
                                    onClick={() => {
                                      remove.reset();
                                      setDeleting(tag);
                                    }}
                                  >
                                    {t("tags.delete")}
                                  </button>
                                </span>
                              )}
                            </td>
                          ) : null}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <Pager pager={pager} nextCursor={page.next_cursor} label={t("ui.pagination")} />
              </>
            )
          }
        </QueryBlock>
      </section>
      {editing ? <EditTag tag={editing} onClose={() => setEditing(null)} onSaved={refresh} /> : null}
      <ConfirmDialog
        isOpen={deleting !== null}
        onOpenChange={(o) => {
          if (!o) setDeleting(null);
        }}
        title={t("tags.deleteTitle", { name: deleting?.name ?? "" })}
        description={<p>{t("tags.deleteDescription")}</p>}
        confirmLabel={t("tags.delete")}
        destructive
        pending={remove.isPending}
        error={remove.isError ? remove.error : undefined}
        onConfirm={() => {
          if (deleting) remove.mutate(deleting);
        }}
      >
        {remove.error instanceof ApiError && remove.error.code === "conflict" ? (
          <p className="text-sm" data-testid="tag-in-use">
            {t("tags.inUse")}
          </p>
        ) : null}
      </ConfirmDialog>
    </Page>
  );
}

function CreateTag({ onCreated }: { onCreated: () => void }) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const id = useId();
  const [name, setName] = useState("tag:");
  const [purpose, setPurpose] = useState<"custom" | "server">("custom");
  const [description, setDescription] = useState("");
  const valid = TAG_NAME_RE.test(name);
  const create = useIdempotentMutation({
    mutationFn: (body: { name: string; purpose: "custom" | "server"; description?: string }, key: string) =>
      call(api.POST("/tenants/{tenantId}/tags", { params: { path: { tenantId }, header: { "Idempotency-Key": key } }, body })),
    onSuccess: () => {
      setName("tag:");
      setDescription("");
      onCreated();
    },
  });
  return (
    <section className="card" aria-labelledby={`${id}-title`}>
      <h2 id={`${id}-title`} className="font-semibold">
        {t("tags.create")}
      </h2>
      <form
        className="mt-2 grid gap-3 md:grid-cols-[1fr_auto_1fr_auto] md:items-end"
        onSubmit={(e) => {
          e.preventDefault();
          if (valid) create.mutate({ name, purpose, ...(description.trim() ? { description: description.trim() } : {}) });
        }}
      >
        <div>
          <label htmlFor={`${id}-name`} className="label">
            {t("tags.col.name")}
          </label>
          <input
            id={`${id}-name`}
            className="input font-mono"
            value={name}
            spellCheck={false}
            autoComplete="off"
            aria-invalid={name !== "tag:" && !valid}
            aria-describedby={`${id}-name-hint`}
            onChange={(e) => setName(e.target.value.toLowerCase())}
          />
          <p id={`${id}-name-hint`} className={name !== "tag:" && !valid ? "field-error" : "hint"}>
            {t("tags.nameHint")}
          </p>
        </div>
        <div>
          <label htmlFor={`${id}-purpose`} className="label">
            {t("tags.col.purpose")}
          </label>
          <select id={`${id}-purpose`} className="select" value={purpose} onChange={(e) => setPurpose(e.target.value as "custom" | "server")}>
            <option value="custom">{t("tags.purposes.custom")}</option>
            <option value="server">{t("tags.purposes.server")}</option>
          </select>
        </div>
        <div>
          <label htmlFor={`${id}-desc`} className="label">
            {t("tags.col.description")}
          </label>
          <input id={`${id}-desc`} className="input" maxLength={1000} value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
        <button type="submit" className="btn-primary" disabled={!valid || create.isPending}>
          {create.isPending ? t("common.working") : t("tags.createAction")}
        </button>
      </form>
      {create.isError ? (
        <div className="mt-2">
          <ProblemAlert error={create.error} />
        </div>
      ) : null}
      {create.isSuccess ? (
        <p role="status" className="mt-2 text-sm" data-testid="tag-created">
          {t("tags.created", { name: create.data.name })}
        </p>
      ) : null}
    </section>
  );
}

function EditTag({ tag, onClose, onSaved }: { tag: Tag; onClose: () => void; onSaved: () => void }) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const id = useId();
  const [description, setDescription] = useState(tag.description ?? "");
  const save = useMutation({
    mutationFn: () =>
      call(
        api.PATCH("/tenants/{tenantId}/tags/{tagId}", {
          params: { path: { tenantId, tagId: tag.id }, header: ifMatch(tag.etag) },
          body: { description: description.trim() },
        }),
      ),
    onSuccess: () => {
      onSaved();
      onClose();
    },
  });
  return (
    <ModalDialog
      isOpen
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
      title={t("tags.editTitle", { name: tag.name })}
      busy={save.isPending}
    >
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate();
        }}
      >
        <div>
          <label htmlFor={`${id}-desc`} className="label">
            {t("tags.col.description")}
          </label>
          <textarea id={`${id}-desc`} className="input" rows={3} maxLength={1000} value={description} onChange={(e) => setDescription(e.target.value)} autoFocus />
        </div>
        {save.isError ? <ProblemAlert error={save.error} /> : null}
        {isStaleVersion(save.error) ? <p className="text-sm text-warn">{t("tags.stale")}</p> : null}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn-secondary" onClick={onClose} disabled={save.isPending}>
            {t("ui.cancel")}
          </button>
          <button type="submit" className="btn-primary" disabled={save.isPending}>
            {save.isPending ? t("common.working") : t("tags.save")}
          </button>
        </div>
      </form>
    </ModalDialog>
  );
}
