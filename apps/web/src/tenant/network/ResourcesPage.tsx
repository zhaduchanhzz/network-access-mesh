// Network Resource Catalog (P4-T12, §12.3, §7.2 — alias của khóa `hosts` trong policy): GET /tenants/{t}/resources
// (phân trang cursor), POST (Idempotency-Key), PATCH/DELETE (`If-Match` = `etag` của tài nguyên). Tag chọn từ danh mục
// (GET /tags — khi có tenant.tag:read), nhóm sở hữu từ GET /groups (khi có tenant.group:read); không có quyền ⇒ ô đó ẩn
// (không gửi). Lỗi 422 hiện cạnh từng ô; 412 ⇒ tài nguyên đã đổi ⇒ đóng hộp, tải lại danh sách. Mỗi thay đổi kéo theo
// job `policy.apply` ở server (render lại alias) — response không kèm job.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useState, type SyntheticEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, call } from "../../api/client";
import { ifMatch, isStaleVersion } from "../../api/etag";
import { useIdempotentMutation } from "../../api/idempotency";
import { useCursorPager } from "../../api/pagination";
import { queryKeys } from "../../api/queryClient";
import type { components } from "../../api/schema";
import { can } from "../../auth/permissions";
import { Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { EmptyState, Pager, QueryBlock } from "../../ui/Data";
import { ModalDialog } from "../../ui/Dialog";
import { Timestamp } from "../../ui/time";
import { TagList } from "../devices/DeviceBits";
import { useTenant } from "../TenantScope";
import { FieldError, formLevelError, invalidProps, useFieldErrors } from "./networkBits";

export type NetworkResource = components["schemas"]["NetworkResource"];
type ResourceCreate = components["schemas"]["NetworkResourceCreate"];
type ResourceUpdate = components["schemas"]["NetworkResourceUpdate"];
type Kind = components["schemas"]["NetworkResourceKind"];
type Protocol = components["schemas"]["NetworkResourceProtocol"];

export const RESOURCE_KINDS = ["host", "subnet", "service"] as const satisfies readonly Kind[];
export const RESOURCE_PROTOCOLS = ["any", "tcp", "udp", "icmp"] as const satisfies readonly Protocol[];
type Assert<T extends true> = T;
/** Lỗi typecheck ⇒ spec thêm kind/protocol chưa có ở đây (và chưa có bản dịch). */
export type AllKindsListed = Assert<[Exclude<Kind, (typeof RESOURCE_KINDS)[number]>] extends [never] ? true : false>;
export type AllProtocolsListed = Assert<[Exclude<Protocol, (typeof RESOURCE_PROTOCOLS)[number]>] extends [never] ? true : false>;

export const RESOURCE_PAGE_SIZE = 50;
/** Danh mục tag / nhóm cho ô chọn: trang đầu, tối đa 200 (giới hạn `limit` của spec). */
const OPTIONS_LIMIT = 200;
const FORM_FIELDS = ["name", "kind", "address", "ports", "protocol", "tags", "owner_group_id", "description"] as const;

/** "443, 8000-8100" ⇒ ["443", "8000-8100"] (server kiểm cú pháp và miền giá trị). */
export function parsePorts(text: string): string[] {
  return text.split(/[\s,]+/).filter((s) => s !== "");
}

export function ResourcesPage() {
  const { t } = useTranslation();
  const { tenantId, role, readOnly } = useTenant();
  const queryClient = useQueryClient();
  const pager = useCursorPager(tenantId);
  const list = useQuery({
    queryKey: queryKeys.tenant(tenantId, "resources", "list", { cursor: pager.cursor ?? "" }),
    queryFn: () =>
      call(
        api.GET("/tenants/{tenantId}/resources", {
          params: { path: { tenantId }, query: { limit: RESOURCE_PAGE_SIZE, ...(pager.cursor ? { cursor: pager.cursor } : {}) } },
        }),
      ),
    placeholderData: (prev) => prev,
  });
  const canManage = can(role, "tenant.resource:manage");
  const canGroups = can(role, "tenant.group:read");
  const groups = useQuery({
    queryKey: queryKeys.tenant(tenantId, "groups", "options"),
    queryFn: () => call(api.GET("/tenants/{tenantId}/groups", { params: { path: { tenantId }, query: { limit: OPTIONS_LIMIT } } })),
    enabled: canGroups,
    staleTime: 60_000,
  });
  const groupName = (id: string | undefined) => (id ? (groups.data?.items.find((g) => g.id === id)?.name ?? id) : undefined);
  const [editing, setEditing] = useState<NetworkResource | "new" | null>(null);
  const [deleting, setDeleting] = useState<NetworkResource | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  // danh mục cũng là nguồn của bộ chọn tài nguyên trong Biểu mẫu policy (G4b-E4) ⇒ làm mới cả danh mục tên của policy
  const refresh = () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: queryKeys.tenant(tenantId, "resources") }),
      queryClient.invalidateQueries({ queryKey: queryKeys.tenant(tenantId, "policies", "names") }),
    ]);
  const stale = () => {
    setEditing(null);
    setDeleting(null);
    setNotice(t("network.resources.stale"));
    void refresh();
  };

  const remove = useMutation({
    mutationFn: (r: NetworkResource) =>
      call(api.DELETE("/tenants/{tenantId}/resources/{resourceId}", { params: { path: { tenantId, resourceId: r.id }, header: ifMatch(r.etag) } })),
    onSuccess: (_d, r) => {
      setDeleting(null);
      setNotice(t("network.resources.deleted", { name: r.name }));
      void refresh();
    },
    onError: (e) => {
      if (isStaleVersion(e)) stale();
    },
  });

  return (
    <Page
      title={t("nav.tenant.resources")}
      actions={
        canManage ? (
          <button
            type="button"
            className="btn-primary"
            disabled={readOnly}
            onClick={() => {
              setNotice(null);
              setEditing("new");
            }}
          >
            {t("network.resources.add")}
          </button>
        ) : null
      }
    >
      <p className="mb-3 text-sm text-muted">{t("network.resources.intro")}</p>
      {canManage && readOnly ? <p className="mb-3 text-sm text-muted">{t("ui.readOnlyActions")}</p> : null}
      {notice ? (
        <p role="status" className="mb-3 text-sm" data-testid="resources-notice">
          {notice}
        </p>
      ) : null}
      <QueryBlock query={list}>
        {(data) => (
          <>
            {data.items.length === 0 ? (
              <EmptyState>{t("network.resources.empty")}</EmptyState>
            ) : (
              <div className="relative overflow-x-auto">
                <table className="data-table" data-testid="resources-table">
                  <caption className="sr-only">{t("nav.tenant.resources")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{t("network.resources.col.name")}</th>
                      <th scope="col">{t("network.resources.col.kind")}</th>
                      <th scope="col">{t("network.resources.col.address")}</th>
                      <th scope="col">{t("network.resources.col.ports")}</th>
                      <th scope="col">{t("network.resources.col.protocol")}</th>
                      <th scope="col">{t("network.resources.col.tags")}</th>
                      <th scope="col">{t("network.resources.col.owner")}</th>
                      <th scope="col">{t("network.resources.col.updatedAt")}</th>
                      {canManage ? <th scope="col">{t("network.resources.col.actions")}</th> : null}
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((r) => (
                      <tr key={r.id} data-testid="resource-row">
                        <td>
                          <span className="font-mono font-medium">{r.name}</span>
                          {r.description ? <div className="text-xs text-muted">{r.description}</div> : null}
                        </td>
                        <td>{t(`network.resources.kinds.${r.kind}`)}</td>
                        <td className="font-mono text-xs">{r.address}</td>
                        <td className="font-mono text-xs">{r.ports.length > 0 ? r.ports.join(", ") : <span className="font-sans text-muted">{t("network.resources.allPorts")}</span>}</td>
                        <td>{t(`network.resources.protocols.${r.protocol}`)}</td>
                        <td>
                          <TagList tags={r.tags} />
                        </td>
                        <td>{groupName(r.owner_group_id) ?? <span className="text-muted">{t("common.none")}</span>}</td>
                        <td>
                          <Timestamp iso={r.updated_at} relative={false} />
                        </td>
                        {canManage ? (
                          <td>
                            <div className="flex flex-wrap gap-1">
                              <button
                                type="button"
                                className="btn-secondary"
                                disabled={readOnly}
                                aria-label={t("network.resources.editFor", { name: r.name })}
                                onClick={() => {
                                  setNotice(null);
                                  setEditing(r);
                                }}
                              >
                                {t("network.resources.edit")}
                              </button>
                              <button
                                type="button"
                                className="btn-secondary"
                                disabled={readOnly}
                                aria-label={t("network.resources.deleteFor", { name: r.name })}
                                onClick={() => {
                                  setNotice(null);
                                  remove.reset();
                                  setDeleting(r);
                                }}
                              >
                                {t("network.resources.delete")}
                              </button>
                            </div>
                          </td>
                        ) : null}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <Pager pager={pager} nextCursor={data.next_cursor} label={t("network.resources.pagination")} />
          </>
        )}
      </QueryBlock>
      {editing !== null ? (
        <ResourceDialog
          key={editing === "new" ? "new" : editing.id}
          resource={editing === "new" ? null : editing}
          groups={canGroups ? (groups.data?.items ?? []) : null}
          onClose={() => {
            setEditing(null);
          }}
          onSaved={(r, created) => {
            setEditing(null);
            setNotice(t(created ? "network.resources.created" : "network.resources.updated", { name: r.name }));
            void refresh();
          }}
          onStale={stale}
        />
      ) : null}
      <ConfirmDialog
        isOpen={deleting !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDeleting(null);
            remove.reset();
          }
        }}
        title={t("network.resources.deleteTitle", { name: deleting?.name ?? "" })}
        description={<p>{t("network.resources.deleteDesc")}</p>}
        confirmLabel={t("network.resources.delete")}
        destructive
        pending={remove.isPending}
        error={remove.error ?? undefined}
        onConfirm={() => {
          if (deleting) remove.mutate(deleting);
        }}
      />
    </Page>
  );
}

interface FormState {
  name: string;
  kind: Kind;
  address: string;
  ports: string;
  protocol: Protocol;
  tags: readonly string[];
  owner: string;
  description: string;
}

function initial(r: NetworkResource | null): FormState {
  return {
    name: r?.name ?? "",
    kind: r?.kind ?? "host",
    address: r?.address ?? "",
    ports: r?.ports.join(", ") ?? "",
    protocol: r?.protocol ?? "any",
    tags: r?.tags ?? [],
    owner: r?.owner_group_id ?? "",
    description: r?.description ?? "",
  };
}

const sameList = (a: readonly string[], b: readonly string[]) => [...a].sort().join("\n") === [...b].sort().join("\n");

/** PATCH chỉ gồm các trường đã đổi (spec: trường không gửi giữ nguyên; chuỗi rỗng gỡ nhóm/xóa mô tả). */
export function resourcePatch(r: NetworkResource, f: FormState, opts: { tags: boolean; groups: boolean }): ResourceUpdate {
  const p: ResourceUpdate = {};
  if (f.name.trim() !== r.name) p.name = f.name.trim();
  if (f.kind !== r.kind) p.kind = f.kind;
  if (f.address.trim() !== r.address) p.address = f.address.trim();
  const ports = parsePorts(f.ports);
  if (ports.join(",") !== r.ports.join(",")) p.ports = ports;
  if (f.protocol !== r.protocol) p.protocol = f.protocol;
  if (opts.tags && !sameList(f.tags, r.tags)) p.tags = [...f.tags];
  if (opts.groups && f.owner !== (r.owner_group_id ?? "")) p.owner_group_id = f.owner;
  if (f.description.trim() !== (r.description ?? "")) p.description = f.description.trim();
  return p;
}

function ResourceDialog({
  resource,
  groups,
  onClose,
  onSaved,
  onStale,
}: {
  resource: NetworkResource | null;
  /** null ⇒ không có quyền đọc nhóm: ô nhóm sở hữu ẩn, không gửi */
  groups: readonly components["schemas"]["Group"][] | null;
  onClose: () => void;
  onSaved: (r: NetworkResource, created: boolean) => void;
  onStale: () => void;
}) {
  const { t } = useTranslation();
  const { tenantId, role } = useTenant();
  const id = useId();
  const [f, setF] = useState<FormState>(() => initial(resource));
  const set = (patch: Partial<FormState>) => {
    setF((prev) => ({ ...prev, ...patch }));
  };
  const canTags = can(role, "tenant.tag:read");
  const catalog = useQuery({
    queryKey: queryKeys.tenant(tenantId, "tags", "options"),
    queryFn: () => call(api.GET("/tenants/{tenantId}/tags", { params: { path: { tenantId }, query: { limit: OPTIONS_LIMIT } } })),
    enabled: canTags,
    staleTime: 60_000,
  });
  // tag đang gắn mà không còn trong danh mục vẫn hiện để có thể bỏ chọn
  const tagOptions = [...new Set([...(catalog.data?.items.map((x) => x.name) ?? []), ...f.tags])];

  const create = useIdempotentMutation({
    mutationFn: (body: ResourceCreate, key: string) =>
      call(api.POST("/tenants/{tenantId}/resources", { params: { path: { tenantId }, header: { "Idempotency-Key": key } }, body })),
    onSuccess: (r) => {
      onSaved(r, true);
    },
  });
  const update = useMutation({
    mutationFn: ({ r, body }: { r: NetworkResource; body: ResourceUpdate }) =>
      call(api.PATCH("/tenants/{tenantId}/resources/{resourceId}", { params: { path: { tenantId, resourceId: r.id }, header: ifMatch(r.etag) }, body })),
    onSuccess: (r) => {
      onSaved(r, false);
    },
    onError: (e) => {
      if (isStaleVersion(e)) onStale();
    },
  });
  const m = resource ? update : create;
  const patch = resource ? resourcePatch(resource, f, { tags: canTags, groups: groups !== null }) : null;
  const unchanged = patch !== null && Object.keys(patch).length === 0;
  const fieldError = useFieldErrors(m.error);
  const shown = formLevelError(m.error, FORM_FIELDS);

  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    if (m.isPending) return;
    if (resource && patch) {
      if (!unchanged) update.mutate({ r: resource, body: patch });
      return;
    }
    const ports = parsePorts(f.ports);
    const body: ResourceCreate = { name: f.name.trim(), kind: f.kind, address: f.address.trim(), protocol: f.protocol };
    if (ports.length > 0) body.ports = ports;
    if (canTags && f.tags.length > 0) body.tags = [...f.tags];
    if (groups !== null && f.owner !== "") body.owner_group_id = f.owner;
    if (f.description.trim() !== "") body.description = f.description.trim();
    create.mutate(body);
  };

  const text = (field: (typeof FORM_FIELDS)[number], label: string, value: string, onChange: (v: string) => void, hint?: string, mono = true) => {
    const err = fieldError(field);
    const fid = `${id}-${field}`;
    return (
      <div>
        <label htmlFor={fid} className="label">
          {label}
        </label>
        <input
          id={fid}
          className={mono ? "input font-mono" : "input"}
          value={value}
          spellCheck={false}
          autoComplete="off"
          {...invalidProps(fid, err, hint ? `${fid}-hint` : undefined)}
          onChange={(e) => {
            onChange(e.target.value);
          }}
        />
        {hint ? (
          <p id={`${fid}-hint`} className="hint">
            {hint}
          </p>
        ) : null}
        <FieldError id={fid} message={err} />
      </div>
    );
  };
  const kindErr = fieldError("kind");
  const protocolErr = fieldError("protocol");
  const tagsErr = fieldError("tags");
  const ownerErr = fieldError("owner_group_id");
  const descErr = fieldError("description");

  return (
    <ModalDialog
      isOpen
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title={resource ? t("network.resources.editTitle", { name: resource.name }) : t("network.resources.addTitle")}
      busy={m.isPending}
    >
      <form className="space-y-3" onSubmit={submit} data-testid="resource-form">
        {text("name", t("network.resources.col.name"), f.name, (v) => set({ name: v.toLowerCase() }), t("network.resources.nameHint"))}
        <div>
          <label htmlFor={`${id}-kind`} className="label">
            {t("network.resources.col.kind")}
          </label>
          <select
            id={`${id}-kind`}
            className="select"
            value={f.kind}
            {...invalidProps(`${id}-kind`, kindErr)}
            onChange={(e) => {
              set({ kind: RESOURCE_KINDS.find((k) => k === e.target.value) ?? "host" });
            }}
          >
            {RESOURCE_KINDS.map((k) => (
              <option key={k} value={k}>
                {t(`network.resources.kinds.${k}`)}
              </option>
            ))}
          </select>
          <FieldError id={`${id}-kind`} message={kindErr} />
        </div>
        {text(
          "address",
          t("network.resources.col.address"),
          f.address,
          (v) => set({ address: v }),
          f.kind === "subnet" ? t("network.resources.addressHintSubnet") : t("network.resources.addressHintHost"),
        )}
        {text("ports", t("network.resources.col.ports"), f.ports, (v) => set({ ports: v }), t("network.resources.portsHint"))}
        <div>
          <label htmlFor={`${id}-protocol`} className="label">
            {t("network.resources.col.protocol")}
          </label>
          <select
            id={`${id}-protocol`}
            className="select"
            value={f.protocol}
            {...invalidProps(`${id}-protocol`, protocolErr)}
            onChange={(e) => {
              set({ protocol: RESOURCE_PROTOCOLS.find((p) => p === e.target.value) ?? "any" });
            }}
          >
            {RESOURCE_PROTOCOLS.map((p) => (
              <option key={p} value={p}>
                {t(`network.resources.protocols.${p}`)}
              </option>
            ))}
          </select>
          <FieldError id={`${id}-protocol`} message={protocolErr} />
        </div>
        {canTags ? (
          <fieldset aria-describedby={tagsErr ? `${id}-tags-err` : undefined}>
            <legend className="label">{t("network.resources.col.tags")}</legend>
            {catalog.isError ? <ProblemAlert error={catalog.error} /> : null}
            {tagOptions.length === 0 && catalog.isSuccess ? <p className="hint">{t("network.resources.noTags")}</p> : null}
            <ul className="flex flex-wrap gap-x-4 gap-y-1">
              {tagOptions.map((tag) => (
                <li key={tag} className="flex items-center gap-1">
                  <input
                    id={`${id}-tag-${tag}`}
                    type="checkbox"
                    checked={f.tags.includes(tag)}
                    onChange={(e) => {
                      set({ tags: e.target.checked ? [...f.tags, tag] : f.tags.filter((x) => x !== tag) });
                    }}
                  />
                  <label htmlFor={`${id}-tag-${tag}`} className="font-mono text-sm">
                    {tag}
                  </label>
                </li>
              ))}
            </ul>
            <FieldError id={`${id}-tags`} message={tagsErr} />
          </fieldset>
        ) : null}
        {groups !== null ? (
          <div>
            <label htmlFor={`${id}-owner`} className="label">
              {t("network.resources.col.owner")}
            </label>
            <select
              id={`${id}-owner`}
              className="select"
              value={f.owner}
              {...invalidProps(`${id}-owner`, ownerErr)}
              onChange={(e) => {
                set({ owner: e.target.value });
              }}
            >
              <option value="">{t("network.resources.noOwner")}</option>
              {/* nhóm đang gán mà không có trong trang đầu của danh sách: vẫn giữ được */}
              {f.owner !== "" && !groups.some((g) => g.id === f.owner) ? <option value={f.owner}>{f.owner}</option> : null}
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
            <FieldError id={`${id}-owner`} message={ownerErr} />
          </div>
        ) : null}
        <div>
          <label htmlFor={`${id}-description`} className="label">
            {t("network.resources.description")}
          </label>
          <textarea
            id={`${id}-description`}
            className="input"
            rows={2}
            value={f.description}
            {...invalidProps(`${id}-description`, descErr)}
            onChange={(e) => {
              set({ description: e.target.value });
            }}
          />
          <FieldError id={`${id}-description`} message={descErr} />
        </div>
        <p className="hint">{t("network.resources.policyNote")}</p>
        {shown && !isStaleVersion(shown) ? <ProblemAlert error={shown} /> : null}
        <div className="flex justify-end gap-2 pt-2">
          <button type="button" className="btn-secondary" disabled={m.isPending} onClick={onClose}>
            {t("ui.cancel")}
          </button>
          <button
            type="submit"
            className="btn-primary"
            disabled={m.isPending || unchanged || f.name.trim() === "" || f.address.trim() === ""}
          >
            {m.isPending ? t("common.working") : resource ? t("network.resources.save") : t("network.resources.create")}
          </button>
        </div>
      </form>
    </ModalDialog>
  );
}
