// Template least-privilege của editor (P5-T01, §7.2). Danh mục là DỮ LIỆU của nền tảng (GET /policies/templates: id,
// version, tham số, ghi chú); server render tất định một template thành đoạn `PolicySource` có kiểu (POST
// /policies/templates/render — kiểm tham chiếu thuộc tenant, cổng `*` bị từ chối) và trả kèm báo cáo của riêng đoạn đó.
// Đoạn được THÊM vào bản nháp đang soạn (`append`) hoặc THAY nó (`replace` — deny-all); không lưu gì: người dùng xem lại
// rồi lưu (PATCH) như mọi lần sửa. Ghi chú V-24 nói rõ tests sinh tự động không khẳng định được quyền từ via/self.
import { useMutation, useQuery } from "@tanstack/react-query";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, call } from "../../api/client";
import { queryKeys } from "../../api/queryClient";
import { can } from "../../auth/permissions";
import { ProblemAlert } from "../../components/ProblemAlert";
import { useTenant } from "../TenantScope";
import type { Catalog } from "./api";
import { FindingList } from "./FindingList";
import { IP_PROTO_RE, splitTokens, type PolicySource, type PrincipalName } from "./model";
import type { components } from "../../api/schema";

type Template = components["schemas"]["PolicyTemplate"];
type TemplateParams = components["schemas"]["PolicyTemplateParams"];
type TemplateRender = components["schemas"]["PolicyTemplateRender"];
type RefParam = "group_id" | "tag_id" | "resource_id";

/** Một mục cổng hợp lệ cho template: đúng cú pháp `ip` và không mở mọi cổng (`*`, `tcp:*`). */
export function templatePortProblems(text: string): string[] {
  return splitTokens(text).filter((p) => !IP_PROTO_RE.test(p) || p === "*" || p.endsWith(":*"));
}

/** Nội dung mới của bản nháp sau khi áp một đoạn template. */
export function mergeTemplate(source: PolicySource, r: Pick<TemplateRender, "mode" | "source">): PolicySource {
  if (r.mode === "replace") return { grants: [...r.source.grants], ssh: [...(r.source.ssh ?? [])] };
  return { ...source, grants: [...source.grants, ...r.source.grants], ssh: [...(source.ssh ?? []), ...(r.source.ssh ?? [])] };
}

export interface TemplatePanelProps {
  source: PolicySource;
  catalog: Catalog | undefined;
  /** nội dung mới + tên của các principal mà đoạn template tham chiếu (để hiển thị) */
  onApply: (next: PolicySource, names: PrincipalName[]) => void;
}

export function TemplatePanel({ source, catalog, onApply }: TemplatePanelProps) {
  const { t } = useTranslation();
  const { tenantId, role } = useTenant();
  const id = useId();
  const list = useQuery({
    queryKey: queryKeys.tenant(tenantId, "policies", "templates"),
    queryFn: () => call(api.GET("/tenants/{tenantId}/policies/templates", { params: { path: { tenantId } } })),
    staleTime: Infinity,
  });
  const [chosen, setChosen] = useState("");
  const [refs, setRefs] = useState<Partial<Record<RefParam, string>>>({});
  const [ports, setPorts] = useState("");
  const [done, setDone] = useState<TemplateRender | null>(null);
  const tmpl: Template | undefined = list.data?.items.find((x) => x.id === chosen);
  const needsResources = tmpl?.params.some((p) => p.kind === "resource") ?? false;
  const resources = useQuery({
    queryKey: queryKeys.tenant(tenantId, "resources", "template-choices"),
    queryFn: () => call(api.GET("/tenants/{tenantId}/resources", { params: { path: { tenantId }, query: { limit: 200 } } })),
    enabled: needsResources && can(role, "tenant.resource:read"),
    staleTime: 30_000,
  });
  const render = useMutation({
    mutationFn: (body: { template_id: string; version: number; params: TemplateParams }) =>
      call(api.POST("/tenants/{tenantId}/policies/templates/render", { params: { path: { tenantId } }, body })),
    onSuccess: (r) => {
      const names: PrincipalName[] = [];
      if (refs.group_id) names.push({ type: "group", ref: refs.group_id, name: `group:${catalog?.book.groups.get(refs.group_id) ?? refs.group_id}` });
      if (refs.tag_id) names.push({ type: "tag", ref: refs.tag_id, name: catalog?.book.tags.get(refs.tag_id) ?? refs.tag_id });
      if (refs.resource_id) {
        const res = resources.data?.items.find((x) => x.id === refs.resource_id);
        names.push({ type: "resource", ref: refs.resource_id, name: res?.name ?? refs.resource_id });
      }
      onApply(mergeTemplate(source, r), names);
      setDone(r);
    },
  });

  const choose = (next: string) => {
    setChosen(next);
    setRefs({});
    setDone(null);
    render.reset();
    const tp = list.data?.items.find((x) => x.id === next);
    setPorts((tp?.params.find((p) => p.kind === "ports")?.default ?? []).join(", "));
  };

  const badPorts = templatePortProblems(ports);
  const missing = (tmpl?.params ?? []).filter((p) => p.kind !== "ports" && !refs[p.name as RefParam]).map((p) => p.name);
  const portsEmpty = (tmpl?.params.some((p) => p.kind === "ports") ?? false) && splitTokens(ports).length === 0;
  const ready = tmpl !== undefined && missing.length === 0 && badPorts.length === 0 && !portsEmpty;

  const submit = () => {
    if (!tmpl || !ready) return;
    const params: TemplateParams = {};
    for (const p of tmpl.params) {
      if (p.kind === "ports") params.ports = splitTokens(ports);
      else params[p.name as RefParam] = refs[p.name as RefParam];
    }
    setDone(null);
    render.mutate({ template_id: tmpl.id, version: tmpl.version, params });
  };

  const choices = (kind: string): { id: string; label: string }[] => {
    if (kind === "group") return (catalog?.groups ?? []).map((g) => ({ id: g.id, label: g.name }));
    if (kind === "tag") return (catalog?.tags ?? []).map((g) => ({ id: g.id, label: g.name }));
    return (resources.data?.items ?? []).map((r) => ({ id: r.id, label: `${r.name} (${r.address})` }));
  };
  const name = (x: Template) => t(`policies.templates.items.${x.id}.name`);

  return (
    <section className="card space-y-3" aria-labelledby={`${id}-title`} data-testid="policy-templates">
      <h3 id={`${id}-title`} className="font-semibold">
        {t("policies.templates.title")}
      </h3>
      <p className="hint">{t("policies.templates.intro")}</p>
      {list.isError ? <ProblemAlert error={list.error} /> : null}
      {list.isPending ? <p className="text-sm text-muted">{t("policies.templates.loading")}</p> : null}
      {list.data ? (
        <div>
          <label htmlFor={`${id}-tmpl`} className="label">
            {t("policies.templates.choose")}
          </label>
          <select
            id={`${id}-tmpl`}
            className="select"
            value={chosen}
            onChange={(e) => {
              choose(e.target.value);
            }}
          >
            <option value="">{t("policies.editor.choose")}</option>
            {list.data.items.map((x) => (
              <option key={x.id} value={x.id}>
                {`${name(x)} (${t("policies.templates.versionN", { version: x.version })})`}
              </option>
            ))}
          </select>
        </div>
      ) : null}
      {tmpl ? (
        <div className="space-y-3" data-testid="template-form" data-template={tmpl.id}>
          <p className="text-sm">{t(`policies.templates.items.${tmpl.id}.description`)}</p>
          {tmpl.notes.length > 0 ? (
            <ul className="list-disc space-y-1 pl-5 text-sm" aria-label={t("policies.templates.title")} data-testid="template-notes">
              {tmpl.notes.map((n) => (
                <li key={n} data-note={n} className={n.startsWith("tests_") ? "text-warn" : undefined}>
                  {t(`policies.templates.notes.${n}`)}
                </li>
              ))}
            </ul>
          ) : null}
          {tmpl.params.map((p) =>
            p.kind === "ports" ? (
              <div key={p.name}>
                <label htmlFor={`${id}-ports`} className="label">
                  {t("policies.templates.params.ports")}
                </label>
                <input
                  id={`${id}-ports`}
                  className="input font-mono"
                  value={ports}
                  autoComplete="off"
                  spellCheck={false}
                  aria-describedby={`${id}-ports-hint`}
                  aria-invalid={badPorts.length > 0 || portsEmpty}
                  onChange={(e) => {
                    setPorts(e.target.value);
                  }}
                />
                <p id={`${id}-ports-hint`} className="hint">
                  {t("policies.templates.params.portsHint")}
                </p>
                {badPorts.length > 0 ? (
                  <p className="text-sm text-danger" data-testid="template-ports-invalid">
                    {t("policies.templates.params.portsInvalid", { value: badPorts.join(", ") })}
                  </p>
                ) : null}
              </div>
            ) : (
              <div key={p.name}>
                <label htmlFor={`${id}-${p.name}`} className="label">
                  {t(`policies.templates.params.${p.name}`)}
                </label>
                <select
                  id={`${id}-${p.name}`}
                  className="select"
                  value={refs[p.name as RefParam] ?? ""}
                  onChange={(e) => {
                    setRefs((r) => ({ ...r, [p.name]: e.target.value || undefined }));
                  }}
                >
                  <option value="">{t("policies.editor.choose")}</option>
                  {choices(p.kind).map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.label}
                    </option>
                  ))}
                </select>
                {p.kind === "resource" && !resources.isPending && choices("resource").length === 0 ? (
                  <p className="hint">{t("policies.templates.params.noResources")}</p>
                ) : null}
              </div>
            ),
          )}
          <button type="button" className={tmpl.mode === "replace" ? "btn-danger" : "btn-primary"} disabled={!ready || render.isPending} onClick={submit}>
            {render.isPending ? t("common.working") : t(tmpl.mode === "replace" ? "policies.templates.replace" : "policies.templates.apply")}
          </button>
        </div>
      ) : null}
      {render.isError ? <ProblemAlert error={render.error} /> : null}
      {done ? (
        <div className="space-y-2" data-testid="template-applied">
          <p role="status" className="text-sm">
            {t(done.mode === "replace" ? "policies.templates.replaced" : "policies.templates.applied", {
              count: done.source.grants.length,
              name: t(`policies.templates.items.${done.template_id}.name`),
              version: t("policies.templates.versionN", { version: done.version }),
            })}
          </p>
          <FindingList findings={[...done.report.errors, ...done.report.warnings, ...done.report.info]} label={t("policies.templates.reportTitle")} />
        </div>
      ) : null}
    </section>
  );
}
