// Thiết lập của tenant (P4-T13 — UI của API P4-T03a; §8.6 tenant.settings:*, §13.3 TenantSettings):
//   - GET /settings (+ ETag) cho mọi role đọc được;
//   - thiết lập thường (thông báo, trần hạn pre-auth key) — PATCH /settings (Owner, Admin), If-Match;
//   - thiết lập bảo mật (4-eyes policy/route, group sensitive, self-enroll, web-auth, duyệt enrollment, node_expiry,
//     identity_mode) — PUT /settings/security (Owner, step-up), If-Match. Thay đổi NỚI LỎNG một kiểm soát hai người ⇒
//     202 + yêu cầu phê duyệt trong tenant: UI nói rõ "chưa có hiệu lực", dẫn tới trang phê duyệt (Owner/Admin khác).
// 412 (người khác vừa sửa) ⇒ tải lại bản mới, người dùng quyết định lại (api/etag). `dns` chỉ xem (P4-T12).
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type SyntheticEvent } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { api, call, callWithResponse } from "../../api/client";
import { callWithETag, ifMatch, isStaleVersion } from "../../api/etag";
import { queryKeys } from "../../api/queryClient";
import type { components } from "../../api/schema";
import { can } from "../../auth/permissions";
import { Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { Field, QueryBlock } from "../../ui/Data";
import { StatusBadge } from "../../ui/Status";
import { useTenant } from "../TenantScope";

type TenantSettings = components["schemas"]["TenantSettings"];
type SecuritySettings = components["schemas"]["TenantSecuritySettings"];
type ApprovalRequest = components["schemas"]["ApprovalRequest"];

const NODE_EXPIRY_RE = /^(0|[1-9][0-9]{0,3}[dh])$/;
const TTL_RE = /^([1-9][0-9]{0,6}[mh])?$/;

export function settingsKey(tenantId: string) {
  return queryKeys.tenant(tenantId, "settings");
}

export function SettingsPage() {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  // lưu xong ⇒ ETag mới ⇒ hai form dựng lại từ bản đã lưu: thông báo "đã lưu" nằm ngoài form
  const [saved, setSaved] = useState(false);
  const q = useQuery({
    queryKey: settingsKey(tenantId),
    queryFn: () => callWithETag(api.GET("/tenants/{tenantId}/settings", { params: { path: { tenantId } } })),
  });
  return (
    <Page title={t("nav.tenant.settings")}>
      <p className="mb-4 text-sm text-muted">{t("settings.intro")}</p>
      <QueryBlock query={q}>
        {(v) => (
          <div className="space-y-6">
            {saved ? <p role="status">{t("settings.saved")}</p> : null}
            <GeneralSection key={`g${v.etag ?? ""}`} settings={v.data.settings} etag={v.etag} onSaved={setSaved} />
            <SecuritySection key={`s${v.etag ?? ""}`} settings={v.data.settings} etag={v.etag} onSaved={setSaved} />
          </div>
        )}
      </QueryBlock>
    </Page>
  );
}

function useStaleReload() {
  const { tenantId } = useTenant();
  const queryClient = useQueryClient();
  return (error: unknown) => {
    if (isStaleVersion(error)) void queryClient.invalidateQueries({ queryKey: settingsKey(tenantId) });
  };
}

function GeneralSection({ settings: s, etag, onSaved }: { settings: TenantSettings; etag: string | null; onSaved: (saved: boolean) => void }) {
  const { t } = useTranslation();
  const { tenantId, role, readOnly } = useTenant();
  const queryClient = useQueryClient();
  const reloadIfStale = useStaleReload();
  const editable = can(role, "tenant.settings:update") && !readOnly;
  const [newDevice, setNewDevice] = useState(s.notifications.new_device);
  const [policyApplied, setPolicyApplied] = useState(s.notifications.policy_applied);
  const [ttl, setTtl] = useState(s.enrollment.preauth_key_ttl_max ?? "");
  const ttlBad = !TTL_RE.test(ttl.trim());
  const save = useMutation({
    mutationFn: () =>
      callWithETag(
        api.PATCH("/tenants/{tenantId}/settings", {
          params: { path: { tenantId }, header: ifMatch(etag) },
          body: {
            notifications: { new_device: newDevice, policy_applied: policyApplied },
            enrollment: { preauth_key_ttl_max: ttl.trim() },
          },
        }),
      ),
    onMutate: () => {
      onSaved(false);
    },
    onSuccess: (v) => {
      onSaved(true);
      queryClient.setQueryData(settingsKey(tenantId), v);
    },
    onError: reloadIfStale,
  });
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    if (!ttlBad) save.mutate();
  };
  return (
    <section aria-labelledby="settings-general" className="card space-y-3">
      <h2 id="settings-general" className="text-lg font-semibold">
        {t("settings.general")}
      </h2>
      <form className="space-y-3" onSubmit={submit}>
        <fieldset disabled={!editable || save.isPending} className="space-y-2">
          <legend className="text-sm font-semibold">{t("settings.notifications")}</legend>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={newDevice} onChange={(e) => { setNewDevice(e.target.checked); }} />
            {t("settings.newDevice")}
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={policyApplied} onChange={(e) => { setPolicyApplied(e.target.checked); }} />
            {t("settings.policyApplied")}
          </label>
          <div>
            <label htmlFor="settings-ttl" className="label">
              {t("settings.preauthTtl")}
            </label>
            <input id="settings-ttl" className="input font-mono" value={ttl} placeholder={t("settings.preauthTtlPlaceholder")} aria-invalid={ttlBad} onChange={(e) => { setTtl(e.target.value); }} />
            <p className="hint">{t("settings.preauthTtlHint")}</p>
          </div>
        </fieldset>
        {save.isError ? <ProblemAlert error={save.error} /> : null}
        {editable ? (
          <button type="submit" className="btn-primary" disabled={ttlBad || save.isPending}>
            {save.isPending ? t("common.working") : t("settings.save")}
          </button>
        ) : (
          <p className="text-sm text-muted">{t("settings.readOnlyNote")}</p>
        )}
      </form>
    </section>
  );
}

function SecuritySection({ settings: s, etag, onSaved }: { settings: TenantSettings; etag: string | null; onSaved: (saved: boolean) => void }) {
  const { t } = useTranslation();
  const { tenantId, role, readOnly } = useTenant();
  const queryClient = useQueryClient();
  const reloadIfStale = useStaleReload();
  const editable = can(role, "tenant.settings:update_security") && !readOnly;
  const [form, setForm] = useState<SecuritySettings>({
    enrollment: {
      identity_mode: s.enrollment.identity_mode,
      web_auth_enabled: s.enrollment.web_auth_enabled,
      self_enroll: s.enrollment.self_enroll,
      requires_approval: s.enrollment.requires_approval,
    },
    node_expiry: s.node_expiry,
    policy: { four_eyes: s.policy.four_eyes, sensitive_groups: [...s.policy.sensitive_groups] },
    routes: { four_eyes: s.routes.four_eyes },
  });
  const [approval, setApproval] = useState<ApprovalRequest | null>(null);
  const groups = useQuery({
    queryKey: queryKeys.tenant(tenantId, "groups", "all"),
    queryFn: () => call(api.GET("/tenants/{tenantId}/groups", { params: { path: { tenantId }, query: { limit: 200 } } })),
    enabled: can(role, "tenant.group:read"),
  });
  const expiry = form.node_expiry ?? "";
  const expiryBad = expiry !== "" && !NODE_EXPIRY_RE.test(expiry);
  const save = useMutation({
    mutationFn: async () => {
      const body: SecuritySettings = { ...form, node_expiry: expiry === "" ? null : expiry };
      const r = await callWithResponse(
        api.PUT("/tenants/{tenantId}/settings/security", { params: { path: { tenantId }, header: ifMatch(etag) }, body }),
      );
      return r.response.status === 202
        ? { kind: "approval" as const, approval: r.data as ApprovalRequest }
        : { kind: "saved" as const, etag: r.response.headers.get("ETag"), data: r.data as components["schemas"]["TenantSettingsView"] };
    },
    onMutate: () => {
      onSaved(false);
    },
    onSuccess: async (res) => {
      if (res.kind === "approval") {
        setApproval(res.approval);
        await queryClient.invalidateQueries({ queryKey: queryKeys.tenant(tenantId, "approvals") });
        return;
      }
      onSaved(true);
      queryClient.setQueryData(settingsKey(tenantId), { data: res.data, etag: res.etag });
    },
    onError: reloadIfStale,
  });
  const set = (fn: (f: SecuritySettings) => SecuritySettings) => {
    setForm((f) => fn(structuredClone(f)));
  };
  const toggleGroup = (id: string, on: boolean) => {
    set((f) => {
      const ids = new Set(f.policy.sensitive_groups);
      if (on) ids.add(id);
      else ids.delete(id);
      f.policy.sensitive_groups = [...ids].sort();
      return f;
    });
  };
  const groupName = (id: string) => groups.data?.items.find((g) => g.id === id)?.name ?? id;

  return (
    <section aria-labelledby="settings-security" className="card space-y-3">
      <h2 id="settings-security" className="text-lg font-semibold">
        {t("settings.security")}
      </h2>
      <p className="text-sm text-muted">{t("settings.securityIntro")}</p>
      {approval ? (
        <div role="status" className="banner banner-warn" data-testid="security-approval">
          <p className="font-semibold">{t("settings.approvalCreated")}</p>
          <p className="text-sm">{t("settings.approvalNotInEffect")}</p>
          <p className="mt-1 flex flex-wrap items-center gap-2 text-sm">
            <StatusBadge status={approval.status}>{t(`status.approval.${approval.status}`)}</StatusBadge>
            <Link to={`/t/${tenantId}/approvals/${approval.id}`} className="link">
              {t("settings.openApproval")}
            </Link>
          </p>
        </div>
      ) : null}
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          if (!expiryBad) save.mutate();
        }}
      >
        <fieldset disabled={!editable || save.isPending} className="space-y-2">
          <legend className="text-sm font-semibold">{t("settings.twoPerson")}</legend>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={form.policy.four_eyes} onChange={(e) => { const v = e.target.checked; set((f) => ({ ...f, policy: { ...f.policy, four_eyes: v } })); }} />
            {t("settings.policyFourEyes")}
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={form.routes.four_eyes} onChange={(e) => { const v = e.target.checked; set((f) => ({ ...f, routes: { four_eyes: v } })); }} />
            {t("settings.routesFourEyes")}
          </label>
          <div>
            <p className="label">{t("settings.sensitiveGroups")}</p>
            {groups.data ? (
              groups.data.items.length === 0 ? (
                <p className="hint">{t("settings.noGroups")}</p>
              ) : (
                <ul className="space-y-1">
                  {groups.data.items.map((g) => (
                    <li key={g.id}>
                      <label className="flex items-center gap-2">
                        <input type="checkbox" checked={form.policy.sensitive_groups.includes(g.id)} onChange={(e) => { toggleGroup(g.id, e.target.checked); }} />
                        {g.name}
                      </label>
                    </li>
                  ))}
                </ul>
              )
            ) : (
              <ul className="text-sm">
                {form.policy.sensitive_groups.map((id) => (
                  <li key={id} className="font-mono text-xs">
                    {groupName(id)}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </fieldset>
        <fieldset disabled={!editable || save.isPending} className="space-y-2">
          <legend className="text-sm font-semibold">{t("settings.enrollment")}</legend>
          <div>
            <label htmlFor="settings-identity-mode" className="label">
              {t("settings.identityMode")}
            </label>
            <select id="settings-identity-mode" className="select" value={form.enrollment.identity_mode} onChange={(e) => { const v = e.target.value === "headscale_oidc" ? "headscale_oidc" : "portal"; set((f) => ({ ...f, enrollment: { ...f.enrollment, identity_mode: v } })); }}>
              <option value="portal">{t("settings.identityModes.portal")}</option>
              <option value="headscale_oidc">{t("settings.identityModes.headscale_oidc")}</option>
            </select>
          </div>
          {(["web_auth_enabled", "self_enroll", "requires_approval"] as const).map((k) => (
            <label key={k} className="flex items-center gap-2">
              <input type="checkbox" checked={form.enrollment[k]} onChange={(e) => { const v = e.target.checked; set((f) => ({ ...f, enrollment: { ...f.enrollment, [k]: v } })); }} />
              {t(`settings.${k}`)}
            </label>
          ))}
          <div>
            <label htmlFor="settings-node-expiry" className="label">
              {t("settings.nodeExpiry")}
            </label>
            <input id="settings-node-expiry" className="input font-mono" value={expiry} placeholder={t("settings.nodeExpiryPlaceholder")} aria-invalid={expiryBad} onChange={(e) => { const v = e.target.value.trim(); set((f) => ({ ...f, node_expiry: v === "" ? null : v })); }} />
            <p className="hint">{t("settings.nodeExpiryHint")}</p>
          </div>
        </fieldset>
        {save.isError ? <ProblemAlert error={save.error} /> : null}
        {editable ? (
          <>
            <p className="hint">{t("settings.stepUpNote")}</p>
            <button type="submit" className="btn-primary" disabled={expiryBad || save.isPending}>
              {save.isPending ? t("common.working") : t("settings.saveSecurity")}
            </button>
          </>
        ) : (
          <p className="text-sm text-muted">{t("settings.securityReadOnly")}</p>
        )}
      </form>
      <dl className="grid gap-3 border-t border-line pt-3 sm:grid-cols-2">
        <Field label={t("settings.dns")}>
          <span className="text-sm text-muted">{t("settings.dnsNote")}</span>
        </Field>
      </dl>
    </section>
  );
}
