// Routes (P4-T12, §12.3; T-08, PL-10): GET /tenants/{t}/routes — thiết bị router từ sổ thiết bị (mỗi thiết bị kèm
// `synced_at`; đồng bộ ngay = cơ chế sync của Devices), route quảng bá / đã duyệt / chờ duyệt (double opt-in: route chưa
// duyệt không được phân phối), exit node, cảnh báo (chồng lấn, router không tag, exit node). Duyệt: POST /routes/approve
// (`If-Match` = `routes_etag`, Idempotency-Key) — exit node chỉ qua hộp xác nhận rủi ro riêng và `confirm_exit_node`;
// gỡ duyệt: POST /routes/revoke (`If-Match`). 200 ⇒ cập nhật; 202 ⇒ tenant bật 4-eyes: đã tạo yêu cầu phê duyệt (chưa
// đổi gì — khung "chưa hiệu lực" với trạng thái sống của yêu cầu và link tới trang phê duyệt của tenant; thực thi xong ⇒
// tải lại routes); 412 ⇒ dữ liệu đã đổi ⇒ tải lại, người dùng chọn lại. Nút chỉ là UX — server quyết định (quyền, step-up, 4-eyes).
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { api, call, callWithResponse } from "../../api/client";
import { ifMatch, isStaleVersion } from "../../api/etag";
import { useIdempotentMutation } from "../../api/idempotency";
import { approvalFromLocation } from "../../api/jobs";
import { queryKeys } from "../../api/queryClient";
import type { components } from "../../api/schema";
import { can } from "../../auth/permissions";
import { Page } from "../../components/Page";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { EmptyState, QueryBlock } from "../../ui/Data";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { TagList } from "../devices/DeviceBits";
import { SyncControl } from "../devices/SyncControl";
import { useTenant } from "../TenantScope";
import { ApprovalCreated, type ApprovalRequest } from "./networkBits";

export type RouteDevice = components["schemas"]["RouteDevice"];
export type RouteWarning = components["schemas"]["RouteWarning"];
type RouteChange = components["schemas"]["RouteChange"];

/** Exit node = `0.0.0.0/0` + `::/0` (server coi một trong hai là cả hai). */
export const EXIT_PREFIXES: readonly string[] = ["0.0.0.0/0", "::/0"];
export const isExitPrefix = (p: string) => EXIT_PREFIXES.includes(p);

type ActionKind = "approve" | "exit" | "revoke";
type Action = { kind: ActionKind; deviceId: string } | null;

export function RoutesPage() {
  const { t } = useTranslation();
  const { tenantId, role, readOnly } = useTenant();
  const queryClient = useQueryClient();
  const routesKey = queryKeys.tenant(tenantId, "routes");
  const routes = useQuery({
    queryKey: routesKey,
    queryFn: () => call(api.GET("/tenants/{tenantId}/routes", { params: { path: { tenantId } } })),
  });
  const canApprove = can(role, "tenant.route:approve");
  const [action, setAction] = useState<Action>(null);
  const [done, setDone] = useState<string | null>(null);
  const [approval, setApproval] = useState<{ id: string; data: ApprovalRequest } | null>(null);
  const items = routes.data?.items ?? [];
  const nameOf = (id: string | undefined) => items.find((d) => d.device_id === id)?.given_name ?? id ?? "";
  const current = action ? items.find((d) => d.device_id === action.deviceId) : undefined;

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: routesKey });
    void queryClient.invalidateQueries({ queryKey: queryKeys.tenant(tenantId, "devices") });
  };

  return (
    <Page title={t("nav.tenant.routes")} actions={can(role, "tenant.device:sync") ? <SyncControl /> : null}>
      <p className="mb-2 text-sm text-muted">{t("network.routes.intro")}</p>
      {approval ? (
        <ApprovalCreated
          key={approval.id}
          approval={approval}
          onDismiss={() => {
            setApproval(null);
          }}
          onExecuted={refresh}
        />
      ) : null}
      {done ? (
        <p role="status" className="mb-3 text-sm" data-testid="routes-done">
          {done}
        </p>
      ) : null}
      {canApprove && readOnly ? <p className="mb-3 text-sm text-muted">{t("ui.readOnlyActions")}</p> : null}
      <QueryBlock query={routes}>
        {(data) =>
          data.items.length === 0 ? (
            <EmptyState>{t("network.routes.empty")}</EmptyState>
          ) : (
            <div className="overflow-x-auto">
              <table className="data-table" data-testid="routes-table">
                <caption className="sr-only">{t("nav.tenant.routes")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("network.routes.col.device")}</th>
                    <th scope="col">{t("network.routes.col.tags")}</th>
                    <th scope="col">{t("network.routes.col.online")}</th>
                    <th scope="col">{t("network.routes.col.advertised")}</th>
                    <th scope="col">{t("network.routes.col.approved")}</th>
                    <th scope="col">{t("network.routes.col.pending")}</th>
                    <th scope="col">{t("network.routes.col.exitNode")}</th>
                    <th scope="col">{t("network.routes.col.syncedAt")}</th>
                    <th scope="col">{t("network.routes.col.warnings")}</th>
                    {canApprove ? <th scope="col">{t("network.routes.col.actions")}</th> : null}
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((d) => (
                    <tr key={d.device_id} data-testid="route-row">
                      <td>
                        <Link to={`/t/${tenantId}/devices/${d.device_id}`} className="link font-medium">
                          {d.given_name}
                        </Link>
                        <div className="text-xs text-muted">{d.name}</div>
                      </td>
                      <td>
                        <TagList tags={d.tags} />
                      </td>
                      <td>
                        <StatusBadge tone={d.online ? "ok" : "neutral"}>{d.online ? t("devices.online") : t("devices.offline")}</StatusBadge>
                      </td>
                      <td>
                        <PrefixList prefixes={d.advertised_routes} />
                      </td>
                      <td>
                        <PrefixList prefixes={d.approved_routes} />
                      </td>
                      <td data-testid="pending-routes">
                        <PrefixList prefixes={d.pending_routes} tone="warn" />
                      </td>
                      <td>
                        <ExitNodeState device={d} />
                      </td>
                      <td>
                        <Timestamp iso={d.synced_at} />
                      </td>
                      <td>
                        <WarningList warnings={d.warnings} nameOf={nameOf} />
                      </td>
                      {canApprove ? (
                        <td>
                          <RowActions
                            device={d}
                            disabled={readOnly}
                            onAction={(kind) => {
                              setDone(null);
                              setAction({ kind, deviceId: d.device_id });
                            }}
                          />
                        </td>
                      ) : null}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        }
      </QueryBlock>
      {action && current ? (
        <RouteChangeDialog
          key={`${action.kind}:${action.deviceId}`}
          kind={action.kind}
          device={current}
          nameOf={nameOf}
          onClose={() => {
            setAction(null);
          }}
          onStale={refresh}
          onApplied={(d, prefixes) => {
            queryClient.setQueryData<{ items: RouteDevice[] }>(routesKey, (old) =>
              old ? { items: old.items.map((x) => (x.device_id === d.device_id ? d : x)) } : old,
            );
            refresh();
            setAction(null);
            setDone(
              t(action.kind === "revoke" ? "network.routes.revoked" : "network.routes.approved", {
                name: d.given_name,
                prefixes: prefixes.join(", "),
              }),
            );
          }}
          onApprovalRequested={(a) => {
            setAction(null);
            setApproval(a);
            void queryClient.invalidateQueries({ queryKey: queryKeys.tenant(tenantId, "approvals") });
          }}
        />
      ) : null}
    </Page>
  );
}

function PrefixList({ prefixes, tone }: { prefixes: readonly string[]; tone?: "warn" }) {
  const { t } = useTranslation();
  if (prefixes.length === 0) return <span className="text-muted">{t("common.none")}</span>;
  return (
    <ul className="space-y-0.5 font-mono text-xs">
      {prefixes.map((p) => (
        <li key={p}>{tone ? <StatusBadge tone={tone}>{p}</StatusBadge> : p}</li>
      ))}
    </ul>
  );
}

function ExitNodeState({ device }: { device: RouteDevice }) {
  const { t } = useTranslation();
  const { advertised, approved } = device.exit_node;
  if (!advertised && !approved) return <span className="text-muted">{t("common.none")}</span>;
  if (approved) {
    return <StatusBadge tone="warn">{advertised ? t("network.routes.exit.approved") : t("network.routes.exit.approvedNotAdvertised")}</StatusBadge>;
  }
  return <StatusBadge tone="info">{t("network.routes.exit.pending")}</StatusBadge>;
}

export function WarningList({ warnings, nameOf }: { warnings: readonly RouteWarning[]; nameOf: (id: string | undefined) => string }) {
  const { t } = useTranslation();
  if (warnings.length === 0) return <span className="text-muted">{t("common.none")}</span>;
  return (
    <ul className="space-y-1 text-xs" data-testid="route-warnings">
      {warnings.map((w, i) => (
        <li key={`${w.code}:${w.prefix ?? ""}:${w.other_device_id ?? ""}:${w.other_prefix ?? ""}:${i}`}>
          <StatusBadge tone={w.code === "overlap" ? "danger" : "warn"}>{t(`network.routes.warningCodes.${w.code}`)}</StatusBadge>{" "}
          {w.code === "overlap"
            ? t("network.routes.warnings.overlap", { prefix: w.prefix ?? "", other: nameOf(w.other_device_id), otherPrefix: w.other_prefix ?? "" })
            : t(`network.routes.warnings.${w.code}`)}
        </li>
      ))}
    </ul>
  );
}

function RowActions({ device, disabled, onAction }: { device: RouteDevice; disabled: boolean; onAction: (k: ActionKind) => void }) {
  const { t } = useTranslation();
  const pendingSubnets = device.pending_routes.filter((p) => !isExitPrefix(p));
  const exitPending = device.exit_node.advertised && !device.exit_node.approved;
  const name = device.given_name;
  return (
    <div className="flex flex-col items-start gap-1">
      {pendingSubnets.length > 0 ? (
        <button type="button" className="btn-secondary" disabled={disabled} aria-label={t("network.routes.approveFor", { name })} onClick={() => onAction("approve")}>
          {t("network.routes.approve")}
        </button>
      ) : null}
      {exitPending ? (
        <button type="button" className="btn-secondary" disabled={disabled} aria-label={t("network.routes.approveExitFor", { name })} onClick={() => onAction("exit")}>
          {t("network.routes.approveExit")}
        </button>
      ) : null}
      {device.approved_routes.length > 0 ? (
        <button type="button" className="btn-secondary" disabled={disabled} aria-label={t("network.routes.revokeFor", { name })} onClick={() => onAction("revoke")}>
          {t("network.routes.revoke")}
        </button>
      ) : null}
    </div>
  );
}

type ChangeVars = RouteChange & { etag: string };

/**
 * Hộp xác nhận của một thay đổi route trên một thiết bị. `device` luôn là bản mới nhất trong cache (sau 412 ⇒ tải lại ⇒
 * ETag mới, lựa chọn lọc theo tập mới). Idempotency-Key: một khóa cho một nội dung (thiết bị, prefix, ETag) trong suốt
 * đời hộp thoại — bấm lại sau lỗi dùng lại khóa; đóng hộp ⇒ ý định mới.
 */
function RouteChangeDialog({
  kind,
  device,
  nameOf,
  onClose,
  onStale,
  onApplied,
  onApprovalRequested,
}: {
  kind: ActionKind;
  device: RouteDevice;
  nameOf: (id: string | undefined) => string;
  onClose: () => void;
  onStale: () => void;
  onApplied: (d: RouteDevice, prefixes: string[]) => void;
  onApprovalRequested: (a: { id: string; data: ApprovalRequest }) => void;
}) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const ackId = useId();
  const groupId = useId();
  // lựa chọn: prefix subnet + mục "exit" (đại diện cả hai họ địa chỉ)
  const choices =
    kind === "approve"
      ? device.pending_routes.filter((p) => !isExitPrefix(p))
      : kind === "revoke"
        ? [...device.approved_routes.filter((p) => !isExitPrefix(p)), ...(device.exit_node.approved ? ["exit"] : [])]
        : [];
  const [selected, setSelected] = useState<ReadonlySet<string>>(() => new Set(kind === "approve" ? choices : []));
  const [ack, setAck] = useState(false);
  const chosen = choices.filter((c) => selected.has(c));
  const prefixes =
    kind === "exit"
      ? exitPrefixes(device.advertised_routes)
      : kind === "approve"
        ? chosen
        : chosen.flatMap((c) => (c === "exit" ? device.approved_routes.filter(isExitPrefix) : [c]));

  const onError = (e: Error) => {
    if (isStaleVersion(e)) onStale();
  };
  const approve = useIdempotentMutation({
    mutationFn: ({ etag, ...body }: ChangeVars, key: string) =>
      callWithResponse(
        api.POST("/tenants/{tenantId}/routes/approve", {
          params: { path: { tenantId }, header: { ...ifMatch(etag), "Idempotency-Key": key } },
          body,
        }),
      ),
    onError,
    onSuccess: ({ data, response }, vars) => {
      if (response.status === 202) {
        const a = data as ApprovalRequest;
        onApprovalRequested({ id: approvalFromLocation(response.headers.get("Location")) ?? a.id, data: a });
      } else {
        onApplied(data as RouteDevice, vars.prefixes);
      }
    },
  });
  const revoke = useMutation({
    mutationFn: ({ etag, ...body }: ChangeVars) =>
      call(api.POST("/tenants/{tenantId}/routes/revoke", { params: { path: { tenantId }, header: ifMatch(etag) }, body })),
    onError,
    onSuccess: (d, vars) => {
      onApplied(d, vars.prefixes);
    },
  });
  const m = kind === "revoke" ? revoke : approve;
  const submit = () => {
    const vars: ChangeVars = { device_id: device.device_id, prefixes, etag: device.routes_etag };
    if (kind === "revoke") revoke.mutate(vars);
    else approve.mutate(kind === "exit" ? { ...vars, confirm_exit_node: true } : vars);
  };
  const name = device.given_name;
  // cảnh báo trước khi duyệt: chồng lấn + router không tag (exit node có hộp rủi ro riêng)
  const warnings = device.warnings.filter((w) => kind !== "approve" || w.code !== "exit_node");
  const title =
    kind === "approve"
      ? t("network.routes.dialog.approveTitle", { name })
      : kind === "exit"
        ? t("network.routes.dialog.exitTitle", { name })
        : t("network.routes.dialog.revokeTitle", { name });

  return (
    <ConfirmDialog
      isOpen
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title={title}
      description={
        <div className="space-y-2">
          {kind === "approve" ? <p>{t("network.routes.dialog.approveDesc")}</p> : null}
          {kind === "exit" ? (
            <div className="space-y-2" data-testid="exit-risk">
              <p className="font-semibold text-danger">{t("network.routes.dialog.exitRisk")}</p>
              <p>{t("network.routes.dialog.exitRiskDetail")}</p>
            </div>
          ) : null}
          {kind === "revoke" ? <p>{t("network.routes.dialog.revokeDesc")}</p> : null}
          {kind !== "revoke" && warnings.length > 0 ? (
            <div className="rounded-md border border-warn/40 bg-warn-bg p-3" data-testid="dialog-warnings">
              <p className="font-medium">{t("network.routes.dialog.warningsTitle")}</p>
              <WarningList warnings={warnings} nameOf={nameOf} />
            </div>
          ) : null}
          {isStaleVersion(m.error) ? <p className="text-sm">{t("network.routes.dialog.stale")}</p> : null}
        </div>
      }
      confirmLabel={kind === "revoke" ? t("network.routes.revoke") : kind === "exit" ? t("network.routes.approveExit") : t("network.routes.approve")}
      destructive={kind !== "approve"}
      canConfirm={prefixes.length > 0 && (kind !== "exit" || ack)}
      pending={m.isPending}
      error={m.error ?? undefined}
      onConfirm={submit}
    >
      {kind === "exit" ? (
        <div className="space-y-2">
          <p className="font-mono text-xs">{prefixes.join(", ")}</p>
          <div className="flex items-start gap-2">
            <input
              id={ackId}
              type="checkbox"
              checked={ack}
              onChange={(e) => {
                setAck(e.target.checked);
              }}
            />
            <label htmlFor={ackId} className="text-sm">
              {t("network.routes.dialog.exitAck")}
            </label>
          </div>
        </div>
      ) : (
        <fieldset aria-describedby={choices.length === 0 ? groupId : undefined}>
          <legend className="label">{kind === "revoke" ? t("network.routes.dialog.chooseRevoke") : t("network.routes.dialog.chooseApprove")}</legend>
          {choices.length === 0 ? (
            <p id={groupId} className="hint">
              {t("network.routes.dialog.nothing")}
            </p>
          ) : (
            <ul className="space-y-1">
              {choices.map((c) => (
                <li key={c} className="flex items-center gap-2">
                  <input
                    id={`${groupId}-${c}`}
                    type="checkbox"
                    checked={selected.has(c)}
                    onChange={(e) => {
                      const next = new Set(selected);
                      if (e.target.checked) next.add(c);
                      else next.delete(c);
                      setSelected(next);
                    }}
                  />
                  <label htmlFor={`${groupId}-${c}`} className="font-mono text-sm">
                    {c === "exit" ? t("network.routes.dialog.exitChoice") : c}
                  </label>
                </li>
              ))}
            </ul>
          )}
        </fieldset>
      )}
    </ConfirmDialog>
  );
}

/** Prefix exit node đang được quảng bá (server: một trong hai là cả hai — gửi đúng những gì thiết bị quảng bá). */
function exitPrefixes(advertised: readonly string[]): string[] {
  const out = advertised.filter(isExitPrefix);
  return out.length > 0 ? out : [...EXIT_PREFIXES];
}
