// Chi tiết thiết bị (P4-T04, §12.3): GET /tenants/{t}/devices/{id} kèm `synced_at`; đổi tên (PATCH, nhãn DNS kiểm cục
// bộ); thu hồi hai pha — expire (POST …/expire, Idempotency-Key) và xóa (DELETE) đều trả 202 + `revocation.state =
// pending`, màn hình poll thiết bị tới `applied`/`failed` và chỉ báo "đã áp dụng" khi applied (T-17); xóa đã áp dụng
// ⇒ thiết bị biến khỏi sổ (404) ⇒ báo đã xóa. Quyền theo role (§8.6; End User chỉ trên thiết bị của mình — server
// quyết định), tenant chỉ-đọc ⇒ khóa mọi thao tác ghi. Tag và route chỉ đọc ở đây (đổi tag: P4-T10; duyệt route: P4-T12).
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type SyntheticEvent } from "react";
import { useTranslation } from "react-i18next";
import { Link, useParams } from "react-router";
import { api, call } from "../../api/client";
import { ApiError } from "../../api/problem";
import { isUuid, queryKeys } from "../../api/queryClient";
import { can } from "../../auth/permissions";
import { Loading, Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { NotFoundPage } from "../../pages/StatusPages";
import { callWithResponse } from "../../api/client";
import { useIdempotencyKey } from "../../api/idempotency";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { ObservedAt, Timestamp } from "../../ui/time";
import { useTenant } from "../TenantScope";
import { ExpiryText, OnlineBadge, OwnerText, RevocationBadge, TagList } from "./DeviceBits";
import { GIVEN_NAME_RE, revocationPending, type Device } from "./deviceModel";

export const REVOCATION_POLL_MS = 2000;

type Pending = "expire" | "delete" | null;

export function DeviceDetailPage() {
  const { deviceId: raw = "" } = useParams();
  const deviceId = raw.toLowerCase();
  if (!isUuid(deviceId)) return <NotFoundPage />;
  return <DeviceDetail key={deviceId} deviceId={deviceId} />;
}

function DeviceDetail({ deviceId }: { deviceId: string }) {
  const { t } = useTranslation();
  const { tenantId, role, readOnly } = useTenant();
  const queryClient = useQueryClient();
  const [deleteRequested, setDeleteRequested] = useState(false);
  const key = queryKeys.tenant(tenantId, "devices", "detail", deviceId);
  const device = useQuery({
    queryKey: key,
    queryFn: () => call(api.GET("/tenants/{tenantId}/devices/{deviceId}", { params: { path: { tenantId, deviceId } } })),
    refetchInterval: (q) => (revocationPending(q.state.data) && q.state.error === null ? REVOCATION_POLL_MS : false),
    retry: false,
  });
  const store = (d: Device) => {
    queryClient.setQueryData(key, d);
    void queryClient.invalidateQueries({ queryKey: queryKeys.tenant(tenantId, "devices", "list") });
    void queryClient.invalidateQueries({ queryKey: queryKeys.tenant(tenantId, "dashboard") });
  };

  const gone = device.error instanceof ApiError && device.error.status === 404;
  if (gone && deleteRequested) {
    return (
      <Page title={t("devices.deleted.title")}>
        <p role="status" data-testid="device-deleted">
          {t("devices.deleted.description")}
        </p>
        <p className="mt-4">
          <Link to={`/t/${tenantId}/devices`} className="link">
            {t("devices.backToList")}
          </Link>
        </p>
      </Page>
    );
  }
  if (gone) return <NotFoundPage />;
  if (device.isPending) return <Loading />;
  if (device.isError) {
    return (
      <Page title={t("nav.tenant.devices")}>
        <ProblemAlert error={device.error} onRetry={() => void device.refetch()} />
      </Page>
    );
  }
  const d = device.data;
  const writable = !readOnly;
  return (
    <Page title={d.given_name}>
      <p className="-mt-4 mb-4">
        <Link to={`/t/${tenantId}/devices`} className="link text-sm">
          {t("devices.backToList")}
        </Link>
      </p>
      {readOnly ? <p className="mb-3 text-sm text-muted">{t("ui.readOnlyActions")}</p> : null}
      <RevocationPanel device={d} deleteRequested={deleteRequested} />
      <section className="card" aria-labelledby="dev-info">
        <h2 id="dev-info" className="font-semibold">
          {t("devices.detail.info")}
        </h2>
        <dl className="mt-2 grid gap-x-6 gap-y-2 text-sm md:grid-cols-[max-content_1fr]">
          <dt className="text-muted">{t("devices.col.name")}</dt>
          <dd>{d.given_name}</dd>
          <dt className="text-muted">{t("devices.detail.hostname")}</dt>
          <dd>{d.name}</dd>
          <dt className="text-muted">{t("devices.col.owner")}</dt>
          <dd>
            <OwnerText device={d} />
          </dd>
          <dt className="text-muted">{t("devices.col.tags")}</dt>
          <dd>
            <TagList tags={d.tags} />
            <span className="ms-2 text-xs text-muted">{t("devices.detail.tagsLater")}</span>
          </dd>
          <dt className="text-muted">{t("devices.col.addresses")}</dt>
          <dd className="font-mono text-xs">{d.ip_addresses.join(", ")}</dd>
          <dt className="text-muted">{t("devices.col.status")}</dt>
          <dd className="space-x-1">
            <OnlineBadge device={d} />
            <RevocationBadge device={d} />
          </dd>
          <dt className="text-muted">{t("devices.col.lastSeen")}</dt>
          <dd>
            <Timestamp iso={d.last_seen} />
          </dd>
          <dt className="text-muted">{t("devices.col.expiry")}</dt>
          <dd>
            <ExpiryText device={d} />
          </dd>
          <dt className="text-muted">{t("devices.detail.registerMethod")}</dt>
          <dd>
            <code>{d.register_method}</code>
          </dd>
          <dt className="text-muted">{t("devices.detail.routesAdvertised")}</dt>
          <dd className="font-mono text-xs">{d.routes.advertised.length > 0 ? d.routes.advertised.join(", ") : "—"}</dd>
          <dt className="text-muted">{t("devices.detail.routesApproved")}</dt>
          <dd className="font-mono text-xs">{d.routes.approved.length > 0 ? d.routes.approved.join(", ") : "—"}</dd>
        </dl>
        <ObservedAt labelKey="ui.syncedAt" iso={d.synced_at} />
        <p className="mt-1 text-xs text-muted">{t("devices.noOsNote")}</p>
      </section>
      {can(role, "tenant.device:rename") ? <RenameForm device={d} disabled={!writable} onDone={store} /> : null}
      <Revocations
        device={d}
        canExpire={can(role, "tenant.device:expire")}
        canDelete={can(role, "tenant.device:delete")}
        disabled={!writable}
        onAccepted={(next, kind) => {
          if (kind === "delete") setDeleteRequested(true);
          store(next);
        }}
      />
    </Page>
  );
}

function RevocationPanel({ device, deleteRequested }: { device: Device; deleteRequested: boolean }) {
  const { t } = useTranslation();
  const r = device.revocation;
  if (r.state === "none" && !deleteRequested) return null;
  const kind = r.kind ? t(`devices.revocation.kind.${r.kind}`) : "";
  return (
    <div role="status" aria-live="polite" className="mb-4 rounded-md border border-line bg-surface p-4" data-testid="revocation-panel">
      <p className="font-medium">{t(`devices.revocation.explain.${r.state}`, { kind })}</p>
      {r.requested_at ? (
        <p className="mt-1 text-sm text-muted">
          {t("devices.revocation.requestedAt")} <Timestamp iso={r.requested_at} />
        </p>
      ) : null}
      {r.verified_at ? (
        <p className="mt-1 text-sm text-muted">
          {t("devices.revocation.verifiedAt")} <Timestamp iso={r.verified_at} />
        </p>
      ) : null}
    </div>
  );
}

function RenameForm({ device, disabled, onDone }: { device: Device; disabled: boolean; onDone: (d: Device) => void }) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const [name, setName] = useState(device.given_name);
  const invalid = !GIVEN_NAME_RE.test(name);
  const rename = useMutation({
    mutationFn: (givenName: string) =>
      call(
        api.PATCH("/tenants/{tenantId}/devices/{deviceId}", {
          params: { path: { tenantId, deviceId: device.id } },
          body: { given_name: givenName },
        }),
      ),
    onSuccess: onDone,
  });
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    if (!invalid && name !== device.given_name) rename.mutate(name);
  };
  return (
    <section className="card mt-4" aria-labelledby="dev-rename">
      <h2 id="dev-rename" className="font-semibold">
        {t("devices.rename.title")}
      </h2>
      <form className="mt-2 flex flex-wrap items-end gap-2" onSubmit={submit}>
        <div className="min-w-64 flex-1">
          <label htmlFor="dev-given-name" className="block text-xs font-medium text-muted">
            {t("devices.rename.label")}
          </label>
          <input
            id="dev-given-name"
            className="input"
            value={name}
            maxLength={63}
            disabled={disabled}
            aria-invalid={invalid}
            aria-describedby="dev-given-name-hint"
            onChange={(e) => {
              setName(e.target.value.toLowerCase());
            }}
          />
          <p id="dev-given-name-hint" className={invalid ? "mt-1 text-xs text-danger" : "mt-1 text-xs text-muted"}>
            {t("devices.rename.hint")}
          </p>
        </div>
        <button type="submit" className="btn-primary" disabled={disabled || invalid || name === device.given_name || rename.isPending}>
          {t("devices.rename.submit")}
        </button>
      </form>
      {rename.isSuccess ? (
        <p role="status" className="mt-2 text-sm">
          {t("devices.rename.done")}
        </p>
      ) : null}
      {rename.isError ? (
        <div className="mt-2">
          <ProblemAlert error={rename.error} />
        </div>
      ) : null}
    </section>
  );
}

function Revocations({
  device,
  canExpire,
  canDelete,
  disabled,
  onAccepted,
}: {
  device: Device;
  canExpire: boolean;
  canDelete: boolean;
  disabled: boolean;
  onAccepted: (d: Device, kind: "expire" | "delete") => void;
}) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const [confirm, setConfirm] = useState<Pending>(null);
  const key = useIdempotencyKey();
  const revoke = useMutation({
    mutationFn: async (kind: "expire" | "delete") => {
      const path = { tenantId, deviceId: device.id };
      const { data } =
        kind === "expire"
          ? await callWithResponse(
              api.POST("/tenants/{tenantId}/devices/{deviceId}/expire", { params: { path, header: { "Idempotency-Key": key.current() } } }),
            )
          : await callWithResponse(api.DELETE("/tenants/{tenantId}/devices/{deviceId}", { params: { path } }));
      return { data, kind };
    },
    onSuccess: ({ data, kind }) => {
      key.reset();
      setConfirm(null);
      onAccepted(data, kind);
    },
  });
  if (!canExpire && !canDelete) return null;
  const pending = revocationPending(device);
  const close = () => {
    setConfirm(null);
    key.reset();
    revoke.reset();
  };
  return (
    <section className="card mt-4" aria-labelledby="dev-revoke">
      <h2 id="dev-revoke" className="font-semibold">
        {t("devices.revoke.title")}
      </h2>
      <p className="mt-1 text-sm text-muted">{t("devices.revoke.description")}</p>
      <div className="mt-3 flex flex-wrap gap-2">
        {canExpire ? (
          <button type="button" className="btn-secondary" disabled={disabled || pending} onClick={() => setConfirm("expire")}>
            {t("devices.revoke.expire")}
          </button>
        ) : null}
        {canDelete ? (
          <button type="button" className="btn-danger" disabled={disabled || pending} onClick={() => setConfirm("delete")}>
            {t("devices.revoke.delete")}
          </button>
        ) : null}
      </div>
      <ConfirmDialog
        isOpen={confirm !== null}
        onOpenChange={(o) => {
          if (!o) close();
        }}
        title={confirm === "delete" ? t("devices.revoke.confirmDeleteTitle", { name: device.given_name }) : t("devices.revoke.confirmExpireTitle", { name: device.given_name })}
        description={
          <div className="space-y-2">
            <p>{confirm === "delete" ? t("devices.revoke.confirmDelete") : t("devices.revoke.confirmExpire")}</p>
            <p className="text-muted">{t("devices.revoke.twoPhase")}</p>
          </div>
        }
        confirmLabel={confirm === "delete" ? t("devices.revoke.delete") : t("devices.revoke.expire")}
        destructive
        pending={revoke.isPending}
        error={revoke.isError ? revoke.error : undefined}
        onConfirm={() => {
          if (confirm) revoke.mutate(confirm);
        }}
      />
    </section>
  );
}
