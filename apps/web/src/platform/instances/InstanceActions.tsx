// Thao tác vận hành instance (§12.2 "Instance actions", §11.4, §8.5): restart / reconfigure / backup (platform.instance
// :operate), upgrade (:upgrade), quarantine (:quarantine) ⇒ 202 + Location của job ⇒ timeline có sẵn (P4-T02);
// restore (:restore) và release (:release) LUÔN 2P ⇒ 202 + Location của yêu cầu phê duyệt ⇒ trang phê duyệt có sẵn.
// Mọi lệnh mang Idempotency-Key (một khóa cho một ý định — src/api/idempotency.ts). Nút chỉ hiện theo role + trạng thái
// (UX); server quyết định (trạng thái ⇒ 409, step-up ⇒ 401, giá trị ⇒ 422).
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import type { components } from "../../api/schema";
import { api, callWithResponse } from "../../api/client";
import { fingerprintOf, useIdempotentMutation } from "../../api/idempotency";
import { approvalFromLocation, jobFromLocation } from "../../api/jobs";
import { can } from "../../auth/permissions";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { CheckboxField, SelectField, TextField } from "../../ui/Form";
import { FormDialog } from "../../ui/FormDialog";
import { Timestamp } from "../../ui/time";
import { invalidatePlatform } from "../api";
import { useInstanceBackups, type Instance } from "../opsApi";

type S = components["schemas"];
export type InstanceAction = "restart" | "reconfigure" | "backup" | "upgrade" | "restore" | "quarantine" | "release";
type Vars =
  | { act: "restart" | "backup" }
  | { act: "reconfigure"; body: S["InstanceReconfigure"] }
  | { act: "upgrade"; body: S["InstanceUpgrade"] }
  | { act: "restore"; body: S["InstanceRestoreCreate"] }
  | { act: "quarantine" | "release"; body: { reason: string } };

const PERMISSION: Record<InstanceAction, string> = {
  restart: "platform.instance:operate",
  reconfigure: "platform.instance:operate",
  backup: "platform.instance:operate",
  upgrade: "platform.instance:upgrade",
  restore: "platform.instance:restore",
  quarantine: "platform.instance:quarantine",
  release: "platform.instance:release",
};

/** Thao tác hiện cho role + trạng thái (thứ tự hiển thị). Chỉ UX — server quyết định. */
export function actionsFor(role: string | null, status: Instance["status"]): InstanceAction[] {
  const byStatus: Record<InstanceAction, boolean> = {
    restart: status === "running",
    reconfigure: status === "running",
    upgrade: status === "running",
    backup: status !== "quarantined" && status !== "removed",
    restore: status !== "removed",
    quarantine: status !== "removed",
    release: status === "quarantined",
  };
  return (Object.keys(PERMISSION) as InstanceAction[]).filter((a) => byStatus[a] && can(role, PERMISSION[a]));
}

export const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const LOG_LEVELS = ["info", "warn", "error"] as const;

export interface ReconfigureForm {
  logLevel: "" | (typeof LOG_LEVELS)[number];
  nodeExpiryDays: string;
  nameservers: string;
  derpRegionId: string;
}

function intIn(raw: string, lo: number, hi: number): number | null {
  if (!/^\d{1,10}$/.test(raw.trim())) return null;
  const n = Number(raw.trim());
  return n >= lo && n <= hi ? n : null;
}

/** Lỗi theo trường (khóa i18n) + body InstanceReconfigure (chỉ trường đã điền — trống = giữ nguyên). */
export function reconfigureRequest(f: ReconfigureForm): { errors: Partial<Record<keyof ReconfigureForm | "form", string>>; body: S["InstanceReconfigure"] } {
  const errors: Partial<Record<keyof ReconfigureForm | "form", string>> = {};
  const body: S["InstanceReconfigure"] = {};
  if (f.logLevel) body.log_level = f.logLevel;
  if (f.nodeExpiryDays.trim()) {
    const n = intIn(f.nodeExpiryDays, 1, 3650);
    if (n === null) errors.nodeExpiryDays = "platform.instance.errors.nodeExpiry";
    else body.node_expiry_days = n;
  }
  if (f.nameservers.trim()) {
    const list = f.nameservers.split(/[\s,]+/).filter(Boolean);
    if (list.length < 1 || list.length > 8 || new Set(list).size !== list.length || list.some((s) => s.length < 2 || s.length > 45)) {
      errors.nameservers = "platform.instance.errors.nameservers";
    } else body.nameservers = list;
  }
  if (f.derpRegionId.trim()) {
    const n = intIn(f.derpRegionId, 900, 999);
    if (n === null) errors.derpRegionId = "platform.instance.errors.derpRegion";
    else body.derp_region_id = n;
  }
  if (Object.keys(body).length === 0 && Object.keys(errors).length === 0) errors.form = "platform.instance.errors.nothing";
  return { errors, body };
}

export function InstanceActions({ instance, role }: { instance: Instance; role: string | null }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState<InstanceAction | null>(null);

  const run = useIdempotentMutation<{ data: { id: string }; response: Response }, Vars>({
    fingerprint: (v: Vars) => `${instance.id}:${fingerprintOf(v)}`,
    mutationFn: (v: Vars, key: string) => {
      const p = { path: { instanceId: instance.id }, header: { "Idempotency-Key": key } };
      switch (v.act) {
        case "restart":
          return callWithResponse(api.POST("/platform/instances/{instanceId}/restart", { params: p }));
        case "backup":
          return callWithResponse(api.POST("/platform/instances/{instanceId}/backup", { params: p }));
        case "reconfigure":
          return callWithResponse(api.POST("/platform/instances/{instanceId}/reconfigure", { params: p, body: v.body }));
        case "upgrade":
          return callWithResponse(api.POST("/platform/instances/{instanceId}/upgrade", { params: p, body: v.body }));
        case "quarantine":
          return callWithResponse(api.POST("/platform/instances/{instanceId}/quarantine", { params: p, body: v.body }));
        case "restore":
          return callWithResponse(api.POST("/platform/instances/{instanceId}/restore", { params: p, body: v.body }));
        case "release":
          return callWithResponse(api.POST("/platform/instances/{instanceId}/release", { params: p, body: v.body }));
      }
    },
    onSuccess: async (r, v) => {
      setOpen(null);
      await Promise.all([
        invalidatePlatform(queryClient, "instance", instance.id),
        invalidatePlatform(queryClient, "instances"),
        invalidatePlatform(queryClient, "jobs"),
        invalidatePlatform(queryClient, "approvals"),
      ]);
      const location = r.response.headers.get("Location");
      if (v.act === "restore" || v.act === "release") {
        void navigate(`/platform/approvals/${approvalFromLocation(location) ?? r.data.id}`, { state: { requested: true } });
      } else {
        void navigate(`/platform/jobs/${jobFromLocation(location)?.jobId ?? r.data.id}`);
      }
    },
  });

  const shown = actionsFor(role, instance.status);
  if (shown.length === 0) return null;
  const close = (o: boolean) => {
    if (!o) {
      setOpen(null);
      run.reset();
    }
  };
  const common = { onOpenChange: close, pending: run.isPending, error: run.error };

  return (
    <div className="flex flex-wrap gap-2" role="group" aria-label={t("platform.instance.actions")}>
      {shown.map((a) => (
        <button
          key={a}
          type="button"
          className={a === "quarantine" ? "btn-danger" : "btn-secondary"}
          onClick={() => {
            setOpen(a);
          }}
        >
          {t(`platform.instance.act.${a}`)}
        </button>
      ))}

      <ConfirmDialog
        {...common}
        isOpen={open === "restart" || open === "backup"}
        title={t(open === "backup" ? "platform.instance.backupTitle" : "platform.instance.restartTitle", { host: instance.control_hostname })}
        description={<p>{t(open === "backup" ? "platform.instance.backupDesc" : "platform.instance.restartDesc")}</p>}
        confirmLabel={t(open === "backup" ? "platform.instance.act.backup" : "platform.instance.act.restart")}
        onConfirm={() => {
          if (open === "restart" || open === "backup") run.mutate({ act: open });
        }}
      />
      {open === "reconfigure" ? <ReconfigureDialog {...common} instance={instance} onRun={(body) => { run.mutate({ act: "reconfigure", body }); }} /> : null}
      {open === "upgrade" ? <UpgradeDialog {...common} instance={instance} onRun={(body) => { run.mutate({ act: "upgrade", body }); }} /> : null}
      {open === "restore" ? (
        <RestoreDialog {...common} instance={instance} canList={can(role, "platform.backup:read")} onRun={(body) => { run.mutate({ act: "restore", body }); }} />
      ) : null}
      {open === "quarantine" || open === "release" ? (
        <ReasonDialog
          {...common}
          act={open}
          instance={instance}
          onRun={(reason) => {
            run.mutate({ act: open, body: { reason } });
          }}
        />
      ) : null}
    </div>
  );
}

interface DialogProps {
  instance: Instance;
  onOpenChange: (o: boolean) => void;
  pending: boolean;
  error: unknown;
}

function ReconfigureDialog({ instance, onRun, ...p }: DialogProps & { onRun: (b: S["InstanceReconfigure"]) => void }) {
  const { t } = useTranslation();
  const [f, setF] = useState<ReconfigureForm>({ logLevel: "", nodeExpiryDays: "", nameservers: "", derpRegionId: "" });
  const [tried, setTried] = useState(false);
  const { errors, body } = reconfigureRequest(f);
  const err = (k: keyof ReconfigureForm) => (tried && errors[k] ? t(errors[k]) : undefined);
  const set = (k: keyof ReconfigureForm) => (v: string) => {
    setF((x) => ({ ...x, [k]: v }));
  };
  return (
    <FormDialog
      {...p}
      isOpen
      title={t("platform.instance.reconfigureTitle", { host: instance.control_hostname })}
      description={<p>{t("platform.instance.reconfigureDesc")}</p>}
      submitLabel={t("platform.instance.submit.reconfigure")}
      onSubmit={() => {
        setTried(true);
        if (Object.keys(errors).length === 0) onRun(body);
      }}
    >
      <SelectField
        label={t("platform.instance.logLevel")}
        value={f.logLevel}
        autoFocus
        options={[{ value: "" as const, label: t("platform.instance.unchanged") }, ...LOG_LEVELS.map((l) => ({ value: l, label: l }))]}
        onChange={(v) => {
          setF((x) => ({ ...x, logLevel: v }));
        }}
      />
      <TextField label={t("platform.instance.nodeExpiry")} hint={t("platform.instance.nodeExpiryHint")} value={f.nodeExpiryDays} onChange={set("nodeExpiryDays")} error={err("nodeExpiryDays")} numeric />
      <TextField label={t("platform.instance.nameservers")} hint={t("platform.instance.nameserversHint")} value={f.nameservers} onChange={set("nameservers")} error={err("nameservers")} mono />
      <TextField label={t("platform.instance.derpRegion")} hint={t("platform.instance.derpRegionHint")} value={f.derpRegionId} onChange={set("derpRegionId")} error={err("derpRegionId")} numeric />
      {tried && errors.form ? <p className="field-error">{t(errors.form)}</p> : null}
    </FormDialog>
  );
}

function UpgradeDialog({ instance, onRun, ...p }: DialogProps & { onRun: (b: S["InstanceUpgrade"]) => void }) {
  const { t } = useTranslation();
  const [digest, setDigest] = useState("");
  const [tried, setTried] = useState(false);
  const v = digest.trim();
  const bad = !DIGEST_RE.test(v) ? "platform.instance.errors.digest" : v === instance.image_digest ? "platform.instance.errors.sameDigest" : null;
  return (
    <FormDialog
      {...p}
      isOpen
      title={t("platform.instance.upgradeTitle", { host: instance.control_hostname })}
      description={
        <div className="space-y-2">
          <p>{t("platform.instance.upgradeDesc")}</p>
          <p className="text-xs">
            {t("platform.instance.currentDigest")} <code className="break-all">{instance.image_digest}</code>
          </p>
        </div>
      }
      submitLabel={t("platform.instance.submit.upgrade")}
      onSubmit={() => {
        setTried(true);
        if (!bad) onRun({ image_digest: v });
      }}
    >
      <TextField label={t("platform.instance.targetDigest")} hint={t("platform.instance.targetDigestHint")} value={digest} onChange={setDigest} error={tried && bad ? t(bad) : undefined} mono autoFocus />
    </FormDialog>
  );
}

function RestoreDialog({ instance, canList, onRun, ...p }: DialogProps & { canList: boolean; onRun: (b: S["InstanceRestoreCreate"]) => void }) {
  const { t } = useTranslation();
  const backups = useInstanceBackups(instance.id, canList);
  const [backupId, setBackupId] = useState("");
  const [older, setOlder] = useState(false);
  const [reason, setReason] = useState("");
  const items = backups.data?.items ?? [];
  const chosen = backupId || items[0]?.id || "";
  const ok = chosen !== "" && reason.trim().length > 0 && reason.length <= 1000;
  return (
    <FormDialog
      {...p}
      isOpen
      destructive
      title={t("platform.instance.restoreTitle", { host: instance.control_hostname })}
      description={
        <div className="space-y-2">
          <p>{t("platform.instance.restoreDesc")}</p>
          <p className="font-medium">{t("platform.instance.twoPerson")}</p>
        </div>
      }
      submitLabel={t("platform.instance.requestRestore")}
      canSubmit={ok}
      onSubmit={() => {
        if (ok) onRun({ backup_id: chosen, restore_point_older_than_backup: older, reason: reason.trim() });
      }}
    >
      {!canList ? (
        <p className="text-sm text-muted">{t("platform.tenantDetail.noPermission")}</p>
      ) : backups.isPending ? (
        <p role="status" className="text-sm text-muted">
          {t("common.loading")}
        </p>
      ) : items.length === 0 ? (
        <p className="text-sm text-muted" data-testid="no-backups">
          {t("platform.instance.noBackups")}
        </p>
      ) : (
        <fieldset>
          <legend className="label">{t("platform.instance.chooseBackup")}</legend>
          <ul className="space-y-1">
            {items.map((b) => (
              <li key={b.id} className="flex items-start gap-2">
                <input
                  id={`bk-${b.id}`}
                  type="radio"
                  name="backup"
                  className="mt-1"
                  checked={chosen === b.id}
                  onChange={() => {
                    setBackupId(b.id);
                  }}
                />
                <label htmlFor={`bk-${b.id}`} className="text-sm">
                  <Timestamp iso={b.started_at} relative={false} /> · <code className="text-xs">{b.headscale_version ?? b.id}</code>
                </label>
              </li>
            ))}
          </ul>
        </fieldset>
      )}
      <CheckboxField label={t("platform.instance.olderRestorePoint")} hint={t("platform.instance.olderRestorePointHint")} checked={older} onChange={setOlder} />
      <TextField label={t("platform.tenantDetail.reason")} value={reason} onChange={setReason} rows={3} maxLength={1000} />
    </FormDialog>
  );
}

function ReasonDialog({ act, instance, onRun, ...p }: DialogProps & { act: "quarantine" | "release"; onRun: (reason: string) => void }) {
  const { t } = useTranslation();
  const [reason, setReason] = useState("");
  const ok = reason.trim().length > 0 && reason.length <= 1000;
  return (
    <ConfirmDialog
      {...p}
      isOpen
      destructive={act === "quarantine"}
      title={t(`platform.instance.${act}Title`, { host: instance.control_hostname })}
      description={
        <div className="space-y-2">
          <p>{t(`platform.instance.${act}Desc`)}</p>
          {act === "release" ? <p className="font-medium">{t("platform.instance.twoPerson")}</p> : null}
        </div>
      }
      confirmLabel={t(act === "release" ? "platform.instance.requestRelease" : "platform.instance.submit.quarantine")}
      typedConfirmation={act === "quarantine" ? { expected: instance.control_hostname, label: t("platform.instance.typeHostname") } : undefined}
      canConfirm={ok}
      onConfirm={() => {
        onRun(reason.trim());
      }}
    >
      <TextField label={t("platform.tenantDetail.reason")} value={reason} onChange={setReason} rows={3} maxLength={1000} />
    </ConfirmDialog>
  );
}
