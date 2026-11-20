// Thiết lập hệ thống (§12.2 "System configuration — SA; audit + ETag"): GET /platform/settings — tập khóa ĐÓNG của
// internal/config (khóa sửa được + cờ chỉ lệnh host ghi; con trỏ nội bộ không bao giờ được trả); PUT
// /platform/settings/{key} chỉ Super Admin (platform.settings:update) + step-up, `If-Match` = `etag` của bản đã đọc.
// 412 (người khác vừa sửa) ⇒ hộp nói rõ, hiện giá trị mới nhất và để người dùng quyết định lại — không tự ghi đè.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, call } from "../../api/client";
import { ifMatch, isStaleVersion } from "../../api/etag";
import { can } from "../../auth/permissions";
import { QueryBlock } from "../../ui/Data";
import { TextField } from "../../ui/Form";
import { FormDialog } from "../../ui/FormDialog";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { Page } from "../../components/Page";
import { opsKeys, usePlatformSettings, type SystemSetting } from "../opsApi";
import { usePlatformRole } from "../PlatformScope";

/** Miền giá trị của các khóa sửa được (mirror internal/config/systemsettings.go — chỉ để hướng dẫn; server quyết định). */
export const SETTING_RANGES: Readonly<Record<string, { min: number; max: number }>> = {
  "approval.ttl_hours": { min: 1, max: 168 },
  "quota.max_tenants": { min: 0, max: 2147483647 },
};

/** Giá trị đã gõ ⇒ JSON gửi đi, hoặc khóa i18n của lỗi. Khóa đã biết: số nguyên trong miền; khóa khác: JSON bất kỳ. */
export function parseSettingValue(key: string, raw: string): { value: unknown } | { error: string } {
  const range = SETTING_RANGES[key];
  if (range) {
    if (!/^\d{1,10}$/.test(raw.trim())) return { error: "platform.settings.errors.integer" };
    const n = Number(raw.trim());
    return n >= range.min && n <= range.max ? { value: n } : { error: "platform.settings.errors.range" };
  }
  try {
    return { value: JSON.parse(raw) as unknown };
  } catch {
    return { error: "platform.settings.errors.json" };
  }
}

/** JSON của giá trị (chuỗi rỗng khi chưa có). */
function display(v: unknown): string {
  return v === null || v === undefined ? "" : JSON.stringify(v);
}

export function SettingsPage() {
  const { t } = useTranslation();
  const role = usePlatformRole();
  const q = usePlatformSettings();
  const [editing, setEditing] = useState<string | null>(null);
  const canUpdate = can(role, "platform.settings:update");
  return (
    <Page title={t("nav.platform.settings")}>
      <p className="mb-4 text-sm text-muted">{t(canUpdate ? "platform.settings.intro" : "platform.settings.readOnlyRole")}</p>
      <QueryBlock query={q}>
        {(data) => (
          <>
            <div className="relative overflow-x-auto rounded-lg border border-line bg-surface">
              <table className="data-table">
                <caption className="sr-only">{t("nav.platform.settings")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("platform.settings.col.key")}</th>
                    <th scope="col">{t("platform.settings.col.value")}</th>
                    <th scope="col">{t("platform.settings.col.updated")}</th>
                    <th scope="col">{t("platform.settings.col.actions")}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((s) => (
                    <tr key={s.key} data-testid="setting-row" data-key={s.key}>
                      <td>
                        <code>{s.key}</code>
                        <span className="hint block">{t(`platform.settings.desc.${s.key.replaceAll(".", "_")}`, { defaultValue: s.description })}</span>
                      </td>
                      <td>
                        {s.value === null || s.value === undefined ? (
                          <span className="text-muted">
                            {t("platform.settings.unset")}
                            {s.default !== undefined ? ` (${t("platform.settings.default", { value: display(s.default) })})` : ""}
                          </span>
                        ) : (
                          <code data-testid="setting-value">{display(s.value)}</code>
                        )}
                      </td>
                      <td>
                        {s.version === 0 ? t("common.none") : <Timestamp iso={s.updated_at} emptyKey="common.none" />}
                        <span className="hint block">{t("platform.settings.version", { version: s.version })}</span>
                      </td>
                      <td>
                        {!s.writable ? (
                          <StatusBadge tone="neutral">{t("platform.settings.readOnly")}</StatusBadge>
                        ) : canUpdate ? (
                          <button
                            type="button"
                            className="btn-secondary"
                            onClick={() => {
                              setEditing(s.key);
                            }}
                          >
                            {t("platform.settings.edit", { key: s.key })}
                          </button>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {editing ? (
              <EditSetting
                key={editing}
                setting={data.items.find((s) => s.key === editing) ?? null}
                onClose={() => {
                  setEditing(null);
                }}
              />
            ) : null}
          </>
        )}
      </QueryBlock>
    </Page>
  );
}

/** `setting` là bản mới nhất trong cache (đổi sau khi tải lại); bản đã đọc khi mở hộp (`base`) quyết định If-Match. */
function EditSetting({ setting, onClose }: { setting: SystemSetting | null; onClose: () => void }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [base, setBase] = useState(setting);
  const [raw, setRaw] = useState(display(setting?.value ?? setting?.default ?? null));
  const [tried, setTried] = useState(false);
  const save = useMutation({
    mutationFn: (v: { key: string; etag: string; value: unknown }) =>
      call(
        api.PUT("/platform/settings/{settingKey}", {
          params: { path: { settingKey: v.key }, header: ifMatch(v.etag) },
          body: { value: v.value },
        }),
      ),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: opsKeys.settings() });
      onClose();
    },
    onError: async (e) => {
      // bản đã cũ: tải bản mới nhất để hiện cho người dùng (không tự gửi lại)
      if (isStaleVersion(e)) await queryClient.invalidateQueries({ queryKey: opsKeys.settings() });
    },
  });
  if (!base) return null;
  const parsed = parseSettingValue(base.key, raw);
  const stale = isStaleVersion(save.error);
  const range = SETTING_RANGES[base.key];
  return (
    <FormDialog
      isOpen
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
      title={t("platform.settings.editTitle", { key: base.key })}
      description={<p>{t("platform.settings.editDesc")}</p>}
      submitLabel={t("platform.settings.save")}
      pending={save.isPending}
      error={stale ? null : save.error}
      canSubmit={!stale}
      onSubmit={() => {
        setTried(true);
        if ("value" in parsed) save.mutate({ key: base.key, etag: base.etag, value: parsed.value });
      }}
    >
      <TextField
        label={t("platform.settings.value")}
        hint={range ? t("platform.settings.rangeHint", { min: range.min, max: range.max }) : t("platform.settings.jsonHint")}
        value={raw}
        onChange={setRaw}
        error={tried && "error" in parsed ? t(parsed.error) : undefined}
        numeric={range !== undefined}
        mono
        autoFocus
      />
      {stale ? (
        <div role="alert" className="rounded-md border border-warn/40 bg-warn-bg p-3 text-sm" data-testid="stale-setting">
          <p className="font-semibold">{t("problem.precondition_failed")}</p>
          <p className="mt-1">
            {t("platform.settings.latest")} <code data-testid="latest-value">{setting ? display(setting.value ?? setting.default ?? null) : t("common.none")}</code>
          </p>
          <button
            type="button"
            className="btn-secondary mt-2"
            disabled={!setting || setting.etag === base.etag}
            onClick={() => {
              if (!setting) return;
              setBase(setting);
              setRaw(display(setting.value ?? setting.default ?? null));
              setTried(false);
              save.reset();
            }}
          >
            {t("platform.settings.useLatest")}
          </button>
        </div>
      ) : null}
    </FormDialog>
  );
}
