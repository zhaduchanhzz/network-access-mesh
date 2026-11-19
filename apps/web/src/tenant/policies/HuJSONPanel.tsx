// Chế độ HuJSON của editor (P4-T11). Bộ dịch nằm ở SERVER (POST /policies/export và /policies/import — §7.2): văn bản
// của admin không bao giờ được lưu hay gửi tới Headscale; "Dịch sang biểu mẫu" thay nội dung của form bằng `source` có
// kiểu server trả về, người dùng xem lại rồi mới lưu (PATCH) như mọi lần sửa. Văn bản rỗng không được gửi (L2, báo ngay
// trên trang); thiếu `grants` do server báo (L1). Không phải trình soạn "thô" của headscale-admin (§12.5): chuỗi ở đây
// không đi tới đâu ngoài bộ dịch.
import { useMutation } from "@tanstack/react-query";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, call } from "../../api/client";
import { ProblemAlert } from "../../components/ProblemAlert";
import { useTenant } from "../TenantScope";
import { FindingList } from "./FindingList";
import { toSourceBody, type PolicyFinding, type PolicySource, type PrincipalName } from "./model";

export interface HuJSONPanelProps {
  /** văn bản đang hiển thị (đã xuất từ nội dung hiện tại) */
  text: string;
  onText: (text: string) => void;
  /** cảnh báo của lần xuất (tham chiếu không còn tồn tại) */
  exportWarnings: readonly PolicyFinding[];
  /** undefined ⇒ chỉ xem (version không sửa được hoặc role không có quyền soạn) */
  onImported?: (source: PolicySource, principals: readonly PrincipalName[]) => void;
}

/** Xuất một nội dung thành HuJSON có tên (dùng khi bật chế độ HuJSON). */
export function useExport() {
  const { tenantId } = useTenant();
  return useMutation({
    mutationFn: (source: PolicySource) =>
      call(api.POST("/tenants/{tenantId}/policies/export", { params: { path: { tenantId } }, body: { source: toSourceBody(source) } })),
  });
}

const EMPTY_FINDING: PolicyFinding = { rule: "L2", severity: "error", code: "empty", message: "" };

export function HuJSONPanel({ text, onText, exportWarnings, onImported }: HuJSONPanelProps) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const id = useId();
  const [emptyError, setEmptyError] = useState(false);
  const imp = useMutation({
    mutationFn: (hujson: string) => call(api.POST("/tenants/{tenantId}/policies/import", { params: { path: { tenantId } }, body: { hujson } })),
    onSuccess: (r) => {
      if (r.result === "passed" && r.source && onImported) onImported(r.source, r.principals);
    },
  });
  const run = () => {
    if (text.trim() === "") {
      // L2: không gửi chuỗi rỗng (server cũng từ chối)
      setEmptyError(true);
      return;
    }
    setEmptyError(false);
    imp.mutate(text);
  };
  const result = imp.data;
  const failed = result?.result === "failed";
  return (
    <div className="space-y-3" data-testid="hujson-panel">
      <label htmlFor={`${id}-text`} className="label">
        {t("policies.hujson.label")}
      </label>
      <textarea
        id={`${id}-text`}
        className="input min-h-80 font-mono text-xs"
        spellCheck={false}
        autoComplete="off"
        readOnly={!onImported}
        value={text}
        aria-describedby={`${id}-hint`}
        aria-invalid={failed || emptyError}
        onChange={(e) => {
          onText(e.target.value);
          setEmptyError(false);
        }}
      />
      <p id={`${id}-hint`} className="hint">
        {t(onImported ? "policies.hujson.hint" : "policies.hujson.readOnlyHint")}
      </p>
      <FindingList findings={exportWarnings} label={t("policies.hujson.exportWarnings")} />
      {onImported ? (
        <div className="flex flex-wrap gap-2">
          <button type="button" className="btn-primary" disabled={imp.isPending} onClick={run}>
            {imp.isPending ? t("common.working") : t("policies.hujson.import")}
          </button>
        </div>
      ) : null}
      {emptyError ? (
        <div role="alert" data-testid="hujson-empty">
          <FindingList findings={[EMPTY_FINDING]} label={t("policies.hujson.errors")} />
        </div>
      ) : null}
      {imp.isError ? <ProblemAlert error={imp.error} /> : null}
      {result && failed ? (
        <div role="alert" className="space-y-2" data-testid="import-errors">
          <p className="font-semibold text-danger">{t("policies.hujson.failed", { count: result.errors.length })}</p>
          <FindingList findings={result.errors} label={t("policies.hujson.errors")} />
        </div>
      ) : null}
      {result?.result === "passed" ? (
        <p role="status" className="text-sm" data-testid="import-ok">
          {t("policies.hujson.imported")}
        </p>
      ) : null}
    </div>
  );
}
