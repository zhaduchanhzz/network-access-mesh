// Một danh sách phát hiện (lint L1–L13, decoder guard, CheckPolicy, lỗi dịch HuJSON — P4-T11): mức, đường dẫn, dòng,
// thông điệp đã dịch theo `code` (không có bản dịch ⇒ thông điệp của server) là câu chính; mã luật + mã phát hiện chỉ ở
// dòng "chi tiết kỹ thuật" nhỏ (G4b-E11 — người vận hành vẫn đối chiếu được); cờ cần xác nhận / chỉ Owner / đã xác nhận.
// Màu chỉ là phụ — chữ luôn nói mức (WCAG 1.4.1).
import { useTranslation } from "react-i18next";
import { StatusBadge } from "../../ui/Status";
import { baseCode, type PolicyFinding } from "./model";

export function FindingList({ findings, label }: { findings: readonly PolicyFinding[]; label?: string }) {
  const { t, i18n } = useTranslation();
  if (findings.length === 0) return null;
  return (
    <ul className="space-y-1.5 text-sm" aria-label={label ?? t("policies.report.findings")} data-testid="findings">
      {findings.map((f, i) => {
        const key = `policies.finding.${baseCode(f.code)}`;
        const text = i18n.exists(key) ? t(key) : f.message;
        return (
          <li
            key={`${f.rule}:${f.code}:${f.path ?? ""}:${String(i)}`}
            className="rounded-md border border-line p-2"
            data-rule={f.rule}
            data-code={f.code}
            data-severity={f.severity}
          >
            <span className="flex flex-wrap items-center gap-1.5">
              <StatusBadge tone={f.severity === "error" ? "danger" : f.severity === "warning" ? "warn" : "info"}>
                {t(`policies.severity.${f.severity}`)}
              </StatusBadge>
              {f.path ? <code className="text-xs">{f.path}</code> : null}
              {f.line ? <span className="text-xs text-muted">{t("policies.report.line", { line: f.line })}</span> : null}
              {f.requires_ack ? <span className="badge badge-warn">{t(f.acknowledged ? "policies.report.acknowledged" : "policies.report.needsAck")}</span> : null}
              {f.owner_only ? <span className="badge">{t("policies.ack.ownerOnly")}</span> : null}
            </span>
            <span className="mt-1 block">{text}</span>
            <span className="block font-mono text-xs text-muted" data-testid="finding-technical">
              {t("policies.report.technical", { rule: f.rule, code: f.code })}
            </span>
          </li>
        );
      })}
    </ul>
  );
}
