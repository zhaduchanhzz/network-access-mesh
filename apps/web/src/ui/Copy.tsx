// Sao chép vào clipboard (P4-T08: lệnh cài đặt, login server, pre-auth key một lần). Chỉ ghi clipboard khi người dùng
// bấm (navigator.clipboard — cần secure context); kết quả báo qua vùng live (a11y). Không giữ bản sao nào của giá trị.
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

export function CopyButton({ value, label, testId }: { value: string; label: string; testId?: string }) {
  const { t } = useTranslation();
  const [result, setResult] = useState<"ok" | "fail" | null>(null);
  useEffect(() => {
    if (result === null) return;
    const id = window.setTimeout(() => {
      setResult(null);
    }, 4000);
    return () => {
      window.clearTimeout(id);
    };
  }, [result]);
  const copy = () => {
    // ngoài secure context trình duyệt không có navigator.clipboard
    const clip = (navigator as { clipboard?: Clipboard }).clipboard;
    if (!clip) {
      setResult("fail");
      return;
    }
    clip.writeText(value).then(
      () => {
        setResult("ok");
      },
      () => {
        setResult("fail");
      },
    );
  };
  return (
    <span className="inline-flex items-center gap-2">
      <button type="button" className="btn-secondary" aria-label={label} data-testid={testId} onClick={copy}>
        {t("ui.copy")}
      </button>
      <span role="status" className="text-xs text-muted">
        {result === "ok" ? t("ui.copied") : result === "fail" ? t("ui.copyFailed") : ""}
      </span>
    </span>
  );
}

/** Lệnh/giá trị một dòng hoặc nhiều dòng, cuộn được bằng bàn phím, kèm nút sao chép. */
export function CodeLine({ value, copyLabel, testId }: { value: string; copyLabel: string; testId?: string }) {
  return (
    <div className="flex flex-wrap items-start gap-2">
      <pre tabIndex={0} className="min-w-0 flex-1 overflow-x-auto rounded-md border border-line bg-bg p-2 font-mono text-xs whitespace-pre-wrap break-all" data-testid={testId}>
        <code>{value}</code>
      </pre>
      <CopyButton value={value} label={copyLabel} />
    </div>
  );
}
