// Hạ tầng UI dùng chung (P4-T04): thời điểm theo locale (§12.4) — tuyệt đối trong <time dateTime> + tương đối
// ("5 phút trước"). Dùng cho `synced_at` / `checked_at` (§13.1 độ tươi dữ liệu): mỗi số liệu kèm thời điểm quan sát.
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { formatDateTime } from "../i18n";

/** "Bây giờ" (ms) cập nhật mỗi `intervalMs` — render thuần, thời gian tương đối vẫn tươi. */
export function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const id = window.setInterval(() => {
      setNow(Date.now());
    }, intervalMs);
    return () => {
      window.clearInterval(id);
    };
  }, [intervalMs]);
  return now;
}

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["day", 86_400],
  ["hour", 3_600],
  ["minute", 60],
  ["second", 1],
];

/** "5 phút trước" / "in 3 days" theo locale; ISO lạ ⇒ chuỗi rỗng. */
export function formatRelative(iso: string, lng: string, now: number = Date.now()): string {
  const at = Date.parse(iso);
  if (Number.isNaN(at)) return "";
  const diff = Math.round((at - now) / 1000);
  const fmt = new Intl.RelativeTimeFormat(lng, { numeric: "auto" });
  for (const [unit, secs] of UNITS) {
    if (Math.abs(diff) >= secs || unit === "second") return fmt.format(Math.trunc(diff / secs), unit);
  }
  return "";
}

/** Thời điểm tuyệt đối + tương đối; `null` ⇒ `emptyKey` (ví dụ "chưa từng"). */
export function Timestamp({ iso, emptyKey = "ui.never", relative = true }: { iso: string | null | undefined; emptyKey?: string; relative?: boolean }) {
  const { t, i18n } = useTranslation();
  const now = useNow();
  if (!iso) return <span className="text-muted">{t(emptyKey)}</span>;
  const rel = relative ? formatRelative(iso, i18n.language, now) : "";
  return (
    <time dateTime={iso} title={iso}>
      {formatDateTime(iso, i18n.language)}
      {rel ? <span className="text-muted">{` (${rel})`}</span> : null}
    </time>
  );
}

/** Dòng "Đồng bộ lúc …" / "Kiểm lúc …" đi kèm số liệu. */
export function ObservedAt({ labelKey, iso }: { labelKey: string; iso: string | null | undefined }) {
  const { t } = useTranslation();
  return (
    <p className="mt-1 text-xs text-muted">
      {t(labelKey)} <Timestamp iso={iso} />
    </p>
  );
}
