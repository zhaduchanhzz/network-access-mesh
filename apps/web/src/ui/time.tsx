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

/** Lệch dưới ngưỡng này (giây) ⇒ "bây giờ": lệch đồng hồ máy ↔ server và độ trễ mạng không thành "sau 2 giây nữa". */
export const NOW_TOLERANCE_S = 10;

/** "Bây giờ" thật để so: `useNow()` chỉ đổi mỗi 30 s, nên mốc vừa trả về từ server có thể mới hơn nó (G4b-E8 — "sau 17
 * giây nữa" cho việc vừa xảy ra) ⇒ lấy giá trị muộn hơn của hai. */
export function freshNow(now: number): number {
  return Math.max(now, Date.now());
}

/** "5 phút trước" / "in 3 days" theo locale; |lệch| < NOW_TOLERANCE_S ⇒ "bây giờ"; ISO lạ ⇒ chuỗi rỗng. */
export function formatRelative(iso: string, lng: string, now: number = Date.now()): string {
  const at = Date.parse(iso);
  if (Number.isNaN(at)) return "";
  const raw = Math.round((at - now) / 1000);
  const diff = Math.abs(raw) < NOW_TOLERANCE_S ? 0 : raw;
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
  const rel = relative ? formatRelative(iso, i18n.language, freshNow(now)) : "";
  return (
    <time dateTime={iso} title={iso}>
      {formatDateTime(iso, i18n.language)}
      {rel ? <span className="text-muted">{` (${rel})`}</span> : null}
    </time>
  );
}

/** Câu "chưa có lần nào" của từng nhãn "… lúc" (G4b-E9: không ghép "lúc" + "chưa từng" ⇒ "lúc chưa từng"). */
const NEVER_KEYS: Readonly<Record<string, string>> = {
  "ui.syncedAt": "ui.syncedNever",
  "ui.checkedAt": "ui.checkedNever",
  "diagnostics.readAt": "diagnostics.readNever",
};

/** Dòng "Đồng bộ lúc …" / "Kiểm lúc …" đi kèm số liệu; chưa có mốc ⇒ một câu riêng ("Chưa đồng bộ lần nào"). */
export function ObservedAt({ labelKey, iso, neverKey }: { labelKey: string; iso: string | null | undefined; neverKey?: string }) {
  const { t } = useTranslation();
  if (!iso) {
    return (
      <p className="mt-1 text-xs text-muted" data-testid="observed-never">
        {t(neverKey ?? NEVER_KEYS[labelKey] ?? "ui.observedNever")}
      </p>
    );
  }
  return (
    <p className="mt-1 text-xs text-muted">
      {t(labelKey)} <Timestamp iso={iso} />
    </p>
  );
}
