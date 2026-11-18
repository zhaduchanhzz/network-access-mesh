// Phần hiển thị dùng chung của danh sách và chi tiết thiết bị (P4-T04). Không có cột hệ điều hành/phiên bản client:
// Headscale API không cung cấp (HS-14) — §12.3 "không hiển thị thay vì hiển thị giá trị giả".
import { useTranslation } from "react-i18next";
import { StatusBadge } from "../../ui/Status";
import { Timestamp, useNow } from "../../ui/time";
import { REVOCATION_TONE, type Device } from "./deviceModel";

export function RevocationBadge({ device }: { device: Device }) {
  const { t } = useTranslation();
  const r = device.revocation;
  if (r.state === "none") return null;
  const kind = r.kind ? t(`devices.revocation.kind.${r.kind}`) : "";
  return (
    <StatusBadge tone={REVOCATION_TONE[r.state]} testId="revocation-state">
      {t(`devices.revocation.state.${r.state}`, { kind })}
    </StatusBadge>
  );
}

export function OnlineBadge({ device }: { device: Device }) {
  const { t } = useTranslation();
  return (
    <StatusBadge tone={device.online ? "ok" : "neutral"}>{device.online ? t("devices.online") : t("devices.offline")}</StatusBadge>
  );
}

/** Hạn của node: `null` = không hết hạn; đã qua = đã hết hạn. */
export function ExpiryText({ device }: { device: Device }) {
  const { t } = useTranslation();
  const now = useNow();
  if (!device.expiry) return <StatusBadge tone={device.tags.length > 0 ? "warn" : "neutral"}>{t("devices.neverExpires")}</StatusBadge>;
  const expired = Date.parse(device.expiry) <= now;
  return (
    <span>
      {expired ? <StatusBadge tone="danger">{t("devices.expired")}</StatusBadge> : null} <Timestamp iso={device.expiry} />
    </span>
  );
}

export function OwnerText({ device }: { device: Device }) {
  const { t } = useTranslation();
  if (device.owner) return <span>{device.owner.display_name}</span>;
  return <span className="text-muted">{device.tags.length > 0 ? t("devices.ownedByTags") : t("devices.noOwner")}</span>;
}

export function TagList({ tags }: { tags: readonly string[] }) {
  const { t } = useTranslation();
  if (tags.length === 0) return <span className="text-muted">{t("devices.noTags")}</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {tags.map((tag) => (
        <code key={tag} className="badge">
          {tag}
        </code>
      ))}
    </span>
  );
}
