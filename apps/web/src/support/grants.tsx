// Support Access Grant (P4-T13, §8.7) — phần dùng chung của hai phía: kiểu, danh sách trạng thái (kiểm bằng typecheck
// so với spec), nhãn trạng thái, các cột mô tả một grant. Trang của tenant: tenant/support; của platform: platform/support.
import { useTranslation } from "react-i18next";
import type { components } from "../api/schema";
import { StatusBadge } from "../ui/Status";
import { Timestamp } from "../ui/time";

export type SupportGrant = components["schemas"]["SupportGrant"];
export type SupportGrantList = components["schemas"]["SupportGrantList"];
export type SupportGrantStatus = components["schemas"]["SupportGrantStatus"];
export type SupportGrantRole = components["schemas"]["SupportGrantRole"];
export type SupportGrantCreate = components["schemas"]["SupportGrantCreate"];

export const GRANT_STATUSES = ["pending", "approved", "rejected", "revoked", "expired"] as const satisfies readonly SupportGrantStatus[];
export const GRANT_ROLES = ["support_operator", "support_admin"] as const satisfies readonly SupportGrantRole[];
/** Thời lượng đề xuất (phút) — trần 480 (8 giờ, CHECK của bảng). */
export const GRANT_DURATIONS = [30, 60, 120, 240, 480] as const;
export const GRANT_PAGE = 25;
type Assert<T extends true> = T;
/** Lỗi typecheck ⇒ spec thêm trạng thái/role chưa có ở đây (và chưa có bản dịch support.status.* / roles.*). */
export type AllGrantStatusesListed = Assert<[Exclude<SupportGrantStatus, (typeof GRANT_STATUSES)[number]>] extends [never] ? true : false>;
export type AllGrantRolesListed = Assert<[Exclude<SupportGrantRole, (typeof GRANT_ROLES)[number]>] extends [never] ? true : false>;

export function isGrantStatus(v: string): v is SupportGrantStatus {
  return (GRANT_STATUSES as readonly string[]).includes(v);
}

/** Grant còn đổi được (thu hồi): đang chờ hoặc đang hiệu lực. */
export function grantOpen(g: SupportGrant): boolean {
  return g.status === "pending" || g.status === "approved";
}

export function GrantStatusBadge({ grant: g }: { grant: SupportGrant }) {
  const { t } = useTranslation();
  return (
    <span className="inline-flex flex-wrap gap-1">
      <StatusBadge status={g.status} testId="grant-status">
        {t(`support.status.${g.status}`)}
      </StatusBadge>
      {g.active ? <StatusBadge tone="info">{t("support.activeNow")}</StatusBadge> : null}
      {g.approval_kind === "breakglass" ? (
        <StatusBadge tone="danger" testId="grant-breakglass">
          {t("support.breakglass")}
        </StatusBadge>
      ) : null}
    </span>
  );
}

/** Cửa sổ thời gian của grant (≤ 8 giờ). */
export function GrantWindow({ grant: g }: { grant: SupportGrant }) {
  const { t } = useTranslation();
  return (
    <div className="space-y-0.5 text-xs">
      <div>
        {t("support.from")} <Timestamp iso={g.starts_at} relative={false} />
      </div>
      <div>
        {t("support.until")} <Timestamp iso={g.expires_at} />
      </div>
      {g.revoked_at ? (
        <div>
          {t("support.revokedAt")} <Timestamp iso={g.revoked_at} relative={false} />
        </div>
      ) : null}
    </div>
  );
}

/** Lý do + ticket (văn bản của người xin — hiển thị nguyên văn, không HTML). */
export function GrantReason({ grant: g }: { grant: SupportGrant }) {
  return (
    <div className="max-w-xs space-y-1">
      <code className="text-xs">{g.ticket_ref}</code>
      <p className="text-sm whitespace-pre-wrap break-words">{g.reason}</p>
    </div>
  );
}
