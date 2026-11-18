// Mô hình của màn hình Devices (P4-T04): bộ lọc ↔ query string của trang (deep link, nút Back), tham số của
// GET /tenants/{t}/devices (§13.1 tham số tường minh), trạng thái thu hồi hai pha (§13.3 Device.revocation, T-17).
import type { components } from "../../api/schema";
import type { Tone } from "../../ui/Status";

export type Device = components["schemas"]["Device"];
export type RevocationState = components["schemas"]["DeviceRevocation"]["state"];

/** Báo cáo rà soát định kỳ tagged node không hết hạn (§7.4, ADR-23). */
export const REVIEW_QUERY = { tagged: true, has_expiry: false } as const;

export const TAG_RE = /^tag:[a-z][a-z0-9-]{0,49}$/;
/** Nhãn DNS của `given_name` — cùng pattern với DeviceRename của spec. */
export const GIVEN_NAME_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
export const DEVICE_PAGE = 50;

export type TriState = "any" | "yes" | "no";

export interface DeviceFilters {
  q: string;
  online: TriState;
  tagged: TriState;
  expiry: TriState; // yes = có hạn, no = không hết hạn
  tag: string;
  mine: boolean;
  review: boolean;
}

function tri(v: string | null): TriState {
  return v === "yes" || v === "no" ? v : "any";
}

export function filtersFromParams(p: URLSearchParams): DeviceFilters {
  const review = p.get("view") === "review";
  return {
    q: (p.get("q") ?? "").slice(0, 64),
    online: tri(p.get("online")),
    tagged: review ? "yes" : tri(p.get("tagged")),
    expiry: review ? "no" : tri(p.get("expiry")),
    tag: p.get("tag") ?? "",
    mine: p.get("mine") === "1",
    review,
  };
}

export function paramsFromFilters(f: DeviceFilters): URLSearchParams {
  const p = new URLSearchParams();
  if (f.review) p.set("view", "review");
  if (f.q) p.set("q", f.q);
  if (f.online !== "any") p.set("online", f.online);
  if (!f.review && f.tagged !== "any") p.set("tagged", f.tagged);
  if (!f.review && f.expiry !== "any") p.set("expiry", f.expiry);
  if (f.tag) p.set("tag", f.tag);
  if (f.mine) p.set("mine", "1");
  return p;
}

function bool(v: TriState): boolean | undefined {
  return v === "any" ? undefined : v === "yes";
}

export interface DeviceListQuery {
  limit: number;
  q?: string;
  online?: boolean;
  tagged?: boolean;
  has_expiry?: boolean;
  tag?: string;
  owner?: string;
}

/** Tham số API của bộ lọc; tag sai dạng bị bỏ (ô nhập báo lỗi riêng) thay vì gửi một request chắc chắn 422. */
export function apiQuery(f: DeviceFilters, membershipId: string | null): DeviceListQuery {
  const q: DeviceListQuery = { limit: DEVICE_PAGE };
  if (f.q.trim()) q.q = f.q.trim();
  const online = bool(f.online);
  if (online !== undefined) q.online = online;
  const tagged = bool(f.tagged);
  if (tagged !== undefined) q.tagged = tagged;
  const expiry = bool(f.expiry);
  if (expiry !== undefined) q.has_expiry = expiry;
  if (TAG_RE.test(f.tag)) q.tag = f.tag;
  if (f.mine && membershipId) q.owner = membershipId;
  return q;
}

export const REVOCATION_TONE: Record<RevocationState, Tone> = { none: "neutral", pending: "warn", applied: "ok", failed: "danger" };

/** Thiết bị đang chờ thu hồi ⇒ màn hình poll tới khi `applied`/`failed` (UI chỉ báo "đã áp dụng" khi applied — T-17). */
export function revocationPending(d: Pick<Device, "revocation"> | undefined): boolean {
  return d?.revocation.state === "pending";
}
