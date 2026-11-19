// Form sửa ràng buộc claim của một IdP (PATCH /platform/identity-providers/{id} — §8.2 MVP: claim_mapping,
// required_claims, allowed_email_domains; issuer/client_id/driver bất biến, không bao giờ gửi). Kiểm tra mirror
// internal/config/idpclaims.go (cách callback đăng nhập đọc chúng) — chỉ để hướng dẫn; server quyết định (422).
import type { components } from "../../api/schema";

type IdP = components["schemas"]["IdentityProvider"];
export type IdpUpdate = components["schemas"]["IdentityProviderUpdate"];

export const MAPPED_FIELDS = ["email", "email_verified", "name"] as const;
const CLAIM_NAME_RE = /^[A-Za-z0-9_.:/-]{1,128}$/;
const DOMAIN_RE = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const RESERVED = new Set(["sub", "iss", "aud"]);

export interface IdpForm {
  mapping: Record<(typeof MAPPED_FIELDS)[number], string>;
  requiredClaims: string;
  domains: string;
}

export type IdpErrors = Partial<Record<"mapping" | "requiredClaims" | "domains", string>>;

export function formOf(idp: IdP): IdpForm {
  return {
    mapping: {
      email: idp.claim_mapping.email ?? "",
      email_verified: idp.claim_mapping.email_verified ?? "",
      name: idp.claim_mapping.name ?? "",
    },
    requiredClaims: JSON.stringify(idp.required_claims, null, 2),
    domains: idp.allowed_email_domains.join("\n"),
  };
}

function scalarOk(v: unknown): boolean {
  return (typeof v === "string" && v !== "" && v.length <= 256) || typeof v === "boolean" || (typeof v === "number" && Number.isFinite(v));
}

/** required_claims hợp lệ ⇒ object; sai ⇒ null. */
export function parseRequiredClaims(raw: string): Record<string, unknown> | null {
  let v: unknown;
  try {
    v = JSON.parse(raw.trim() === "" ? "{}" : raw);
  } catch {
    return null;
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  const m = v as Record<string, unknown>;
  const keys = Object.keys(m);
  if (keys.length > 16) return null;
  for (const k of keys) {
    if (!CLAIM_NAME_RE.test(k) || RESERVED.has(k)) return null;
    const x = m[k];
    if (Array.isArray(x)) {
      if (x.length === 0 || x.length > 32 || !x.every(scalarOk)) return null;
    } else if (!scalarOk(x)) return null;
  }
  return m;
}

export function parseDomains(raw: string): string[] | null {
  const list = [...new Set(raw.split(/[\s,]+/).map((d) => d.trim().toLowerCase()).filter(Boolean))].sort();
  if (list.length > 32 || list.some((d) => d.length > 253 || !DOMAIN_RE.test(d))) return null;
  return list;
}

function sameJson(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function sortedObject<T>(m: Record<string, T>): Record<string, T> {
  return Object.fromEntries(Object.entries(m).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

/** Lỗi theo trường (khóa i18n) + body chỉ gồm trường đã đổi (không bao giờ issuer/client_id/driver). */
export function idpUpdate(idp: IdP, f: IdpForm): { errors: IdpErrors; body: IdpUpdate } {
  const errors: IdpErrors = {};
  const body: IdpUpdate = {};
  const mapping: Record<string, string> = {};
  for (const k of MAPPED_FIELDS) {
    const v = f.mapping[k].trim();
    if (v === "") continue;
    if (!CLAIM_NAME_RE.test(v)) errors.mapping = "platform.idp.errors.mapping";
    mapping[k] = v;
  }
  if (!errors.mapping && !sameJson(sortedObject(mapping), sortedObject(idp.claim_mapping))) body.claim_mapping = mapping;
  const rc = parseRequiredClaims(f.requiredClaims);
  if (rc === null) errors.requiredClaims = "platform.idp.errors.requiredClaims";
  else if (!sameJson(sortedObject(rc), sortedObject(idp.required_claims))) body.required_claims = rc;
  const domains = parseDomains(f.domains);
  if (domains === null) errors.domains = "platform.idp.errors.domains";
  else if (!sameJson(domains, [...idp.allowed_email_domains].sort())) body.allowed_email_domains = domains;
  return { errors, body };
}
