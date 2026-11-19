// Quyền của một role theo seed RBAC (rbac.gen.ts) — dùng để ẩn/hiện mục điều hướng. Ẩn ở frontend chỉ là UX; server
// quyết định ở mỗi request (§8.8, §12.1). Role lạ ⇒ không có quyền nào (fail-closed).
import { ROLE_PERMISSIONS } from "./rbac.gen";

export function can(role: string | null | undefined, permission: string): boolean {
  if (!role || !Object.hasOwn(ROLE_PERMISSIONS, role)) return false;
  const grants = ROLE_PERMISSIONS[role];
  return grants !== undefined && Object.hasOwn(grants, permission);
}

/** Như `can`, nhưng chỉ với phạm vi `any` (ô ○ "chỉ của mình" của §8.6 không tính). */
export function canAny(role: string | null | undefined, permission: string): boolean {
  return can(role, permission) && ROLE_PERMISSIONS[role ?? ""]?.[permission] === "any";
}
