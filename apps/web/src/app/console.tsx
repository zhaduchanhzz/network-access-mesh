// Một bản build SPA phục vụ hai origin (§8.3, §12.1): admin.<domain> là Platform Console, mọi origin khác
// (app.<domain>) là Tenant Portal. Cookie __Host- gắn theo host và server từ chối session của origin khác, nên SPA chỉ
// cần biết mình đang ở console nào để chọn luồng đăng nhập và điều hướng.
import { createContext, useContext, type ReactNode } from "react";

export type ConsoleKind = "tenant" | "platform";

export function consoleFromHost(hostname: string): ConsoleKind {
  return hostname.toLowerCase().startsWith("admin.") ? "platform" : "tenant";
}

const ConsoleContext = createContext<ConsoleKind>("tenant");

export function ConsoleProvider({ kind, children }: { kind: ConsoleKind; children: ReactNode }) {
  return <ConsoleContext value={kind}>{children}</ConsoleContext>;
}

export function useConsole(): ConsoleKind {
  return useContext(ConsoleContext);
}

/** Điều hướng ra khỏi SPA (đăng nhập/đăng xuất qua IdP) — top-level navigation, không fetch. Tách ra để test thay thế. */
export const browser = {
  assign(url: string): void {
    window.location.assign(url);
  },
};
