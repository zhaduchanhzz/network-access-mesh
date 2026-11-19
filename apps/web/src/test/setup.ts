import "@testing-library/jest-dom/vitest";
import { cleanup, configure } from "@testing-library/react";
import { afterEach, beforeEach, vi } from "vitest";
import { setCsrfToken } from "../api/client";
import { i18n, initI18n } from "../i18n";

// jsdom không có matchMedia: mặc định hệ điều hành ở chế độ sáng; test đổi qua setSystemDark().
let systemDark = false;
const mqListeners = new Set<(e: MediaQueryListEvent) => void>();
export function setSystemDark(dark: boolean): void {
  systemDark = dark;
  for (const l of mqListeners) l({ matches: dark, media: "(prefers-color-scheme: dark)" } as MediaQueryListEvent);
}
Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    get matches() {
      return query.includes("dark") ? systemDark : false;
    },
    media: query,
    onchange: null,
    addEventListener: (_: string, l: (e: MediaQueryListEvent) => void) => mqListeners.add(l),
    removeEventListener: (_: string, l: (e: MediaQueryListEvent) => void) => mqListeners.delete(l),
    addListener: () => undefined,
    removeListener: () => undefined,
    dispatchEvent: () => false,
  }),
});

initI18n("vi");

// Màn hình Platform Console tải theo route (`lazy` — import động): lần đầu Vitest phải transform module, trên runner chậm
// hoặc khi nhiều file chạy song song có thể quá 1 s mặc định của findBy*/waitFor (P4-T02).
configure({ asyncUtilTimeout: 5000 });

beforeEach(async () => {
  localStorage.clear();
  sessionStorage.clear();
  systemDark = false;
  mqListeners.clear();
  setCsrfToken(null);
  delete document.documentElement.dataset.theme;
  if (i18n.language !== "vi") await i18n.changeLanguage("vi");
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
