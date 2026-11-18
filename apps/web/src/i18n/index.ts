// i18n (§12.4): catalog vi + en đóng gói cùng bản build (không tải từ mạng). Không chuỗi giao diện hardcode — eslint
// meshguard/no-literal-ui-string và test src/i18n/i18n.test.ts. Tiếng Việt không có dạng số nhiều: i18next dùng
// Intl.PluralRules ⇒ chỉ khóa `_other` (ST-03); tiếng Anh có `_one` + `_other`.
import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import en from "./locales/en.json";
import vi from "./locales/vi.json";
import { readPref, writePref } from "../prefs";

export const LANGUAGES = ["vi", "en"] as const;
export type Language = (typeof LANGUAGES)[number];
export const DEFAULT_LANGUAGE: Language = "vi";

export function isLanguage(v: unknown): v is Language {
  return (LANGUAGES as readonly unknown[]).includes(v);
}

/** Ngôn ngữ đã chọn tay; nếu chưa chọn, ngôn ngữ đầu tiên của trình duyệt mà SPA hỗ trợ; mặc định tiếng Việt. */
export function detectLanguage(): Language {
  const chosen = readPref("lang");
  if (chosen) return chosen;
  for (const tag of navigator.languages) {
    const base = tag.toLowerCase().split("-")[0];
    if (isLanguage(base)) return base;
  }
  return DEFAULT_LANGUAGE;
}

export function initI18n(lng: Language = detectLanguage()): typeof i18n {
  if (!i18n.isInitialized) {
    void i18n.use(initReactI18next).init({
      resources: { vi: { translation: vi }, en: { translation: en } },
      lng,
      fallbackLng: DEFAULT_LANGUAGE,
      supportedLngs: [...LANGUAGES],
      interpolation: { escapeValue: false }, // React tự escape
      returnEmptyString: false,
      initAsync: false,
    });
    i18n.on("languageChanged", (l) => {
      document.documentElement.lang = l;
    });
  } else if (i18n.language !== lng) {
    void i18n.changeLanguage(lng);
  }
  document.documentElement.lang = lng;
  return i18n;
}

export function setLanguage(lng: Language): void {
  writePref("lang", lng);
  void i18n.changeLanguage(lng);
}

export function formatDateTime(iso: string, lng: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat(lng, { dateStyle: "medium", timeStyle: "short" }).format(d);
}

export { i18n };
