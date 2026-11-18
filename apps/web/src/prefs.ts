// Nơi DUY NHẤT của SPA chạm tới Web Storage (eslint: no-restricted-globals; test src/security/storage.test.tsx).
// Chỉ lưu tùy chọn hiển thị (giao diện, ngôn ngữ) với giá trị thuộc tập cố định — không thể chứa token hay secret.
// Không có session, CSRF token, ID token, Headscale API key hay pre-auth key nào trong localStorage/sessionStorage
// (§8.3 bước 4, §12.4).
export const PREFS = {
  theme: { key: "mg.pref.theme", values: ["system", "light", "dark"] },
  lang: { key: "mg.pref.lang", values: ["vi", "en"] },
} as const;

export type PrefName = keyof typeof PREFS;
export type PrefValue<N extends PrefName> = (typeof PREFS)[N]["values"][number];
export const PREF_KEYS: readonly string[] = Object.values(PREFS).map((p) => p.key);

function allowed<N extends PrefName>(name: N, value: unknown): value is PrefValue<N> {
  return (PREFS[name].values as readonly unknown[]).includes(value);
}

export function readPref<N extends PrefName>(name: N): PrefValue<N> | null {
  try {
    const v = window.localStorage.getItem(PREFS[name].key);
    return allowed(name, v) ? v : null;
  } catch {
    return null; // storage bị chặn (chế độ riêng tư, chính sách trình duyệt) ⇒ dùng mặc định
  }
}

export function writePref<N extends PrefName>(name: N, value: PrefValue<N>): void {
  if (!allowed(name, value)) throw new Error(`giá trị không hợp lệ cho ${name}`);
  try {
    window.localStorage.setItem(PREFS[name].key, value);
  } catch {
    /* không lưu được thì chỉ áp dụng cho phiên hiện tại */
  }
}
