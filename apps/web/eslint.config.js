// ESLint (P4-T01): TypeScript có kiểm type, React hooks, và hai nhóm luật riêng của dự án:
// - meshguard/no-literal-ui-string: không chuỗi giao diện hardcode (§12.4 — i18n vi/en);
// - không Web Storage / cookie / IndexedDB ngoài src/prefs.ts, không fetch ngoài src/api/client.ts (§8.3 bước 4, §12.4:
//   không token trong browser storage; trình duyệt chỉ gọi /api/v1 cùng origin, không bao giờ gọi Headscale).
import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";
import noLiteralUiString from "./eslint-rules/no-literal-ui-string.js";

const storageGlobals = ["localStorage", "sessionStorage", "indexedDB", "caches", "cookieStore"].map((name) => ({
  name,
  message: "Chỉ src/prefs.ts được chạm Web Storage (không token/secret trong browser storage — §12.4)",
}));
const storageProps = [
  ...["localStorage", "sessionStorage", "indexedDB", "caches", "cookieStore"].map((property) => ({
    object: "window",
    property,
    message: "Chỉ src/prefs.ts được chạm Web Storage (§12.4)",
  })),
  { object: "document", property: "cookie", message: "Cookie session là HttpOnly — JavaScript không đọc/ghi cookie (§8.3)" },
  { object: "navigator", property: "serviceWorker", message: "Không service worker (không cache response chứa dữ liệu tenant)" },
];

export default defineConfig(
  { ignores: ["dist/**", "node_modules/**", "src/api/schema.d.ts", "src/auth/rbac.gen.ts"] },
  js.configs.recommended,
  {
    files: ["src/**/*.{ts,tsx}", "vite.config.ts"],
    extends: [tseslint.configs.strictTypeChecked],
    languageOptions: {
      globals: globals.browser,
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    plugins: { "react-hooks": reactHooks, meshguard: { rules: { "no-literal-ui-string": noLiteralUiString } } },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "meshguard/no-literal-ui-string": "error",
      "no-restricted-globals": ["error", ...storageGlobals, { name: "fetch", message: "Gọi API qua src/api/client.ts" }],
      "no-restricted-properties": [
        "error",
        ...storageProps,
        ...["window", "globalThis", "self"].map((object) => ({ object, property: "fetch", message: "Gọi API qua src/api/client.ts" })),
      ],
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
      "@typescript-eslint/no-confusing-void-expression": ["error", { ignoreArrowShorthand: true }],
    },
  },
  {
    files: ["src/prefs.ts"],
    rules: { "no-restricted-globals": "off", "no-restricted-properties": "off" },
  },
  {
    files: ["src/api/client.ts"],
    rules: { "no-restricted-globals": ["error", ...storageGlobals], "no-restricted-properties": ["error", ...storageProps] },
  },
  {
    files: ["src/**/*.test.{ts,tsx}", "src/test/**"],
    rules: {
      "meshguard/no-literal-ui-string": "off",
      "no-restricted-globals": "off",
      "no-restricted-properties": "off",
      "@typescript-eslint/no-non-null-assertion": "off",
    },
  },
  {
    // P4-T14: Playwright chạy trong Node (không phải SPA) — kiểm type chặt như src/, không áp luật chuỗi giao diện/storage
    files: ["e2e/**/*.ts", "playwright.config.ts"],
    extends: [tseslint.configs.strictTypeChecked],
    languageOptions: {
      globals: { ...globals.node, ...globals.browser },
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
      "@typescript-eslint/no-confusing-void-expression": ["error", { ignoreArrowShorthand: true }],
    },
  },
  {
    files: ["scripts/**/*.mjs", "eslint-rules/**/*.js", "eslint.config.js"],
    languageOptions: { globals: globals.node },
  },
);
