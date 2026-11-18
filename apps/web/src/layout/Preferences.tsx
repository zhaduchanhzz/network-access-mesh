// Chọn ngôn ngữ (vi/en) và giao diện (theo hệ thống/sáng/tối) — <select> gốc: có sẵn ARIA và điều hướng bàn phím.
import { useId } from "react";
import { useTranslation } from "react-i18next";
import { isLanguage, LANGUAGES, setLanguage } from "../i18n";
import { useTheme, type ThemeChoice } from "../theme/theme";

const THEMES: readonly ThemeChoice[] = ["system", "light", "dark"];

export function Preferences() {
  const { t, i18n } = useTranslation();
  const theme = useTheme();
  const langId = useId();
  const themeId = useId();
  return (
    <div className="flex flex-wrap items-center gap-3 text-sm">
      <label htmlFor={langId} className="sr-only">
        {t("prefs.language")}
      </label>
      <select
        id={langId}
        className="select"
        value={i18n.language}
        onChange={(e) => {
          if (isLanguage(e.target.value)) setLanguage(e.target.value);
        }}
      >
        {LANGUAGES.map((l) => (
          <option key={l} value={l} lang={l}>
            {t(`prefs.languages.${l}`)}
          </option>
        ))}
      </select>
      <label htmlFor={themeId} className="sr-only">
        {t("prefs.theme")}
      </label>
      <select
        id={themeId}
        className="select"
        value={theme.choice}
        onChange={(e) => {
          const v = THEMES.find((x) => x === e.target.value);
          if (v) theme.setChoice(v);
        }}
      >
        {THEMES.map((x) => (
          <option key={x} value={x}>
            {t(`prefs.themes.${x}`)}
          </option>
        ))}
      </select>
    </div>
  );
}
