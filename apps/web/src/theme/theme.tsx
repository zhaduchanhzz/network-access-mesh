// Dark/Light theo design token (§12.4): mặc định theo prefers-color-scheme của hệ điều hành, người dùng có thể chọn
// tay (lưu ở prefs — chỉ giá trị system/light/dark). Token màu nằm trong styles.css dưới [data-theme].
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { readPref, writePref } from "../prefs";

export type ThemeChoice = "system" | "light" | "dark";
export type ResolvedTheme = "light" | "dark";

const DARK_QUERY = "(prefers-color-scheme: dark)";

function systemTheme(): ResolvedTheme {
  return window.matchMedia(DARK_QUERY).matches ? "dark" : "light";
}

export function applyTheme(resolved: ResolvedTheme): void {
  document.documentElement.dataset.theme = resolved;
}

interface ThemeState {
  choice: ThemeChoice;
  resolved: ResolvedTheme;
  setChoice: (c: ThemeChoice) => void;
}

const ThemeContext = createContext<ThemeState | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [choice, setChoiceState] = useState<ThemeChoice>(() => readPref("theme") ?? "system");
  const [system, setSystem] = useState<ResolvedTheme>(systemTheme);

  useEffect(() => {
    const mq = window.matchMedia(DARK_QUERY);
    const onChange = (e: MediaQueryListEvent) => {
      setSystem(e.matches ? "dark" : "light");
    };
    mq.addEventListener("change", onChange);
    return () => {
      mq.removeEventListener("change", onChange);
    };
  }, []);

  const resolved: ResolvedTheme = choice === "system" ? system : choice;
  useEffect(() => {
    applyTheme(resolved);
  }, [resolved]);

  const setChoice = useCallback((c: ThemeChoice) => {
    writePref("theme", c);
    setChoiceState(c);
  }, []);

  const value = useMemo(() => ({ choice, resolved, setChoice }), [choice, resolved, setChoice]);
  return <ThemeContext value={value}>{children}</ThemeContext>;
}

export function useTheme(): ThemeState {
  const v = useContext(ThemeContext);
  if (!v) throw new Error("useTheme ngoài ThemeProvider");
  return v;
}
