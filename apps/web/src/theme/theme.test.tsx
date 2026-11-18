import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { Preferences } from "../layout/Preferences";
import { setSystemDark } from "../test/setup";
import { ThemeProvider } from "./theme";

function renderPrefs() {
  return render(
    <ThemeProvider>
      <Preferences />
    </ThemeProvider>,
  );
}

describe("theme", () => {
  it("mặc định theo prefers-color-scheme và đổi theo hệ thống", () => {
    setSystemDark(true);
    renderPrefs();
    expect(document.documentElement.dataset.theme).toBe("dark");
    act(() => {
      setSystemDark(false);
    });
    expect(document.documentElement.dataset.theme).toBe("light");
  });

  it("chọn tay thắng hệ thống và được nhớ (chỉ giá trị light/dark/system)", async () => {
    setSystemDark(true);
    const { unmount } = renderPrefs();
    await userEvent.selectOptions(screen.getByLabelText("Giao diện"), "light");
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(localStorage.getItem("mg.pref.theme")).toBe("light");
    unmount();
    renderPrefs();
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(screen.getByLabelText<HTMLSelectElement>("Giao diện").value).toBe("light");
  });

  it("giá trị lạ trong storage bị bỏ qua", () => {
    localStorage.setItem("mg.pref.theme", "<script>");
    setSystemDark(true);
    renderPrefs();
    expect(document.documentElement.dataset.theme).toBe("dark");
  });

  it("đổi ngôn ngữ cập nhật <html lang> và nhãn", async () => {
    renderPrefs();
    await userEvent.selectOptions(screen.getByLabelText("Ngôn ngữ"), "en");
    expect(document.documentElement.lang).toBe("en");
    expect(screen.getByLabelText("Theme")).toBeInTheDocument();
    expect(localStorage.getItem("mg.pref.lang")).toBe("en");
  });
});
