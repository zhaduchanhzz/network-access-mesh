// Công cụ chung của các spec enrollment (G4b — P4-T14): tạo yêu cầu web-auth ở wizard, tìm hàng của RequestTable theo
// nhãn, đóng các vai trò phụ.
import type { Locator, Page } from "@playwright/test";
import { clickUntil, expect, lit, T, type Actor, type Lng } from "./support";

/** Wizard (Linux, web-auth) với nhãn ⇒ bấm "Tạo lệnh đăng ký" (429 ⇒ bấm lại); `done` là kết quả mong đợi. */
export async function requestWebAuth(page: Page, lng: Lng, label: string, done: Locator): Promise<void> {
  const wizard = page.getByTestId("enroll-wizard");
  await wizard.getByRole("radio", { name: "Linux", exact: true }).check();
  await expect(wizard.getByTestId("instructions")).toHaveAttribute("data-os", "linux", { timeout: 60_000 });
  const web = wizard.getByRole("radio", { name: lit(T(lng, "enroll.method.web_auth")) });
  await expect(web).toBeEnabled();
  await web.check();
  await wizard.getByLabel(T(lng, "enroll.wizard.label")).fill(label);
  await clickUntil(page, lng, wizard.getByRole("button", { name: T(lng, "enroll.wizard.submitWeb") }), done);
}

/** Hàng của một yêu cầu (theo nhãn) trong một bảng của RequestTable. */
export function row(table: Locator, label: string): Locator {
  return table.getByTestId("enroll-row").filter({ has: table.page().getByText(label, { exact: true }) });
}

export async function closeAll(actors: (Actor | null)[]): Promise<void> {
  for (const a of actors) await a?.context.close().catch(() => undefined);
}
