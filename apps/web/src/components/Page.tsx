import { useEffect, useRef, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { useLocation } from "react-router";

/** `state` của một điều hướng sau thao tác trong hộp thoại (mời, tạo group…): hộp đóng và route đổi ⇒ focus không còn
 * nút mở để trở về, nên trang mới đưa focus vào `h1` của nó — trình đọc màn hình đọc tên trang mới (G4b-E17). */
export const FOCUS_HEADING = { focusHeading: true } as const;

function wantsHeadingFocus(state: unknown): boolean {
  return typeof state === "object" && state !== null && (state as { focusHeading?: unknown }).focusHeading === true;
}

/** Tiêu đề tài liệu "<trang> · MeshGuard" (đổi theo ngôn ngữ). */
export function useDocumentTitle(title: string): void {
  const { t } = useTranslation();
  const app = t("app.name");
  useEffect(() => {
    document.title = title ? `${title} · ${app}` : app;
  }, [title, app]);
}

export function Page({ title, children, actions }: { title: string; children?: ReactNode; actions?: ReactNode }) {
  useDocumentTitle(title);
  const location = useLocation();
  const heading = useRef<HTMLHeadingElement>(null);
  const focusHeading = wantsHeadingFocus(location.state);
  useEffect(() => {
    if (focusHeading) heading.current?.focus();
  }, [focusHeading, location.key]);
  return (
    <section aria-labelledby="page-title" className="mx-auto w-full max-w-5xl">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <h1 id="page-title" ref={heading} tabIndex={-1} className="text-2xl font-semibold tracking-tight focus:outline-none">
          {title}
        </h1>
        {actions}
      </div>
      {children}
    </section>
  );
}

export function Loading() {
  const { t } = useTranslation();
  return (
    <p role="status" aria-live="polite" className="p-6 text-muted">
      {t("common.loading")}
    </p>
  );
}
