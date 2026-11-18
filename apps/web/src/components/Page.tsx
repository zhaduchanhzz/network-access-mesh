import { useEffect, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

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
  return (
    <section aria-labelledby="page-title" className="mx-auto w-full max-w-5xl">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <h1 id="page-title" className="text-2xl font-semibold tracking-tight">
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
