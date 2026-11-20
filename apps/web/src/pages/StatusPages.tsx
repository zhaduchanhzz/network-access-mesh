// Trang trạng thái dùng chung:
// - NotFoundPage: 404 THỐNG NHẤT — cùng một nội dung cho đường dẫn lạ, tenant không thuộc người gọi, Platform Console
//   trên app., ID của tenant khác (§8.4 bất biến 6: không lộ sự tồn tại).
// - ForbiddenPage: đã ở trong tenant/console nhưng role không có quyền xem màn hình này.
// - UnavailablePage: màn hình chưa xây (task ở §20) hoặc thuộc giai đoạn sau MVP — không có số liệu giả (§12.4).
// - RouteErrorPage: lỗi khi render route (errorElement của router).
import { useTranslation } from "react-i18next";
import { Link, isRouteErrorResponse, useRouteError } from "react-router";
import { ApiError } from "../api/problem";
import type { NavItem } from "../nav/navModel";
import { Page } from "../components/Page";
import { ProblemAlert } from "../components/ProblemAlert";

export function NotFoundPage() {
  const { t } = useTranslation();
  return (
    <Page title={t("notFound.title")}>
      <p className="text-muted">{t("notFound.description")}</p>
      <p className="mt-4">
        <Link to="/" className="link">
          {t("common.home")}
        </Link>
      </p>
    </Page>
  );
}

export function ForbiddenPage() {
  const { t } = useTranslation();
  return (
    <Page title={t("forbidden.title")}>
      <p className="text-muted">{t("forbidden.description")}</p>
      <p className="mt-4">
        <Link to="/" className="link">
          {t("common.home")}
        </Link>
      </p>
    </Page>
  );
}

export function UnavailablePage({ item }: { item: NavItem }) {
  const { t } = useTranslation();
  return (
    <Page title={t(item.labelKey)}>
      {/* mã task chỉ ở data-task (đối chiếu kế hoạch) — không hiện cho khách hàng (G4b-E11) */}
      <div className="rounded-md border border-dashed border-line bg-surface p-6" data-testid="unavailable" data-task={item.task}>
        <p className="font-medium">{t("unavailable.title")}</p>
        <p className="mt-1 text-sm text-muted">
          {item.phase === "post_mvp"
            ? t("unavailable.postMvp")
            : t("unavailable.planned")}
        </p>
      </div>
    </Page>
  );
}

export function RouteErrorPage() {
  const { t } = useTranslation();
  const error = useRouteError();
  if ((isRouteErrorResponse(error) && error.status === 404) || (error instanceof ApiError && error.status === 404)) {
    return (
      <main id="main" className="p-6">
        <NotFoundPage />
      </main>
    );
  }
  return (
    <main id="main" className="p-6">
      <Page title={t("error.title")}>
        <ProblemAlert error={error} />
        <p className="mt-4">
          <a href="/" className="link">
            {t("common.home")}
          </a>
        </p>
      </Page>
    </main>
  );
}
