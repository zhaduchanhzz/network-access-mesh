// Đăng nhập (§8.3 bước 1): Tenant Portal hỏi slug của tenant (chỉ dùng để định tuyến đăng nhập — IdP được chọn ở
// server theo tenant, không nhận từ client); Platform Console đăng nhập phạm vi platform (luôn prompt=login, MFA).
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { Navigate, useSearchParams } from "react-router";
import { useConsole } from "../app/console";
import { safeReturnTo, SLUG_RE, startLogin, useSession } from "../auth/session";
import { Loading, useDocumentTitle } from "../components/Page";
import { ProblemAlert } from "../components/ProblemAlert";
import { Preferences } from "../layout/Preferences";

export function LoginPage() {
  const { t } = useTranslation();
  const kind = useConsole();
  const [params] = useSearchParams();
  const session = useSession();
  const returnTo = safeReturnTo(params.get("return_to"));
  const initialSlug = params.get("tenant") ?? "";
  const [slug, setSlug] = useState(SLUG_RE.test(initialSlug) ? initialSlug : "");
  const [invalid, setInvalid] = useState(false);
  const inputId = useId();
  const hintId = useId();
  useDocumentTitle(t("login.title"));

  if (session.isPending) return <Loading />;
  if (session.data) return <Navigate to={returnTo ?? "/"} replace />;

  const submit = () => {
    if (kind === "tenant") {
      const s = slug.trim().toLowerCase();
      if (!SLUG_RE.test(s)) {
        setInvalid(true);
        return;
      }
      startLogin({ console: kind, tenantSlug: s, returnTo });
    } else {
      startLogin({ console: kind, returnTo });
    }
  };

  return (
    <div className="flex min-h-screen flex-col bg-bg text-fg">
      <header className="flex items-center justify-end gap-3 p-4">
        <Preferences />
      </header>
      <main id="main" className="flex flex-1 items-start justify-center px-4 pt-12">
        <div className="w-full max-w-md rounded-lg border border-line bg-surface p-6 shadow-sm">
          <p className="text-sm font-medium text-muted">{t("app.name")}</p>
          <h1 className="mt-1 text-2xl font-semibold">
            {kind === "platform" ? t("login.platformHeading") : t("login.tenantHeading")}
          </h1>
          {params.get("reason") === "expired" ? (
            <p role="status" className="mt-3 rounded-md bg-warn-bg p-3 text-sm text-warn">
              {t("login.expired")}
            </p>
          ) : null}
          {session.isError ? (
            <div className="mt-4">
              <ProblemAlert error={session.error} onRetry={() => void session.refetch()} />
            </div>
          ) : null}
          <form
            className="mt-6 space-y-4"
            noValidate
            onSubmit={(e) => {
              e.preventDefault();
              submit();
            }}
          >
            {kind === "tenant" ? (
              <div>
                <label htmlFor={inputId} className="block text-sm font-medium">
                  {t("login.tenantLabel")}
                </label>
                <input
                  id={inputId}
                  name="tenant"
                  className="input mt-1"
                  autoComplete="organization"
                  autoCapitalize="none"
                  spellCheck={false}
                  value={slug}
                  aria-invalid={invalid}
                  aria-describedby={hintId}
                  onChange={(e) => {
                    setSlug(e.target.value);
                    setInvalid(false);
                  }}
                />
                <p id={hintId} className={invalid ? "mt-1 text-sm text-danger" : "mt-1 text-sm text-muted"}>
                  {invalid ? t("login.tenantInvalid") : t("login.tenantHint")}
                </p>
              </div>
            ) : (
              <p className="text-sm text-muted">{t("login.platformHint")}</p>
            )}
            <button type="submit" className="btn-primary w-full">
              {t("login.submit")}
            </button>
          </form>
        </div>
      </main>
    </div>
  );
}
