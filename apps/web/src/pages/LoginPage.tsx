// Đăng nhập (§8.3 bước 1): Tenant Portal hỏi slug của tenant (chỉ dùng để định tuyến đăng nhập — IdP được chọn ở
// server theo tenant, không nhận từ client); Platform Console đăng nhập phạm vi platform (luôn prompt=login, MFA).
// Slug sai (a11y — P4-T14-prep mục 6.3): lỗi nằm trong vùng role="alert" có sẵn từ đầu (trình đọc màn hình đọc ngay khi
// bấm "Tiếp tục", kể cả lần bấm lặp lại), gắn với ô nhập qua aria-describedby + aria-errormessage, focus về ô nhập.
// Lỗi bắt đầu đăng nhập (G4b-E2): GET /auth/login là điều hướng của trình duyệt (rời SPA); tenant không tồn tại / không
// cho đăng nhập ⇒ server chuyển hướng về `/login?error=tenant_not_found&tenant=<slug>` (một mã cho mọi trường hợp — không
// lộ tenant có tồn tại hay không). Trang hiện câu đã dịch trong cùng vùng alert, điền lại slug, focus ô nhập để sửa và
// thử lại; mã `error` lạ ⇒ câu chung. Không bao giờ hiện giá trị `error` nguyên văn.
import { useEffect, useId, useRef, useState } from "react";
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
  // lỗi do server trả về qua ?error= (chỉ ở lần mở trang; sửa ô nhập hoặc bấm lại ⇒ bỏ)
  const [startError, setStartError] = useState<"tenantNotFound" | "startFailed" | null>(() => startErrorOf(params.get("error")));
  // mỗi lần bấm "Tiếp tục" với slug sai là một lỗi mới: nội dung vùng alert được thay (key) để được đọc lại
  const [attempt, setAttempt] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const inputId = useId();
  const hintId = useId();
  const errorId = useId();
  useDocumentTitle(t("login.title"));
  const pending = session.isPending;
  useEffect(() => {
    // ô nhập có mặt sau khi biết chưa có phiên: lỗi từ server ⇒ đưa focus vào ô để sửa slug
    if (!pending && startError !== null) inputRef.current?.focus();
  }, [pending, startError]);

  if (session.isPending) return <Loading />;
  if (session.data) return <Navigate to={returnTo ?? "/"} replace />;

  const submit = () => {
    if (kind === "tenant") {
      const s = slug.trim().toLowerCase();
      setStartError(null);
      if (!SLUG_RE.test(s)) {
        setInvalid(true);
        setAttempt((n) => n + 1);
        inputRef.current?.focus();
        return;
      }
      startLogin({ console: kind, tenantSlug: s, returnTo });
    } else {
      setStartError(null);
      startLogin({ console: kind, returnTo });
    }
  };
  const errorText = invalid ? t("login.tenantInvalid") : startError ? t(`login.errors.${startError}`) : null;

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
                  ref={inputRef}
                  id={inputId}
                  name="tenant"
                  className="input mt-1"
                  autoComplete="organization"
                  autoCapitalize="none"
                  spellCheck={false}
                  value={slug}
                  aria-invalid={errorText !== null}
                  aria-describedby={errorText !== null ? errorId : hintId}
                  aria-errormessage={errorText !== null ? errorId : undefined}
                  onChange={(e) => {
                    setSlug(e.target.value);
                    setInvalid(false);
                    setStartError(null);
                  }}
                />
                {errorText !== null ? null : (
                  <p id={hintId} className="mt-1 text-sm text-muted">
                    {t("login.tenantHint")}
                  </p>
                )}
                {/* vùng alert luôn có trong DOM (rỗng khi hợp lệ) — nội dung chèn vào mới được đọc tin cậy */}
                <p id={errorId} role="alert" className={errorText !== null ? "mt-1 text-sm text-danger" : undefined} data-testid="login-error">
                  {errorText !== null ? <span key={attempt}>{errorText}</span> : null}
                </p>
              </div>
            ) : (
              <>
                <p className="text-sm text-muted">{t("login.platformHint")}</p>
                <p role="alert" className={startError ? "text-sm text-danger" : undefined} data-testid="login-error">
                  {startError ? t("login.errors.startFailed") : null}
                </p>
              </>
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

/** Mã `error` của server ⇒ khóa thông báo; vắng ⇒ null; mã lạ ⇒ câu chung (không hiện mã nguyên văn). */
function startErrorOf(code: string | null): "tenantNotFound" | "startFailed" | null {
  if (code === null || code === "") return null;
  return code === "tenant_not_found" ? "tenantNotFound" : "startFailed";
}
