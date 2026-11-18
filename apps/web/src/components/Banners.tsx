// Banner toàn cục: step-up (401 reauth_required), rate limit (429 + Retry-After), bảo trì (503 maintenance).
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useLocation } from "react-router";
import { useConsole } from "../app/console";
import { useNotices } from "../app/notices";
import { startLogin, useSession } from "../auth/session";

const TENANT_ROUTE_RE = /^\/t\/([0-9a-f-]{36})(?:\/|$)/i;

export function StepUpPrompt() {
  const { t } = useTranslation();
  const notices = useNotices();
  const kind = useConsole();
  const location = useLocation();
  const session = useSession().data;
  if (!notices.stepUp) return null;
  const tenantId = TENANT_ROUTE_RE.exec(location.pathname)?.[1];
  const slug =
    session?.memberships.find((m) => m.tenant_id === tenantId)?.tenant_slug ?? session?.memberships[0]?.tenant_slug;
  const reauth = () => {
    startLogin({
      console: kind,
      tenantSlug: kind === "tenant" ? (slug ?? null) : null,
      returnTo: location.pathname + location.search,
      reauth: true,
    });
  };
  return (
    <div role="alertdialog" aria-labelledby="stepup-title" aria-describedby="stepup-desc" className="banner banner-warn">
      <div>
        <p id="stepup-title" className="font-semibold">
          {t("stepUp.title")}
        </p>
        <p id="stepup-desc" className="text-sm">
          {t("stepUp.description")}
        </p>
      </div>
      <div className="flex gap-2">
        <button type="button" className="btn-primary" onClick={reauth}>
          {t("stepUp.action")}
        </button>
        <button type="button" className="btn-secondary" onClick={notices.dismissStepUp}>
          {t("common.dismiss")}
        </button>
      </div>
    </div>
  );
}

/** Đếm ngược tới `until`; được mount lại (key) mỗi lần có 429 mới nên mốc "bây giờ" luôn mới. */
function Countdown({ until }: { until: number }) {
  const { t } = useTranslation();
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const id = window.setInterval(() => {
      setNow(Date.now());
    }, 1000);
    return () => {
      window.clearInterval(id);
    };
  }, []);
  const left = Math.max(0, Math.ceil((until - now) / 1000));
  return <p>{left > 0 ? t("rateLimit.wait", { count: left }) : t("rateLimit.ready")}</p>;
}

export function RateLimitNotice() {
  const { t } = useTranslation();
  const notices = useNotices();
  if (notices.rateLimitedUntil === null) return null;
  return (
    <div role="status" className="banner banner-warn">
      <Countdown key={notices.rateLimitedUntil} until={notices.rateLimitedUntil} />
      <button type="button" className="btn-secondary" onClick={notices.dismissRateLimit}>
        {t("common.dismiss")}
      </button>
    </div>
  );
}

export function MaintenanceBanner() {
  const { t } = useTranslation();
  const notices = useNotices();
  if (!notices.maintenance) return null;
  return (
    <div role="status" className="banner banner-warn">
      <p>{t("maintenance.banner")}</p>
      <button type="button" className="btn-secondary" onClick={notices.dismissMaintenance}>
        {t("common.dismiss")}
      </button>
    </div>
  );
}
