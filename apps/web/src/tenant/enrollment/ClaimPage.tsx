// Trang claim web-auth (P4-T08) — hợp đồng của edge v10 (P4-T07 §3):
//   GET https://app.<domain>/enroll/claim?tenant=<slug>&auth_id=<auth_id>
// 1. Đọc hai tham số MỘT lần vào state của trang rồi gỡ `auth_id` khỏi thanh địa chỉ (history.replaceState qua router) —
//    không còn trong lịch sử/ảnh chụp màn hình; không ghi vào Web Storage hay history.state.
// 2. Chưa đăng nhập ⇒ /login?tenant=<slug>&return_to=<đường dẫn claim đầy đủ> (login tenant cần `tenant`; return_to
//    cùng origin qua bộ lọc open-redirect hiện có) — sau đăng nhập trình duyệt quay lại đây với đủ tham số.
// 3. `tenant` (slug) ⇒ `tenant_id` qua GET /auth/session (`memberships[].tenant_slug`); không thuộc ⇒ "link lạ", không
//    nút xác nhận. SPA tự kiểm định dạng `auth_id` (người dùng có thể mở URL trực tiếp).
// 4. Cảnh báo chống phishing + xác nhận tường minh ⇒ POST /enrollment/web-auth/claim (ClaimPanel).
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, Navigate, useLocation, useNavigate } from "react-router";
import { api, call } from "../../api/client";
import { queryKeys } from "../../api/queryClient";
import { useConsole } from "../../app/console";
import { useNotices } from "../../app/notices";
import { SLUG_RE, useSession } from "../../auth/session";
import { Loading, useDocumentTitle } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { Preferences } from "../../layout/Preferences";
import { NotFoundPage } from "../../pages/StatusPages";
import { ClaimPanel, InvalidLink } from "./ClaimPanel";
import { AUTH_ID_RE } from "./model";

export const CLAIM_PATH = "/enroll/claim";

function readSlug(search: string): string | null {
  const s = new URLSearchParams(search).get("tenant");
  return s !== null && SLUG_RE.test(s) ? s : null;
}

function readAuthId(search: string): string | null {
  const a = new URLSearchParams(search).get("auth_id");
  return a !== null && AUTH_ID_RE.test(a) ? a : null;
}

export function ClaimPage() {
  const { t } = useTranslation();
  const kind = useConsole();
  const location = useLocation();
  const navigate = useNavigate();
  useDocumentTitle(t("enroll.claim.title"));
  const [slug] = useState(() => readSlug(location.search));
  const [authId, setAuthId] = useState<string | null>(() => readAuthId(location.search));
  const [linkOk] = useState(() => readSlug(location.search) !== null && readAuthId(location.search) !== null);

  useEffect(() => {
    if (new URLSearchParams(location.search).has("auth_id")) {
      void navigate({ pathname: CLAIM_PATH, search: slug ? `?tenant=${slug}` : "" }, { replace: true });
    }
  }, [location.search, navigate, slug]);

  if (kind === "platform") {
    return (
      <main id="main" className="min-h-screen bg-bg p-6 text-fg">
        <NotFoundPage />
      </main>
    );
  }
  return (
    <div className="flex min-h-screen flex-col bg-bg text-fg">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-line bg-surface px-4 py-3">
        <Link to="/" className="font-semibold">
          {t("app.name")}
        </Link>
        <Preferences />
      </header>
      <main id="main" className="mx-auto w-full max-w-2xl p-6">
        <h1 className="mb-4 text-2xl font-semibold tracking-tight">{t("enroll.claim.title")}</h1>
        <ClaimBody
          slug={slug}
          authId={authId}
          linkOk={linkOk}
          onSpent={() => {
            setAuthId(null);
          }}
        />
      </main>
    </div>
  );
}

function ClaimBody({ slug, authId, linkOk, onSpent }: { slug: string | null; authId: string | null; linkOk: boolean; onSpent: () => void }) {
  const { t } = useTranslation();
  const session = useSession();
  if (!linkOk || slug === null) return <InvalidLink />;
  if (session.isPending) return <Loading />;
  if (session.isError) return <ProblemAlert error={session.error} onRetry={() => void session.refetch()} />;
  if (!session.data) {
    if (authId === null) return <InvalidLink />;
    const back = `${CLAIM_PATH}?${new URLSearchParams({ tenant: slug, auth_id: authId }).toString()}`;
    return <Navigate to={`/login?${new URLSearchParams({ tenant: slug, return_to: back }).toString()}`} replace />;
  }
  const membership = session.data.memberships.find((m) => m.tenant_slug === slug);
  if (!membership) {
    return (
      <div role="alert" className="rounded-md border border-line bg-surface p-4" data-testid="claim-not-member">
        <p className="font-semibold">{t("enroll.claim.notMemberTitle")}</p>
        <p className="mt-1 text-sm">{t("enroll.claim.notMember")}</p>
      </div>
    );
  }
  return <MemberClaim tenantId={membership.tenant_id} tenantName={membership.tenant_name} membershipId={membership.membership_id} authId={authId} onSpent={onSpent} />;
}

function MemberClaim(props: { tenantId: string; tenantName: string; membershipId: string; authId: string | null; onSpent: () => void }) {
  const { t } = useTranslation();
  const notices = useNotices();
  const tenant = useQuery({
    queryKey: queryKeys.tenant(props.tenantId, "tenant"),
    queryFn: () => call(api.GET("/tenants/{tenantId}", { params: { path: { tenantId: props.tenantId } } })),
  });
  const status = tenant.data?.status;
  const readOnly = status === "suspended" || status === "deprovisioning" || notices.suspendedTenants.has(props.tenantId);
  return (
    <div className="space-y-4">
      <p className="text-sm text-muted" data-testid="claim-tenant">
        {t("enroll.claim.tenant", { name: props.tenantName })}
      </p>
      {readOnly ? (
        <div role="status" className="banner banner-warn" data-testid="tenant-suspended">
          <p>{t("tenant.suspendedBanner")}</p>
        </div>
      ) : null}
      <ClaimPanel tenantId={props.tenantId} membershipId={props.membershipId} authId={props.authId ?? ""} readOnly={readOnly} onSpent={props.onSpent} />
      <p className="text-sm">
        <Link to={`/t/${props.tenantId}/enroll`} className="link">
          {t("enroll.claim.toEnroll")}
        </Link>
      </p>
    </div>
  );
}
