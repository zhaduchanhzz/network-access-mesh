// Cổng của các route cần đăng nhập và chuyển hướng trang chủ theo console + session.
import { Navigate, Outlet, useLocation } from "react-router";
import { useConsole } from "./console";
import { useNotices } from "./notices";
import { useSession } from "../auth/session";
import { Loading } from "../components/Page";
import { ProblemAlert } from "../components/ProblemAlert";

export function RequireSession() {
  const session = useSession();
  const location = useLocation();
  const { sessionExpired } = useNotices();
  if (session.isPending) return <Loading />;
  if (session.isError) {
    return (
      <main id="main" className="p-6">
        <ProblemAlert error={session.error} onRetry={() => void session.refetch()} />
      </main>
    );
  }
  if (!session.data) {
    const q = new URLSearchParams({ return_to: location.pathname + location.search });
    if (sessionExpired) q.set("reason", "expired");
    return <Navigate to={`/login?${q.toString()}`} replace />;
  }
  return <Outlet />;
}

/** "/" ⇒ Platform Console (admin.) hoặc tenant duy nhất / trang chọn tenant (app.). */
export function HomeRedirect() {
  const kind = useConsole();
  const session = useSession();
  if (session.isPending) return <Loading />;
  if (session.isError) {
    return (
      <main id="main" className="p-6">
        <ProblemAlert error={session.error} onRetry={() => void session.refetch()} />
      </main>
    );
  }
  const s = session.data;
  if (!s) return <Navigate to="/login" replace />;
  if (kind === "platform") {
    return <Navigate to={s.principal.scope === "platform" ? "/platform" : "/tenants"} replace />;
  }
  const only = s.memberships.length === 1 ? s.memberships[0] : undefined;
  return <Navigate to={only ? `/t/${only.tenant_id}` : "/tenants"} replace />;
}
