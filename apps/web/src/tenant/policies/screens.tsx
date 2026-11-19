// Màn hình của P4-T11 tải theo route (chunk riêng — §12.4): Policies, chi tiết version, Tags. tenant/pages.tsx chỉ
// tham chiếu các wrapper này, nên mã của editor không nằm trong chunk chính của Tenant Portal.
import { lazy, Suspense } from "react";
import { Loading } from "../../components/Page";

const PoliciesLazy = lazy(() => import("./PoliciesPage").then((m) => ({ default: m.PoliciesPage })));
const VersionLazy = lazy(() => import("./PolicyVersionPage").then((m) => ({ default: m.PolicyVersionPage })));
const TagsLazy = lazy(() => import("./TagsPage").then((m) => ({ default: m.TagsPage })));

export function PoliciesScreen() {
  return (
    <Suspense fallback={<Loading />}>
      <PoliciesLazy />
    </Suspense>
  );
}

export function PolicyVersionScreen() {
  return (
    <Suspense fallback={<Loading />}>
      <VersionLazy />
    </Suspense>
  );
}

export function TagsScreen() {
  return (
    <Suspense fallback={<Loading />}>
      <TagsLazy />
    </Suspense>
  );
}
