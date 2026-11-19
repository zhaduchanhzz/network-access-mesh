// Màn hình của P4-T08 tải theo route (chunk riêng — §12.4, như P4-T11): Thêm thiết bị, Enrollment key, trang claim.
// tenant/pages.tsx và app/routes.tsx chỉ tham chiếu các wrapper này.
import { lazy, Suspense } from "react";
import { Loading } from "../../components/Page";

const AddDeviceLazy = lazy(() => import("./AddDevicePage").then((m) => ({ default: m.AddDevicePage })));
const KeysLazy = lazy(() => import("./KeysPage").then((m) => ({ default: m.KeysPage })));
const ClaimLazy = lazy(() => import("./ClaimPage").then((m) => ({ default: m.ClaimPage })));

export function AddDeviceScreen() {
  return (
    <Suspense fallback={<Loading />}>
      <AddDeviceLazy />
    </Suspense>
  );
}

export function KeysScreen() {
  return (
    <Suspense fallback={<Loading />}>
      <KeysLazy />
    </Suspense>
  );
}

export function ClaimScreen() {
  return (
    <Suspense fallback={<Loading />}>
      <ClaimLazy />
    </Suspense>
  );
}
