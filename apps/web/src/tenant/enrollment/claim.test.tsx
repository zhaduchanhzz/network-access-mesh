// Trang claim web-auth (P4-T08) theo hợp đồng của edge v10 (P4-T07 §3): /enroll/claim?tenant=<slug>&auth_id=<id> —
// chưa đăng nhập ⇒ /login?tenant=&return_to=; slug ⇒ tenant_id qua GET /auth/session; Auth ID tự kiểm định dạng rồi gỡ
// khỏi URL; cảnh báo phishing + xác nhận tường minh ⇒ POST /enrollment/web-auth/claim; 409 no_pending_request ⇒ cảnh
// báo, không nút xác nhận; replay/hết hạn; 200 failed; 422 request_id_required ⇒ chọn yêu cầu; 422 web_auth_disabled;
// 429 (thử lại được); 403 tenant_suspended; Auth ID không ở DOM/URL/Storage/cache sau khi xử lý.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { QueryClient } from "@tanstack/react-query";
import { CSRF, json, mockApi, problem, renderApp, TENANT_A, TENANT_B, tenantBody, tenantSession } from "../../test/helpers";
import { AUTH_ID, conflict, invalid, REQ_1, REQ_3, request } from "../../test/enrollment";

const base = `/tenants/${TENANT_A}`;
type Routes = Record<string, Response | ((r: Request) => Response | Promise<Response>)>;
const claimUrl = (slug = "tenant-a", authId = AUTH_ID) => `/enroll/claim?tenant=${slug}&auth_id=${authId}`;

function apiFor(extra: Routes = {}, opts: { role?: string; status?: "active" | "suspended"; pending?: ReturnType<typeof request>[] } = {}): Routes {
  return {
    "GET /auth/session": json(200, tenantSession([{ tenantId: TENANT_A, slug: "tenant-a", name: "Tenant A", role: opts.role ?? "end_user" }])),
    [`GET ${base}`]: json(200, tenantBody(TENANT_A, "tenant-a", opts.status ?? "active")),
    [`GET ${base}/enrollment/requests`]: json(200, { items: opts.pending ?? [request(REQ_1)], next_cursor: null }),
    ...extra,
  };
}

const claims = (requests: Request[]) => requests.filter((r) => r.method === "POST" && new URL(r.url).pathname === `/api/v1${base}/enrollment/web-auth/claim`);

function expectGone(router: { state: { location: { search: string; pathname: string } } }, queryClient: QueryClient) {
  expect(router.state.location.search).not.toContain("auth_id");
  expect(document.body.innerHTML).not.toContain(AUTH_ID);
  expect(localStorage.length === 0 || !JSON.stringify(Object.entries(localStorage)).includes(AUTH_ID)).toBe(true);
  expect(sessionStorage.length).toBe(0);
  expect(JSON.stringify(window.history.state ?? null)).not.toContain(AUTH_ID);
  expect(JSON.stringify(queryClient.getQueryCache().getAll().map((q) => q.state))).not.toContain(AUTH_ID);
  expect(JSON.stringify(queryClient.getMutationCache().getAll().map((m) => m.state))).not.toContain(AUTH_ID);
}

async function confirmClaim() {
  const panel = await screen.findByTestId("claim-confirm");
  const button = within(panel).getByRole("button", { name: "Xác nhận thiết bị" });
  expect(button).toBeDisabled();
  await userEvent.click(within(panel).getByLabelText(/Tôi vừa chạy lệnh/));
  await userEvent.click(button);
}

describe("trang claim /enroll/claim", () => {
  it("chưa đăng nhập ⇒ /login?tenant=<slug>&return_to=<đường dẫn claim đầy đủ>", async () => {
    mockApi({ "GET /auth/session": problem(401, "unauthenticated") });
    const { router } = renderApp({ path: claimUrl() });
    await screen.findByRole("heading", { name: "Đăng nhập Tenant Portal", level: 1 });
    const q = new URLSearchParams(router.state.location.search);
    expect(router.state.location.pathname).toBe("/login");
    expect(q.get("tenant")).toBe("tenant-a");
    expect(q.get("return_to")).toBe(claimUrl());
    expect(screen.getByLabelText("Mã tenant (slug)")).toHaveValue("tenant-a");
  });

  it("đăng nhập rồi: gỡ auth_id khỏi URL, cảnh báo + xác nhận tường minh ⇒ POST {auth_id} ⇒ verified, tên thiết bị + link Devices", async () => {
    const { requests } = mockApi(apiFor({ [`POST ${base}/enrollment/web-auth/claim`]: json(200, request(REQ_1, { status: "verified", node_id: "12" })) }));
    const { router, queryClient } = renderApp({ path: claimUrl() });
    await screen.findByTestId("claim-confirm");
    await waitFor(() => expect(router.state.location.search).toBe("?tenant=tenant-a"));
    expect(router.state.location.pathname).toBe("/enroll/claim");
    expect(screen.getByTestId("claim-tenant")).toHaveTextContent("Tenant A");
    expect(screen.getByTestId("phishing-caution")).toHaveTextContent("Nếu ai đó gửi link này cho bạn");
    expect(await screen.findByTestId("pending-context")).toHaveTextContent("laptop-an");
    expect(claims(requests)).toHaveLength(0); // chưa xác nhận ⇒ chưa gọi
    await confirmClaim();
    const ok = await screen.findByTestId("claim-verified");
    expect(ok).toHaveTextContent("Đã thêm thiết bị laptop-an.");
    expect(within(ok).getByRole("link", { name: "Tới danh sách thiết bị" })).toHaveAttribute("href", `/t/${TENANT_A}/devices`);
    const post = claims(requests)[0]!;
    expect(await post.json()).toEqual({ auth_id: AUTH_ID });
    expect(post.headers.get("X-CSRF-Token")).toBe(CSRF);
    expect(screen.queryByRole("button", { name: "Xác nhận thiết bị" })).toBeNull();
    expectGone(router, queryClient);
  });

  it("409 no_pending_request ⇒ trang cảnh báo phishing, KHÔNG có nút xác nhận", async () => {
    const { requests } = mockApi(apiFor({ [`POST ${base}/enrollment/web-auth/claim`]: conflict("no_pending_request") }, { pending: [] }));
    const { router, queryClient } = renderApp({ path: claimUrl() });
    expect(await screen.findByTestId("no-pending-hint")).toHaveTextContent("Không thấy yêu cầu");
    await confirmClaim();
    const warn = await screen.findByTestId("claim-phishing");
    expect(warn).toHaveTextContent("bạn không có yêu cầu thiết bị nào đang chờ");
    expect(screen.queryByRole("button", { name: "Xác nhận thiết bị" })).toBeNull();
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(claims(requests)).toHaveLength(1);
    expectGone(router, queryClient);
  });

  it.each([
    ["auth_id_already_claimed", "claim-used"],
    ["auth_id_not_pending", "claim-used"],
  ])("409 %s ⇒ link đã dùng hoặc hết hạn (15 phút)", async (reason, testId) => {
    mockApi(apiFor({ [`POST ${base}/enrollment/web-auth/claim`]: conflict(reason) }));
    renderApp({ path: claimUrl() });
    await confirmClaim();
    expect(await screen.findByTestId(testId)).toHaveTextContent("15 phút");
    expect(screen.queryByRole("button", { name: "Xác nhận thiết bị" })).toBeNull();
  });

  it.each([
    ["node_mismatch", "đã bị xóa ngay"],
    ["foreign_node", "thuộc người khác"],
    ["mystery_code", "mystery_code"],
  ])("200 failed %s ⇒ hiển thị failure_code", async (code, text) => {
    mockApi(apiFor({ [`POST ${base}/enrollment/web-auth/claim`]: json(200, request(REQ_1, { status: "failed", failure_code: code })) }));
    renderApp({ path: claimUrl() });
    await confirmClaim();
    expect(await screen.findByTestId("claim-failed")).toHaveTextContent(text);
  });

  it("nhiều yêu cầu đang chờ: bắt chọn ⇒ body có request_id; 422 request_id_required ⇒ hiện bộ chọn rồi gửi lại", async () => {
    const two = [request(REQ_1), request(REQ_3, { device_label: "desktop-an" })];
    let n = 0;
    const { requests } = mockApi(
      apiFor(
        { [`POST ${base}/enrollment/web-auth/claim`]: () => (++n === 1 ? json(200, request(REQ_3, { status: "verified", device_label: "desktop-an" })) : problem(500, "internal_error")) },
        { pending: two },
      ),
    );
    renderApp({ path: claimUrl() });
    const pick = await screen.findByTestId("pick-request");
    await userEvent.click(within(screen.getByTestId("claim-confirm")).getByLabelText(/Tôi vừa chạy lệnh/));
    const button = screen.getByRole("button", { name: "Xác nhận thiết bị" });
    expect(button).toBeDisabled(); // chưa chọn yêu cầu
    await userEvent.click(within(pick).getByLabelText(/desktop-an/));
    await userEvent.click(button);
    expect(await screen.findByTestId("claim-verified")).toHaveTextContent("desktop-an");
    expect(await claims(requests)[0]!.json()).toEqual({ auth_id: AUTH_ID, request_id: REQ_3 });
  });

  it("422 request_id_required (danh sách cũ chỉ thấy một) ⇒ bộ chọn xuất hiện, gửi lại với request_id", async () => {
    let listed = [request(REQ_1)];
    let n = 0;
    const { requests } = mockApi({
      ...apiFor({
        [`POST ${base}/enrollment/web-auth/claim`]: () => {
          if (++n === 1) {
            listed = [request(REQ_1), request(REQ_3, { device_label: "desktop-an" })];
            return invalid("request_id", "request_id_required");
          }
          return json(200, request(REQ_1, { status: "verified" }));
        },
      }),
      [`GET ${base}/enrollment/requests`]: () => json(200, { items: listed, next_cursor: null }),
    });
    renderApp({ path: claimUrl() });
    await confirmClaim();
    const pick = await screen.findByTestId("pick-request");
    await userEvent.click(await within(pick).findByLabelText(/laptop-an/));
    await userEvent.click(screen.getByRole("button", { name: "Xác nhận thiết bị" }));
    await screen.findByTestId("claim-verified");
    expect(await claims(requests)[1]!.json()).toEqual({ auth_id: AUTH_ID, request_id: REQ_1 });
  });

  it("429 ⇒ báo chờ, vẫn thử lại được với cùng Auth ID; 422 web_auth_disabled ⇒ dùng pre-auth key", async () => {
    let n = 0;
    const { requests } = mockApi(
      apiFor({ [`POST ${base}/enrollment/web-auth/claim`]: () => (++n === 1 ? problem(429, "rate_limited", {}, { "Retry-After": "30" }) : invalid("auth_id", "web_auth_disabled")) }),
    );
    renderApp({ path: claimUrl() });
    await confirmClaim();
    const panel = screen.getByTestId("claim-confirm");
    expect(await within(panel).findByText(/Thử lại sau 30 giây/)).toBeInTheDocument();
    await userEvent.click(within(panel).getByRole("button", { name: "Xác nhận thiết bị" }));
    expect(await screen.findByTestId("claim-disabled")).toHaveTextContent("pre-auth key");
    expect(claims(requests)).toHaveLength(2);
    expect(await claims(requests)[1]!.json()).toEqual({ auth_id: AUTH_ID });
  });

  it("403 forbidden (tenant chưa cho End User tự thêm) ⇒ lỗi + gợi ý; tenant suspended ⇒ banner, nút khóa", async () => {
    mockApi(apiFor({ [`POST ${base}/enrollment/web-auth/claim`]: problem(403, "forbidden") }));
    const { unmount } = renderApp({ path: claimUrl() });
    await confirmClaim();
    expect(await screen.findByTestId("claim-error")).toHaveTextContent("chưa cho phép người dùng tự thêm thiết bị");
    unmount();
    const { requests } = mockApi(apiFor({}, { status: "suspended" }));
    renderApp({ path: claimUrl() });
    await screen.findByTestId("tenant-suspended");
    await userEvent.click(within(await screen.findByTestId("claim-confirm")).getByLabelText(/Tôi vừa chạy lệnh/));
    expect(screen.getByRole("button", { name: "Xác nhận thiết bị" })).toBeDisabled();
    expect(claims(requests)).toHaveLength(0);
  });

  it("403 tenant_suspended từ server ⇒ thông báo tạm ngưng", async () => {
    mockApi(apiFor({ [`POST ${base}/enrollment/web-auth/claim`]: problem(403, "tenant_suspended", { instance: `/api/v1${base}/enrollment/web-auth/claim` }) }));
    renderApp({ path: claimUrl() });
    await confirmClaim();
    expect(await screen.findByTestId("claim-error")).toHaveTextContent("Tenant đang bị tạm ngưng");
  });

  it.each([
    ["Auth ID sai định dạng", claimUrl("tenant-a", "hskey-authreq-tooShort")],
    ["Auth ID có ký tự lạ", claimUrl("tenant-a", "hskey-authreq-" + "a".repeat(23) + "%2F")],
    ["thiếu tenant", `/enroll/claim?auth_id=${AUTH_ID}`],
    ["slug sai", claimUrl("Tenant_A")],
  ])("%s ⇒ link không hợp lệ, không nút xác nhận, không gọi claim", async (_n, path) => {
    const { requests } = mockApi(apiFor());
    const { router } = renderApp({ path });
    expect(await screen.findByTestId("claim-invalid")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Xác nhận thiết bị" })).toBeNull();
    expect(claims(requests)).toHaveLength(0);
    await waitFor(() => expect(router.state.location.search).not.toContain("auth_id"));
  });

  it("slug không thuộc membership ⇒ 'link không thuộc tenant của bạn', không nút xác nhận", async () => {
    const { requests } = mockApi({
      "GET /auth/session": json(200, tenantSession([{ tenantId: TENANT_B, slug: "tenant-b", name: "Tenant B", role: "end_user" }])),
    });
    const { router } = renderApp({ path: claimUrl() });
    expect(await screen.findByTestId("claim-not-member")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Xác nhận thiết bị" })).toBeNull();
    expect(claims(requests)).toHaveLength(0);
    await waitFor(() => expect(router.state.location.search).toBe("?tenant=tenant-a"));
  });

  it("trên admin. (Platform Console) ⇒ 404 thống nhất", async () => {
    mockApi({ "GET /auth/session": problem(401, "unauthenticated") });
    renderApp({ path: claimUrl(), console: "platform" });
    await screen.findByRole("heading", { name: "Không tìm thấy", level: 1 });
  });
});
