// Thêm thiết bị + Enrollment key (P4-T08) trên App thật (router bộ nhớ, QueryClient, openapi-fetch), API giả ở tầng
// fetch theo đúng hợp đồng P4-T06: wizard theo OS (hướng dẫn từ GET /enrollment/instructions, Windows MSI/LoginURL, mobile
// chỉ key), POST /enrollment/requests (Idempotency-Key + CSRF) ⇒ lệnh web-auth theo dõi tới verified / key MỘT lần,
// pending_approval ⇒ /start, ô dán link/Auth ID, hàng chờ duyệt (người quyết ≠ người yêu cầu), thu hồi hai pha, key đặc
// quyền (tag từ danh mục), lỗi 403/404/409/410/422/429, tenant suspended, nav theo role; key không lọt vào DOM sau khi
// đóng, Web Storage, URL hay cache của TanStack Query.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { QueryClient } from "@tanstack/react-query";
import { CSRF, json, mockApi, platformSession, problem, renderApp, TENANT_A, tenantBody, tenantSession } from "../../test/helpers";
import { tag } from "../../test/network";
import {
  AUTH_ID,
  conflict,
  ENROLL_CODE,
  instructions,
  invalid,
  keyIssue,
  LOGIN_SERVER,
  ME,
  OTHER,
  PREAUTH_KEY,
  REQ_1,
  REQ_2,
  REQ_3,
  request,
  T0,
  webIssue,
} from "../../test/enrollment";
import { extractAuthId, guessOS, isRevocable, problemReason } from "./model";
import { ApiError } from "../../api/problem";
import { i18n } from "../../i18n";

const base = `/tenants/${TENANT_A}`;
type Routes = Record<string, Response | ((r: Request) => Response | Promise<Response>)>;
const UUID_RE = /^[0-9a-f-]{36}$/;

function apiFor(role: string, extra: Routes = {}, status: "active" | "suspended" = "active"): Routes {
  return {
    "GET /auth/session": json(200, tenantSession([{ tenantId: TENANT_A, slug: "tenant-a", name: "Tenant A", role }])),
    [`GET ${base}`]: json(200, tenantBody(TENANT_A, "tenant-a", status)),
    [`GET ${base}/notifications`]: json(200, { items: [], next_cursor: null }),
    [`GET ${base}/enrollment/instructions`]: (r) => json(200, instructions((new URL(r.url).searchParams.get("os") ?? "linux") as "linux")),
    [`GET ${base}/enrollment/requests`]: json(200, { items: [], next_cursor: null }),
    [`GET ${base}/users`]: json(200, { items: [], next_cursor: null }),
    ...extra,
  };
}

const posts = (requests: Request[], path?: string) =>
  requests.filter((r) => r.method === "POST" && (path === undefined || new URL(r.url).pathname === `/api/v1${base}${path}`));

/** Không còn dấu vết của secret: DOM, Web Storage, URL của router, cache của query + mutation. */
type RouterLike = { state: { location: { pathname: string; search: string; hash: string } } };

function expectNoTrace(secret: string, router: RouterLike, queryClient: QueryClient) {
  expect(document.body.innerHTML).not.toContain(secret);
  expectNotStored(secret, router, queryClient);
}

/** Secret đang hiển thị: chỉ được ở DOM — không Web Storage, URL, cache query/mutation. */
function expectNotStored(secret: string, router: RouterLike, queryClient: QueryClient) {
  const dump = (s: Storage) => Array.from({ length: s.length }, (_, i) => `${s.key(i) ?? ""}=${s.getItem(s.key(i) ?? "") ?? ""}`).join(";");
  expect(dump(localStorage) + dump(sessionStorage)).not.toContain(secret);
  const loc = router.state.location;
  expect(loc.pathname + loc.search + loc.hash).not.toContain(secret);
  const queries = JSON.stringify(queryClient.getQueryCache().getAll().map((q) => q.state));
  const mutations = JSON.stringify(queryClient.getMutationCache().getAll().map((m) => m.state));
  expect(queries).not.toContain(secret);
  expect(mutations).not.toContain(secret);
}

describe("model", () => {
  it("tách Auth ID từ Auth ID, link /register/<id>, link trang claim; từ chối link control plane/tenant khác", () => {
    expect(extractAuthId(AUTH_ID)).toEqual({ ok: true, authId: AUTH_ID });
    expect(extractAuthId(`  ${LOGIN_SERVER}/register/${AUTH_ID}  `, { loginServer: LOGIN_SERVER })).toEqual({ ok: true, authId: AUTH_ID });
    expect(extractAuthId(`https://app.example.test/enroll/claim?tenant=tenant-a&auth_id=${AUTH_ID}`, { tenantSlug: "tenant-a" })).toEqual({ ok: true, authId: AUTH_ID });
    expect(extractAuthId(`https://evil.example.test/register/${AUTH_ID}`, { loginServer: LOGIN_SERVER })).toEqual({ ok: false, reason: "other_server" });
    expect(extractAuthId(`https://app.example.test/enroll/claim?tenant=tenant-b&auth_id=${AUTH_ID}`, { tenantSlug: "tenant-a" })).toEqual({ ok: false, reason: "other_server" });
    expect(extractAuthId("hskey-authreq-short")).toEqual({ ok: false, reason: "none" });
    expect(extractAuthId(`${AUTH_ID}x`)).toEqual({ ok: false, reason: "none" });
    expect(extractAuthId(`${AUTH_ID} hskey-authreq-${"Q".repeat(24)}`)).toEqual({ ok: false, reason: "several" });
  });

  it("OS mặc định theo user agent; lý do ổn định của 409/422", () => {
    expect(guessOS("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")).toBe("windows");
    expect(guessOS("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)")).toBe("ios");
    expect(guessOS("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)")).toBe("macos");
    expect(guessOS("Mozilla/5.0 (Linux; Android 15)")).toBe("android");
    expect(guessOS("Mozilla/5.0 (X11; Linux x86_64)")).toBe("linux");
    const e = new ApiError({ status: 409, code: "conflict", problem: { type: "x", title: "x", status: 409, code: "conflict", request_id: "r", errors: [{ field: "request", code: "no_pending_request", message: "m" }] } });
    expect(problemReason(e)).toBe("no_pending_request");
    expect(problemReason(e, "validation_failed")).toBeNull();
    expect(problemReason(new Error("x"))).toBeNull();
  });

  it("thu hồi được: yêu cầu chưa kết thúc, hoặc key reusable đã dùng (consumed) còn hạn — như liveKey của server", () => {
    const now = Date.now();
    const past = new Date(now - 1_000).toISOString();
    for (const status of ["requested", "pending_approval", "approved", "issued"] as const) expect(isRevocable(request(REQ_1, { status }), now)).toBe(true);
    for (const status of ["claimed", "registered", "verified", "rejected", "expired", "revoked", "failed"] as const) expect(isRevocable(request(REQ_1, { status }), now)).toBe(false);
    const used = request(REQ_2, { method: "preauth_key", status: "consumed", reusable: true });
    expect(isRevocable(used, now)).toBe(true);
    expect(isRevocable({ ...used, credential_expires_at: past }, now)).toBe(false);
    expect(isRevocable({ ...used, credential_expires_at: null }, now)).toBe(false);
    expect(isRevocable({ ...used, reusable: false }, now)).toBe(false);
  });
});

describe("Thêm thiết bị — wizard theo OS", () => {
  it("End User: nav chỉ có Thêm thiết bị (không Enrollment key); hướng dẫn đúng login_server; Windows có MSI + LoginURL; iOS chỉ key", async () => {
    const { requests } = mockApi(apiFor("end_user"));
    renderApp({ path: `/t/${TENANT_A}/enroll` });
    const wizard = await screen.findByTestId("enroll-wizard");
    const nav = screen.getByRole("navigation", { name: /điều hướng|Điều hướng/i });
    expect(within(nav).getByRole("link", { name: /Thêm thiết bị/ })).toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: /Enrollment key/ })).toBeNull();
    expect(within(wizard).getByLabelText("Linux")).toBeChecked();
    expect(await within(wizard).findByTestId("login-server")).toHaveTextContent(LOGIN_SERVER);
    expect(within(wizard).getByTestId("managed-env")).toHaveTextContent("TS_NO_LOGS_NO_SUPPORT=true");
    expect(within(wizard).getByTestId("privacy-notice")).toHaveTextContent("Tailscale Inc.");
    expect(within(wizard).getByRole("radio", { name: /Web-auth/ })).toBeChecked();
    expect(within(wizard).queryByLabelText("Hạn của key (phút)")).toBeNull();

    await userEvent.click(within(wizard).getByLabelText("Windows"));
    const msi = await within(wizard).findByTestId("windows-msi");
    expect(msi).toHaveTextContent(`TS_LOGINURL=${LOGIN_SERVER}`);
    expect(msi).toHaveTextContent(`/v LoginURL /t REG_SZ /d ${LOGIN_SERVER}`);
    expect(requests.some((r) => new URL(r.url).searchParams.get("os") === "windows")).toBe(true);

    await userEvent.click(within(wizard).getByLabelText("iOS"));
    await waitFor(() => expect(within(wizard).getByTestId("instructions")).toHaveAttribute("data-os", "ios"));
    expect(within(wizard).getByRole("radio", { name: /Web-auth/ })).toBeDisabled();
    expect(within(wizard).getByRole("radio", { name: /Pre-auth key một lần/ })).toBeChecked();
    expect(within(wizard).getByLabelText("Hạn của key (phút)")).toHaveValue(15);
    expect(within(wizard).queryByTestId("windows-msi")).toBeNull();
  });

  it("nút sao chép ghi đúng lệnh vào clipboard và báo qua vùng live", async () => {
    const user = userEvent.setup();
    mockApi(apiFor("end_user"));
    renderApp({ path: `/t/${TENANT_A}/enroll` });
    const wizard = await screen.findByTestId("enroll-wizard");
    await within(wizard).findByTestId("login-server");
    await user.click(within(wizard).getByRole("button", { name: "Sao chép login server" }));
    expect(await navigator.clipboard.readText()).toBe(LOGIN_SERVER);
    expect(await within(wizard).findByText("Đã sao chép.")).toBeInTheDocument();
  });

  it("web-auth: POST {method, device_label} với Idempotency-Key + CSRF ⇒ lệnh mg-<mã>; poll tới verified ⇒ lệnh/mã rời màn hình", async () => {
    let status: "issued" | "verified" = "issued";
    const { requests } = mockApi(
      apiFor("end_user", {
        [`POST ${base}/enrollment/requests`]: json(201, webIssue()),
        [`GET ${base}/enrollment/requests/${REQ_1}`]: () => json(200, request(REQ_1, { status })),
      }),
    );
    const { router, queryClient } = renderApp({ path: `/t/${TENANT_A}/enroll` });
    const wizard = await screen.findByTestId("enroll-wizard");
    await within(wizard).findByTestId("login-server");
    await userEvent.type(within(wizard).getByLabelText("Nhãn thiết bị (tùy chọn)"), "Laptop-An");
    await userEvent.click(within(wizard).getByRole("button", { name: "Tạo lệnh đăng ký" }));
    const issued = await screen.findByTestId("issued-web");
    expect(within(issued).getByTestId("enroll-command")).toHaveTextContent(`--hostname=mg-${ENROLL_CODE}`);
    const post = posts(requests, "/enrollment/requests")[0]!;
    expect(await post.json()).toEqual({ method: "web_auth", device_label: "laptop-an" });
    expect(post.headers.get("Idempotency-Key")).toMatch(UUID_RE);
    expect(post.headers.get("X-CSRF-Token")).toBe(CSRF);
    expectNotStored(ENROLL_CODE, router, queryClient); // đang hiển thị: không có ở cache/URL/Storage
    status = "verified";
    await waitFor(() => expect(within(issued).getByTestId("issued-verified")).toHaveTextContent("Đã thêm thiết bị laptop-an."), { timeout: 15_000 });
    expect(within(issued).getByRole("link", { name: "Tới danh sách thiết bị" })).toHaveAttribute("href", `/t/${TENANT_A}/devices`);
    await waitFor(() => expect(document.body.innerHTML).not.toContain(ENROLL_CODE));
    // lệnh tạo đã trả bản đọc mới nhất ⇒ không GET lại ngay; danh sách không poll song song (rate limit `enrollment`)
    const gets = requests.filter((r) => r.method === "GET" && new URL(r.url).pathname.includes("/enrollment/"));
    expect(gets.filter((r) => new URL(r.url).pathname.endsWith("/instructions"))).toHaveLength(1);
  }, 25_000);

  it("pre-auth key: POST {method: preauth_key, ttl_minutes} ⇒ key hiển thị MỘT lần; đóng sau khi xác nhận đã lưu ⇒ không còn dấu vết", async () => {
    const { requests } = mockApi(apiFor("tenant_operator", { [`POST ${base}/enrollment/requests`]: json(201, keyIssue()) }));
    const { router, queryClient } = renderApp({ path: `/t/${TENANT_A}/enroll` });
    const wizard = await screen.findByTestId("enroll-wizard");
    await within(wizard).findByTestId("login-server");
    await userEvent.click(within(wizard).getByRole("radio", { name: /Pre-auth key một lần/ }));
    const ttl = within(wizard).getByLabelText("Hạn của key (phút)");
    await userEvent.clear(ttl);
    await userEvent.type(ttl, "16");
    expect(within(wizard).getByRole("button", { name: "Tạo pre-auth key" })).toBeDisabled();
    await userEvent.clear(ttl);
    await userEvent.type(ttl, "10");
    await userEvent.click(within(wizard).getByRole("button", { name: "Tạo pre-auth key" }));
    const dialog = await screen.findByRole("dialog", { name: "Pre-auth key (hiển thị một lần)" });
    expect(within(dialog).getByTestId("secret-value")).toHaveTextContent(PREAUTH_KEY);
    expect(within(dialog).getByTestId("secret-once-warning")).toHaveTextContent("MỘT lần");
    expect(within(dialog).getByTestId("key-command")).not.toHaveTextContent(PREAUTH_KEY); // key qua TS_AUTHKEY
    expect(await posts(requests, "/enrollment/requests")[0]!.json()).toEqual({ method: "preauth_key", ttl_minutes: 10 });
    // khi đang hiển thị, key chỉ ở DOM của hộp — không ở cache/URL/Storage
    const queries = JSON.stringify(queryClient.getQueryCache().getAll().map((q) => q.state));
    expect(queries + JSON.stringify(queryClient.getMutationCache().getAll().map((m) => m.state))).not.toContain(PREAUTH_KEY);
    const close = within(dialog).getByRole("button", { name: "Đóng và xóa key khỏi màn hình" });
    expect(close).toBeDisabled();
    await userEvent.click(within(dialog).getByLabelText("Tôi đã lưu key ở nơi an toàn."));
    await userEvent.click(close);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expectNoTrace(PREAUTH_KEY, router, queryClient);
  });

  it("tenant bật duyệt: 201 pending_approval (không credential) ⇒ chờ duyệt; được duyệt ⇒ /start ⇒ key một lần; /start lần nữa 409 already_started", async () => {
    let approved = false;
    let starts = 0;
    let release = () => {};
    const gate = new Promise<void>((r) => {
      release = r;
    });
    const pendingReq = request(REQ_2, { method: "preauth_key", status: "pending_approval", issued_at: null, credential_expires_at: null, device_label: "nas" });
    mockApi(
      apiFor("end_user", {
        [`POST ${base}/enrollment/requests`]: json(201, { request: pendingReq }),
        [`GET ${base}/enrollment/requests`]: () => json(200, { items: [approved ? { ...pendingReq, status: "approved", approver_membership_id: OTHER } : pendingReq], next_cursor: null }),
        [`POST ${base}/enrollment/requests/${REQ_2}/start`]: async () => {
          if (++starts > 1) return conflict("already_started");
          await gate;
          return json(200, keyIssue({ device_label: "nas" }));
        },
      }),
    );
    const { queryClient } = renderApp({ path: `/t/${TENANT_A}/enroll` });
    const wizard = await screen.findByTestId("enroll-wizard");
    await within(wizard).findByTestId("login-server");
    await userEvent.click(within(wizard).getByRole("radio", { name: /Pre-auth key một lần/ }));
    await userEvent.click(within(wizard).getByRole("button", { name: "Tạo pre-auth key" }));
    expect(await screen.findByTestId("pending-approval")).toHaveTextContent("chờ duyệt");
    expect(screen.queryByRole("dialog")).toBeNull();
    const mine = await screen.findByTestId("my-requests");
    expect(within(mine).getByTestId("enroll-row")).toHaveAttribute("data-status", "pending_approval");
    expect(within(mine).queryByRole("button", { name: /Duyệt/ })).toBeNull(); // End User không duyệt
    approved = true;
    await queryClient.invalidateQueries();
    // WCAG 2.5.3 (Label in Name): tên truy cập bắt đầu bằng đúng chữ hiển thị của nút
    const start = await within(mine).findByRole("button", { name: "Nhận pre-auth key cho nas" });
    expect(start).toHaveTextContent("Nhận pre-auth key");
    await userEvent.click(start);
    // đang gửi /start: chữ hiển thị "Đang gửi…" là tên truy cập, aria-busy
    const busy = await within(mine).findByRole("button", { name: "Đang gửi…" });
    expect(busy).toHaveAttribute("aria-busy", "true");
    expect(busy).toBeDisabled();
    release();
    const dialog = await screen.findByRole("dialog", { name: "Pre-auth key (hiển thị một lần)" });
    expect(within(dialog).getByTestId("secret-value")).toHaveTextContent(PREAUTH_KEY);
    await userEvent.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(document.body.innerHTML).not.toContain(PREAUTH_KEY);
    const again = await within(screen.getByTestId("my-requests")).findByRole("button", { name: "Nhận pre-auth key cho nas" });
    expect(again).not.toHaveAttribute("aria-busy");
    await userEvent.click(again);
    expect(await screen.findByTestId("start-error")).toHaveTextContent("đã được phát");
  });

  it("nút /start của yêu cầu web-auth đã duyệt: tên truy cập 'Nhận lệnh đăng ký cho <nhãn>' chứa chữ hiển thị (WCAG 2.5.3)", async () => {
    const approvedWeb = request(REQ_1, { status: "approved", issued_at: null, credential_expires_at: null, approver_membership_id: OTHER });
    mockApi(apiFor("end_user", { [`GET ${base}/enrollment/requests`]: json(200, { items: [approvedWeb], next_cursor: null }) }));
    renderApp({ path: `/t/${TENANT_A}/enroll` });
    const mine = await screen.findByTestId("my-requests");
    const start = await within(mine).findByRole("button", { name: "Nhận lệnh đăng ký cho laptop-an" });
    expect(start).toHaveTextContent("Nhận lệnh đăng ký");
    for (const b of within(mine).getAllByRole("button")) {
      const name = b.getAttribute("aria-label");
      if (name !== null) expect(name.startsWith(b.textContent.trim()), `${name} ⊉ ${b.textContent}`).toBe(true);
    }
  });

  it("yêu cầu failed vì auth_id_not_pending ⇒ hướng dẫn tạo yêu cầu mới (không bảo chạy lại lệnh cũ)", async () => {
    const failed = request(REQ_1, { status: "failed", failure_code: "auth_id_not_pending", claimed_at: T0 });
    mockApi(apiFor("end_user", { [`GET ${base}/enrollment/requests`]: json(200, { items: [failed], next_cursor: null }) }));
    renderApp({ path: `/t/${TENANT_A}/enroll` });
    const row = within(await screen.findByTestId("my-requests")).getByTestId("enroll-row");
    expect(row).toHaveTextContent("tạo yêu cầu mới");
    expect(row).not.toHaveTextContent("chạy lại lệnh");
  });

  it.each([
    ["403 quota_exceeded", problem(403, "quota_exceeded", { detail: "quota devices exceeded (limit 5)" }), ["Đã vượt hạn mức"]],
    ["429 rate_limited", problem(429, "rate_limited", {}, { "Retry-After": "7" }), ["Quá nhiều yêu cầu", "7 giây"]],
    ["422 nhãn sai", invalid("device_label", "pattern"), ["Dữ liệu không hợp lệ", "device_label"]],
    ["409 no_instance", conflict("no_instance"), ["Xung đột"]],
  ])("lỗi khi tạo yêu cầu: %s", async (_name, response, texts) => {
    mockApi(apiFor("end_user", { [`POST ${base}/enrollment/requests`]: response }));
    renderApp({ path: `/t/${TENANT_A}/enroll` });
    const wizard = await screen.findByTestId("enroll-wizard");
    await within(wizard).findByTestId("login-server");
    await userEvent.click(within(wizard).getByRole("button", { name: "Tạo lệnh đăng ký" }));
    const err = await within(wizard).findByTestId("wizard-error");
    for (const text of texts) expect(err).toHaveTextContent(text);
    expect(screen.queryByTestId("issued-web")).toBeNull();
  });

  it("403 của giao diện vi không in `detail` tiếng Anh của server; giao diện en thì có (G4b-E3)", async () => {
    const quota = () => problem(403, "quota_exceeded", { detail: "quota devices exceeded (limit 5)" });
    mockApi(apiFor("end_user", { [`POST ${base}/enrollment/requests`]: quota }));
    const { unmount } = renderApp({ path: `/t/${TENANT_A}/enroll` });
    let wizard = await screen.findByTestId("enroll-wizard");
    await within(wizard).findByTestId("login-server");
    await userEvent.click(within(wizard).getByRole("button", { name: "Tạo lệnh đăng ký" }));
    expect(await within(wizard).findByTestId("wizard-error")).not.toHaveTextContent("limit 5");
    unmount();
    await i18n.changeLanguage("en");
    mockApi(apiFor("end_user", { [`POST ${base}/enrollment/requests`]: quota }));
    renderApp({ path: `/t/${TENANT_A}/enroll` });
    wizard = await screen.findByTestId("enroll-wizard");
    await within(wizard).findByTestId("login-server");
    await userEvent.click(within(wizard).getByRole("button", { name: i18n.t("enroll.wizard.submitWeb") }));
    expect(await within(wizard).findByTestId("wizard-error")).toHaveTextContent("limit 5");
  });

  it.each(["vi", "en"] as const)(
    "End User, tenant tắt self_enroll: 403 ⇒ wizard thay bằng thông báo đã dịch, không detail tiếng Anh, không tạo lệnh tiếp (G4b-E3, %s)",
    async (lng) => {
      await i18n.changeLanguage(lng);
      const { requests } = mockApi(
        apiFor("end_user", {
          [`POST ${base}/enrollment/requests`]: problem(403, "forbidden", { detail: "This tenant does not let members add devices themselves." }),
        }),
      );
      renderApp({ path: `/t/${TENANT_A}/enroll` });
      const wizard = await screen.findByTestId("enroll-wizard");
      await within(wizard).findByTestId("login-server");
      expect(screen.getByTestId("paste-claim")).toBeInTheDocument();
      await userEvent.click(within(wizard).getByRole("button", { name: i18n.t("enroll.wizard.submitWeb") }));
      const off = await screen.findByTestId("self-enroll-off");
      expect(off).toHaveAttribute("role", "alert");
      expect(off).toHaveTextContent(i18n.t("enroll.selfEnrollOff.title"));
      expect(off).toHaveTextContent(i18n.t("enroll.selfEnrollOff.body"));
      expect(document.body).not.toHaveTextContent("does not let members");
      // không còn nút tạo lệnh, ô dán link (claim cũng cần self_enroll)
      expect(screen.queryByRole("button", { name: i18n.t("enroll.wizard.submitWeb") })).toBeNull();
      expect(screen.queryByRole("button", { name: i18n.t("enroll.wizard.submitKey") })).toBeNull();
      expect(screen.queryByTestId("paste-claim")).toBeNull();
      expect(posts(requests, "/enrollment/requests")).toHaveLength(1);
      // danh sách "Yêu cầu của bạn" vẫn còn
      expect(screen.getByRole("heading", { name: i18n.t("enroll.mine.title") })).toBeInTheDocument();
    },
  );

  it.each(["vi", "en"] as const)(
    "End User, instructions báo self_enroll=false ⇒ thông báo ngay khi tải, không wizard / ô dán link, không POST (G4b-E3, %s)",
    async (lng) => {
      await i18n.changeLanguage(lng);
      const { requests } = mockApi(
        apiFor("end_user", {
          [`GET ${base}/enrollment/instructions`]: (r) =>
            json(200, instructions((new URL(r.url).searchParams.get("os") ?? "linux") as "linux", { self_enroll: false })),
        }),
      );
      renderApp({ path: `/t/${TENANT_A}/enroll` });
      const off = await screen.findByTestId("self-enroll-off");
      expect(off).toHaveTextContent(i18n.t("enroll.selfEnrollOff.title"));
      expect(off).toHaveTextContent(i18n.t("enroll.selfEnrollOff.body"));
      expect(screen.getByTestId("enroll-wizard")).toContainElement(off);
      expect(screen.queryByRole("button", { name: i18n.t("enroll.wizard.submitWeb") })).toBeNull();
      expect(screen.queryByRole("button", { name: i18n.t("enroll.wizard.submitKey") })).toBeNull();
      expect(screen.queryByTestId("paste-claim")).toBeNull();
      expect(screen.getByRole("heading", { name: i18n.t("enroll.mine.title") })).toBeInTheDocument();
      expect(posts(requests)).toHaveLength(0);
    },
  );

  it("self_enroll=false không áp cho role khác (Tenant Owner vẫn có wizard)", async () => {
    mockApi(
      apiFor("tenant_owner", {
        [`GET ${base}/enrollment/instructions`]: (r) =>
          json(200, instructions((new URL(r.url).searchParams.get("os") ?? "linux") as "linux", { self_enroll: false })),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/enroll` });
    const wizard = await screen.findByTestId("enroll-wizard");
    await within(wizard).findByTestId("login-server");
    expect(within(wizard).getByRole("button", { name: "Tạo lệnh đăng ký" })).toBeEnabled();
    expect(screen.queryByTestId("self-enroll-off")).toBeNull();
    expect(screen.getByTestId("paste-claim")).toBeInTheDocument();
  });

  it("403 forbidden với role không bị điều kiện self_enroll (Tenant Owner) ⇒ wizard vẫn còn, lỗi chung", async () => {
    mockApi(apiFor("tenant_owner", { [`POST ${base}/enrollment/requests`]: problem(403, "forbidden") }));
    renderApp({ path: `/t/${TENANT_A}/enroll` });
    const wizard = await screen.findByTestId("enroll-wizard");
    await within(wizard).findByTestId("login-server");
    await userEvent.click(within(wizard).getByRole("button", { name: "Tạo lệnh đăng ký" }));
    expect(await within(wizard).findByTestId("wizard-error")).toHaveTextContent("Bạn không có quyền");
    expect(screen.queryByTestId("self-enroll-off")).toBeNull();
  });

  it("nhãn sai định dạng chặn ở client; tenant chưa có instance ⇒ 404 instructions ⇒ báo rõ", async () => {
    mockApi(apiFor("end_user", { [`GET ${base}/enrollment/instructions`]: problem(404, "not_found") }));
    renderApp({ path: `/t/${TENANT_A}/enroll` });
    const wizard = await screen.findByTestId("enroll-wizard");
    expect(await within(wizard).findByTestId("no-instance")).toHaveTextContent("chưa có control plane");
    await userEvent.type(within(wizard).getByLabelText("Nhãn thiết bị (tùy chọn)"), "-bad-");
    expect(within(wizard).getByLabelText("Nhãn thiết bị (tùy chọn)")).toHaveAttribute("aria-invalid", "true");
    expect(within(wizard).getByRole("button", { name: "Tạo pre-auth key" })).toBeDisabled();
  });

  it("tenant suspended: banner chỉ-đọc, nút tạo/thu hồi khóa; Tenant Viewer không có form tạo", async () => {
    mockApi(apiFor("end_user", { [`GET ${base}/enrollment/requests`]: json(200, { items: [request(REQ_1)], next_cursor: null }) }, "suspended"));
    const { unmount } = renderApp({ path: `/t/${TENANT_A}/enroll` });
    const wizard = await screen.findByTestId("enroll-wizard");
    await screen.findByTestId("tenant-suspended");
    await within(wizard).findByTestId("login-server");
    expect(within(wizard).getByRole("button", { name: "Tạo lệnh đăng ký" })).toBeDisabled();
    expect(await screen.findByRole("button", { name: "Thu hồi yêu cầu laptop-an" })).toBeDisabled();
    expect(screen.getAllByText("Tenant đang ở chế độ chỉ-đọc: các thao tác thay đổi bị khóa.").length).toBeGreaterThan(0);
    unmount();
    mockApi(apiFor("tenant_viewer"));
    renderApp({ path: `/t/${TENANT_A}/enroll` });
    const w2 = await screen.findByTestId("enroll-wizard");
    expect(within(w2).queryByRole("button", { name: /Tạo/ })).toBeNull();
    expect(within(w2).getByText(/không tạo được yêu cầu thiết bị/)).toBeInTheDocument();
    expect(screen.queryByTestId("paste-claim")).toBeNull();
  });
});

describe("dán link hoặc Auth ID (phương án lùi)", () => {
  it("link /register/<id> của đúng control plane ⇒ ô nhập được xóa, cảnh báo + xác nhận ⇒ POST claim {auth_id} ⇒ verified", async () => {
    const { requests } = mockApi(
      apiFor("end_user", {
        [`GET ${base}/enrollment/requests`]: json(200, { items: [request(REQ_1)], next_cursor: null }),
        [`POST ${base}/enrollment/web-auth/claim`]: json(200, request(REQ_1, { status: "verified", node_id: "7" })),
      }),
    );
    const { router, queryClient } = renderApp({ path: `/t/${TENANT_A}/enroll` });
    const paste = await screen.findByTestId("paste-claim");
    await screen.findByTestId("login-server");
    const input = within(paste).getByLabelText("Link hoặc Auth ID");
    await userEvent.type(input, `${LOGIN_SERVER}/register/${AUTH_ID}`);
    await userEvent.click(within(paste).getByRole("button", { name: "Tiếp tục" }));
    expect(input).toHaveValue("");
    const panel = await within(paste).findByTestId("claim-confirm");
    expect(within(panel).getByTestId("phishing-caution")).toHaveTextContent("Chỉ xác nhận nếu chính bạn vừa chạy lệnh");
    const confirm = within(panel).getByRole("button", { name: "Xác nhận thiết bị" });
    expect(confirm).toBeDisabled();
    await userEvent.click(within(panel).getByLabelText(/Tôi vừa chạy lệnh/));
    await userEvent.click(confirm);
    expect(await within(paste).findByTestId("claim-verified")).toHaveTextContent("Đã thêm thiết bị laptop-an.");
    const post = posts(requests, "/enrollment/web-auth/claim")[0]!;
    expect(await post.json()).toEqual({ auth_id: AUTH_ID });
    expect(post.headers.get("X-CSRF-Token")).toBe(CSRF);
    expectNoTrace(AUTH_ID, router, queryClient);
  });

  it("link của control plane khác hoặc chuỗi lạ ⇒ lỗi tại ô, không gọi API", async () => {
    const { requests } = mockApi(apiFor("end_user"));
    renderApp({ path: `/t/${TENANT_A}/enroll` });
    const paste = await screen.findByTestId("paste-claim");
    await screen.findByTestId("login-server");
    const input = within(paste).getByLabelText("Link hoặc Auth ID");
    await userEvent.type(input, `https://other.mesh.example.test/register/${AUTH_ID}`);
    await userEvent.click(within(paste).getByRole("button", { name: "Tiếp tục" }));
    expect(await within(paste).findByText(/control plane hoặc tenant khác/)).toBeInTheDocument();
    expect(input).toHaveAttribute("aria-invalid", "true");
    await userEvent.type(input, "xin chao");
    await userEvent.click(within(paste).getByRole("button", { name: "Tiếp tục" }));
    expect(await within(paste).findByText(/Không thấy Auth ID hợp lệ/)).toBeInTheDocument();
    expect(within(paste).queryByTestId("claim-confirm")).toBeNull();
    expect(posts(requests)).toHaveLength(0);
    expect(document.body.innerHTML).not.toContain(AUTH_ID);
  });
});

describe("Enrollment key + hàng chờ duyệt", () => {
  /** approver thứ ba (không phải người xem, không phải người yêu cầu) */
  const THIRD = "0190d000-0000-7000-8000-0000000000bb";
  const queue = [
    request(REQ_1, { status: "pending_approval", method: "web_auth", device_label: "phone-binh", requested_by_membership_id: OTHER, target_membership_id: OTHER, issued_at: null, credential_expires_at: null }),
    request(REQ_3, { status: "pending_approval", method: "preauth_key", device_label: "my-own", issued_at: null, credential_expires_at: null }),
  ];
  const users = json(200, {
    items: [
      { id: ME, identity_id: "0190c000-0000-7000-8000-0000000000c1", display_name: "Nguyễn Văn A", email: "a@example.test", role: "tenant_admin", status: "active", headscale_username: `mg-${ME}`, version: 1 },
      { id: OTHER, identity_id: "0190c000-0000-7000-8000-0000000000c2", display_name: "Trần Thị Bình", email: "binh@example.test", role: "end_user", status: "active", headscale_username: `mg-${OTHER}`, version: 1 },
    ],
    next_cursor: null,
  });
  const listFor = (items: ReturnType<typeof request>[]) => (r: Request) => {
    const s = new URL(r.url).searchParams.get("status");
    return json(200, { items: s ? items.filter((x) => x.status === s) : items, next_cursor: null });
  };

  it("Tenant Admin: hàng chờ duyệt có tên người yêu cầu; duyệt yêu cầu của người khác ⇒ POST approve; yêu cầu của chính mình không có nút", async () => {
    let items = [...queue];
    const { requests } = mockApi(
      apiFor("tenant_admin", {
        [`GET ${base}/users`]: users,
        [`GET ${base}/enrollment/requests`]: (r) => listFor(items)(r),
        [`POST ${base}/enrollment/requests/${REQ_1}/approve`]: () => {
          items = items.map((x) => (x.id === REQ_1 ? { ...x, status: "approved" as const, approver_membership_id: ME } : x));
          return json(200, items[0]);
        },
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/enrollment-keys` });
    const q = await screen.findByTestId("approval-queue");
    const rows = within(q).getAllByTestId("enroll-row");
    expect(rows).toHaveLength(2);
    await waitFor(() => expect(rows[0]).toHaveTextContent("Trần Thị Bình"));
    expect(within(rows[1]!).getByTestId("needs-other-approver")).toHaveTextContent("Chờ người khác duyệt");
    expect(within(rows[1]!).queryByRole("button", { name: /Duyệt/ })).toBeNull();
    await userEvent.click(within(rows[0]!).getByRole("button", { name: "Duyệt yêu cầu phone-binh" }));
    const dialog = screen.getByRole("alertdialog");
    expect(dialog).toHaveTextContent("Trần Thị Bình");
    await userEvent.click(within(dialog).getByRole("button", { name: "Duyệt" }));
    expect(await screen.findAllByTestId("enroll-done")).not.toHaveLength(0);
    expect(posts(requests, `/enrollment/requests/${REQ_1}/approve`)).toHaveLength(1);
    await waitFor(() => expect(within(screen.getByTestId("approval-queue")).getAllByTestId("enroll-row")).toHaveLength(1));
  });

  it("từ chối ⇒ POST reject; 409 (người khác đã duyệt) ⇒ tải lại, hàng rời hàng chờ nhưng hộp vẫn mở với lỗi; 403 self_approval vẫn hiển thị nếu server từ chối", async () => {
    let n = 0;
    let items = [...queue];
    const { requests } = mockApi(
      apiFor("tenant_owner", {
        [`GET ${base}/users`]: users,
        [`GET ${base}/enrollment/requests`]: (r) => listFor(items)(r),
        [`POST ${base}/enrollment/requests/${REQ_1}/reject`]: () => {
          if (++n > 1) return problem(403, "forbidden");
          // approver khác vừa duyệt: server trả 409 not_pending_approval, hàng chờ (?status=pending_approval) không còn hàng này
          items = items.map((x) => (x.id === REQ_1 ? { ...x, status: "approved" as const, approver_membership_id: THIRD } : x));
          return conflict("not_pending_approval");
        },
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/enrollment-keys` });
    const q = await screen.findByTestId("approval-queue");
    await userEvent.click(within(q).getAllByRole("button", { name: "Từ chối yêu cầu phone-binh" })[0]!);
    const dialog = screen.getByRole("alertdialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Từ chối" }));
    await waitFor(() => expect(within(screen.getByTestId("approval-queue")).getAllByTestId("enroll-row")).toHaveLength(1));
    expect(screen.getByRole("alertdialog")).toBe(dialog);
    expect(within(dialog).getByText(/Xung đột với trạng thái hiện tại/)).toBeInTheDocument();
    expect(dialog).toHaveTextContent("Trần Thị Bình");
    await userEvent.click(within(dialog).getByRole("button", { name: "Từ chối" }));
    expect(await within(dialog).findByText("Bạn không có quyền thực hiện thao tác này.")).toBeInTheDocument();
    expect(posts(requests, `/enrollment/requests/${REQ_1}/reject`)).toHaveLength(2);
  });

  it("yêu cầu cuối của hàng chờ: duyệt ⇒ hàng chờ rỗng nhưng thông báo 'Đã duyệt' vẫn còn (role=status); 409 ⇒ hộp vẫn mở với lỗi", async () => {
    let items = [queue[0]!];
    let n = 0;
    mockApi(
      apiFor("tenant_admin", {
        [`GET ${base}/users`]: users,
        [`GET ${base}/enrollment/requests`]: (r) => listFor(items)(r),
        [`POST ${base}/enrollment/requests/${REQ_1}/approve`]: () => {
          items = items.map((x) => ({ ...x, status: "approved" as const, approver_membership_id: ME }));
          return json(200, items[0]);
        },
        [`POST ${base}/enrollment/requests/${REQ_3}/reject`]: () => {
          n++;
          items = items.map((x) => (x.id === REQ_3 ? { ...x, status: "approved" as const, approver_membership_id: THIRD } : x));
          return conflict("not_pending_approval");
        },
      }),
    );
    const { unmount } = renderApp({ path: `/t/${TENANT_A}/enrollment-keys` });
    const q = await screen.findByTestId("approval-queue");
    await userEvent.click(within(q).getByRole("button", { name: "Duyệt yêu cầu phone-binh" }));
    await userEvent.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Duyệt" }));
    expect(await screen.findByText("Không có yêu cầu nào chờ duyệt.")).toBeInTheDocument();
    expect(screen.getByTestId("enroll-done")).toHaveTextContent("Đã duyệt yêu cầu phone-binh");
    expect(screen.getByTestId("enroll-done")).toHaveAttribute("role", "status");
    unmount();

    // 409 trên yêu cầu cuối: hàng chờ rỗng sau khi tải lại — hộp không biến mất lặng lẽ
    items = [request(REQ_3, { status: "pending_approval", device_label: "tablet-binh", requested_by_membership_id: OTHER, target_membership_id: OTHER, issued_at: null, credential_expires_at: null })];
    renderApp({ path: `/t/${TENANT_A}/enrollment-keys` });
    const q2 = await screen.findByTestId("approval-queue");
    await userEvent.click(within(q2).getByRole("button", { name: "Từ chối yêu cầu tablet-binh" }));
    const dialog = screen.getByRole("alertdialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Từ chối" }));
    expect(await screen.findByText("Không có yêu cầu nào chờ duyệt.")).toBeInTheDocument();
    expect(screen.getByRole("alertdialog")).toHaveTextContent(/Xung đột với trạng thái hiện tại/);
    expect(n).toBe(1);
  });

  it("nhân viên nền tảng có Support Access Grant (support_operator, admin.): nút Duyệt/Từ chối theo rbac của role hiệu lực; duyệt ⇒ POST approve có CSRF; quyết định của support hiện 'bởi nhân viên hỗ trợ'; không nút tạo key", async () => {
    const GRANT = "0190a100-0000-7000-8000-0000000000c4";
    const REQ_4 = "0190b100-0000-7000-8000-000000000004";
    let items = [
      ...queue,
      request(REQ_2, { status: "rejected", method: "preauth_key", device_label: "nas-binh", requested_by_membership_id: OTHER, target_membership_id: OTHER, issued_at: null, credential_expires_at: null, approver_support_grant_id: GRANT }),
      request(REQ_4, { status: "approved", device_label: "pc-binh", requested_by_membership_id: OTHER, target_membership_id: OTHER, issued_at: null, credential_expires_at: null, approved_at: T0, approver_membership_id: THIRD }),
    ];
    const { requests } = mockApi({
      ...apiFor("end_user", {
        [`GET ${base}/users`]: users,
        [`GET ${base}/enrollment/requests`]: (r) => listFor(items)(r),
        [`POST ${base}/enrollment/requests/${REQ_1}/approve`]: () => {
          items = items.map((x) => (x.id === REQ_1 ? { ...x, status: "approved" as const, approved_at: T0, approver_support_grant_id: GRANT } : x));
          return json(200, items.find((x) => x.id === REQ_1));
        },
      }),
      "GET /auth/session": json(200, platformSession("platform_support", [
        { id: GRANT, tenant_id: TENANT_A, effective_role: "support_operator", expires_at: new Date(Date.now() + 3600_000).toISOString() },
      ])),
    });
    renderApp({ path: `/t/${TENANT_A}/enrollment-keys`, console: "platform" });
    const q = await screen.findByTestId("approval-queue");
    const rows = within(q).getAllByTestId("enroll-row");
    expect(rows).toHaveLength(2);
    // staff không có membership: cả hai yêu cầu đều của "người khác" ⇒ cả hai có nút
    expect(within(rows[1]!).getByRole("button", { name: "Duyệt yêu cầu my-own" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Tạo pre-auth key" })).toBeNull();
    const all = screen.getByTestId("all-requests");
    const rejected = within(all).getAllByTestId("enroll-row").find((r) => r.getAttribute("data-request") === REQ_2);
    expect(within(rejected!).getByTestId("decided-by-support")).toHaveTextContent("Từ chối bởi nhân viên hỗ trợ của nền tảng");
    await userEvent.click(within(rows[0]!).getByRole("button", { name: "Duyệt yêu cầu phone-binh" }));
    await userEvent.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Duyệt" }));
    expect(await screen.findByTestId("enroll-done")).toHaveTextContent("Đã duyệt yêu cầu phone-binh");
    const sent = posts(requests, `/enrollment/requests/${REQ_1}/approve`);
    expect(sent).toHaveLength(1);
    expect(sent[0]!.headers.get("X-CSRF-Token")).toBe(CSRF);
    await waitFor(() => {
      const row = within(screen.getByTestId("all-requests")).getAllByTestId("enroll-row").find((r) => r.getAttribute("data-request") === REQ_1);
      expect(within(row!).getByTestId("decided-by-support")).toHaveTextContent("Duyệt bởi nhân viên hỗ trợ của nền tảng");
    });
    // quyết định của thành viên (REQ_4) không mang dòng này
    const byMember = within(screen.getByTestId("all-requests")).getAllByTestId("enroll-row").find((r) => r.getAttribute("data-request") === REQ_4);
    expect(within(byMember!).queryByTestId("decided-by-support")).toBeNull();
    expect(within(screen.getByTestId("all-requests")).getAllByTestId("decided-by-support")).toHaveLength(2);
  });

  // G4b (C4): grant hết hạn/bị thu hồi sau khi trang đã mở ⇒ lần duyệt kế tiếp 403 (lớp 1 no_support_grant hoặc
  // support_grant_not_live trong transaction — server không nêu lý do) ⇒ hộp thoại nói rõ grant có thể đã kết thúc, link
  // tới Support Access; cùng 403 trên app. (thành viên) ⇒ không có dòng này
  it("nhân viên hỗ trợ: duyệt khi grant đã hết hạn/thu hồi ⇒ 403 ⇒ thông báo grant có thể đã kết thúc + link Support Access; thành viên (app.) ⇒ không", async () => {
    const GRANT = "0190a100-0000-7000-8000-0000000000c5";
    const routes = {
      [`GET ${base}/users`]: users,
      [`GET ${base}/enrollment/requests`]: listFor(queue),
      [`POST ${base}/enrollment/requests/${REQ_1}/approve`]: problem(403, "forbidden", { detail: "The support access grant is no longer live." }),
    };
    const { requests } = mockApi({
      ...apiFor("end_user", routes),
      "GET /auth/session": json(200, platformSession("platform_support", [
        { id: GRANT, tenant_id: TENANT_A, effective_role: "support_operator", expires_at: new Date(Date.now() + 3600_000).toISOString() },
      ])),
    });
    const first = renderApp({ path: `/t/${TENANT_A}/enrollment-keys`, console: "platform" });
    const q = await screen.findByTestId("approval-queue");
    await userEvent.click(within(q).getByRole("button", { name: "Duyệt yêu cầu phone-binh" }));
    const dialog = screen.getByRole("alertdialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Duyệt" }));
    const hint = await within(dialog).findByTestId("support-grant-ended");
    expect(hint).toHaveTextContent("Support Access Grant của bạn cho tenant này có thể đã hết hạn hoặc bị thu hồi");
    expect(within(hint).getByRole("link", { name: "Xem Support Access" })).toHaveAttribute("href", "/platform/support-access");
    expect(dialog).toHaveTextContent("Bạn không có quyền thực hiện thao tác này.");
    expect(posts(requests, `/enrollment/requests/${REQ_1}/approve`)).toHaveLength(1);
    expect(screen.queryByTestId("enroll-done")).toBeNull();
    first.unmount();

    mockApi(apiFor("tenant_admin", routes));
    renderApp({ path: `/t/${TENANT_A}/enrollment-keys` });
    const q2 = await screen.findByTestId("approval-queue");
    await userEvent.click(within(q2).getByRole("button", { name: "Duyệt yêu cầu phone-binh" }));
    const dialog2 = screen.getByRole("alertdialog");
    await userEvent.click(within(dialog2).getByRole("button", { name: "Duyệt" }));
    expect(await within(dialog2).findByText("Bạn không có quyền thực hiện thao tác này.")).toBeInTheDocument();
    expect(within(dialog2).queryByTestId("support-grant-ended")).toBeNull();
  });

  it("key reusable đã dùng (consumed) còn hạn ⇒ vẫn có nút Thu hồi ⇒ POST revoke; hết hạn hoặc không reusable ⇒ không có nút", async () => {
    const past = new Date(Date.now() - 60_000).toISOString();
    const live = request(REQ_2, { method: "preauth_key", status: "consumed", device_label: "ci-runner", tags: ["tag:ci"], reusable: true, target_membership_id: null });
    const old = request(REQ_1, { method: "preauth_key", status: "consumed", device_label: "old-runner", reusable: true, credential_expires_at: past, target_membership_id: null });
    const once = request(REQ_3, { method: "preauth_key", status: "consumed", device_label: "one-shot" });
    let revoked = false;
    const { requests } = mockApi(
      apiFor("tenant_admin", {
        [`GET ${base}/users`]: users,
        [`GET ${base}/enrollment/requests`]: (r) => listFor([revoked ? { ...live, status: "revoked" as const } : live, old, once])(r),
        [`POST ${base}/enrollment/requests/${REQ_2}/revoke`]: () => {
          revoked = true;
          return json(200, { ...live, status: "revoked" });
        },
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/enrollment-keys` });
    const all = await screen.findByTestId("all-requests");
    const rows = within(all).getAllByTestId("enroll-row");
    expect(rows).toHaveLength(3);
    expect(within(rows[1]!).queryByRole("button", { name: /Thu hồi/ })).toBeNull();
    expect(within(rows[2]!).queryByRole("button", { name: /Thu hồi/ })).toBeNull();
    await userEvent.click(within(rows[0]!).getByRole("button", { name: "Thu hồi yêu cầu ci-runner" }));
    await userEvent.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Thu hồi" }));
    expect(await screen.findByTestId("enroll-done")).toHaveTextContent("control plane xác nhận");
    expect(posts(requests, `/enrollment/requests/${REQ_2}/revoke`)).toHaveLength(1);
    await waitFor(() => expect(within(screen.getByTestId("all-requests")).getAllByTestId("enroll-row")[0]).toHaveAttribute("data-status", "revoked"));
  });

  it("thu hồi hai pha: 503 ⇒ 'chưa thu hồi', yêu cầu giữ nguyên; thử lại 200 ⇒ đã thu hồi (đã xác minh)", async () => {
    let n = 0;
    let revoked = false;
    const key = request(REQ_2, { method: "preauth_key", status: "issued", device_label: "ci-runner", tags: ["tag:ci"], reusable: true, target_membership_id: null });
    mockApi(
      apiFor("tenant_admin", {
        [`GET ${base}/users`]: users,
        [`GET ${base}/enrollment/requests`]: () => json(200, { items: [revoked ? { ...key, status: "revoked" } : key], next_cursor: null }),
        [`POST ${base}/enrollment/requests/${REQ_2}/revoke`]: () => {
          if (++n === 1) return problem(503, "instance_unavailable");
          revoked = true;
          return json(200, { ...key, status: "revoked" });
        },
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/enrollment-keys` });
    const all = await screen.findByTestId("all-requests");
    const row = within(all).getByTestId("enroll-row");
    expect(row).toHaveTextContent("tag:ci");
    expect(row).toHaveTextContent("Dùng nhiều lần (reusable)");
    expect(row).toHaveTextContent("Chỉ tag (không chủ)");
    await userEvent.click(within(row).getByRole("button", { name: "Thu hồi yêu cầu ci-runner" }));
    const dialog = screen.getByRole("alertdialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Thu hồi" }));
    expect(await within(dialog).findByTestId("revoke-not-applied")).toHaveTextContent("Chưa thu hồi");
    expect(within(all).getByTestId("enroll-row")).toHaveAttribute("data-status", "issued");
    await userEvent.click(within(dialog).getByRole("button", { name: "Thu hồi" }));
    expect(await screen.findByTestId("enroll-done")).toHaveTextContent("control plane xác nhận");
    await waitFor(() => expect(within(screen.getByTestId("all-requests")).getByTestId("enroll-row")).toHaveAttribute("data-status", "revoked"));
  });

  it("key đặc quyền (Tenant Admin): chọn thành viên, tag từ danh mục, reusable ⇒ POST /enrollment/keys; key một lần", async () => {
    const { requests } = mockApi(
      apiFor("tenant_admin", {
        [`GET ${base}/users`]: users,
        [`GET ${base}/tags`]: json(200, { items: [tag("tag:ci", 1), tag("tag:server", 2)], next_cursor: null }),
        [`POST ${base}/enrollment/keys`]: json(201, keyIssue({ target_membership_id: OTHER, tags: ["tag:ci"], reusable: true })),
      }),
    );
    const { router, queryClient } = renderApp({ path: `/t/${TENANT_A}/enrollment-keys` });
    await userEvent.click(await screen.findByRole("button", { name: "Tạo pre-auth key" }));
    const dialog = screen.getByRole("dialog", { name: "Tạo pre-auth key" });
    await userEvent.click(within(dialog).getByLabelText("Thành viên khác"));
    const submit = within(dialog).getByRole("button", { name: "Tạo key" });
    expect(submit).toBeDisabled(); // chưa chọn thành viên
    await userEvent.selectOptions(await within(dialog).findByLabelText("Thành viên"), OTHER);
    expect(within(within(dialog).getByLabelText("Thành viên")).queryByRole("option", { name: /Nguyễn Văn A/ })).toBeNull();
    await userEvent.click(await within(dialog).findByLabelText("tag:ci"));
    await userEvent.click(within(dialog).getByLabelText(/Dùng nhiều lần/));
    await userEvent.type(within(dialog).getByLabelText("Nhãn thiết bị (tùy chọn)"), "ci-runner");
    await userEvent.click(submit);
    const reveal = await screen.findByRole("dialog", { name: "Pre-auth key (hiển thị một lần)" });
    expect(within(reveal).getByTestId("secret-value")).toHaveTextContent(PREAUTH_KEY);
    const post = posts(requests, "/enrollment/keys")[0]!;
    expect(await post.json()).toEqual({ target_membership_id: OTHER, tags: ["tag:ci"], reusable: true, ephemeral: false, device_label: "ci-runner", ttl_minutes: 15 });
    expect(post.headers.get("Idempotency-Key")).toMatch(UUID_RE);
    await userEvent.click(within(reveal).getByLabelText("Tôi đã lưu key ở nơi an toàn."));
    await userEvent.click(within(reveal).getByRole("button", { name: "Đóng và xóa key khỏi màn hình" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expectNoTrace(PREAUTH_KEY, router, queryClient);
  });

  it("key chỉ-tag cần ít nhất một tag; 422 tag ngoài danh mục; 410 secret_no_longer_available ⇒ đề nghị thu hồi rồi tạo lại", async () => {
    let n = 0;
    mockApi(
      apiFor("tenant_owner", {
        [`GET ${base}/tags`]: json(200, { items: [tag("tag:server", 2)], next_cursor: null }),
        [`POST ${base}/enrollment/keys`]: () => (++n === 1 ? invalid("tags", "tag_not_in_catalog") : problem(410, "secret_no_longer_available")),
      }),
    );
    renderApp({ path: `/t/${TENANT_A}/enrollment-keys` });
    await userEvent.click(await screen.findByRole("button", { name: "Tạo pre-auth key" }));
    const dialog = screen.getByRole("dialog", { name: "Tạo pre-auth key" });
    await userEvent.click(within(dialog).getByLabelText(/Chỉ tag/));
    expect(within(dialog).getByRole("button", { name: "Tạo key" })).toBeDisabled();
    await userEvent.click(await within(dialog).findByLabelText("tag:server"));
    await userEvent.click(within(dialog).getByRole("button", { name: "Tạo key" }));
    expect(await within(dialog).findByText("Dữ liệu không hợp lệ.")).toBeInTheDocument();
    expect(within(dialog).getByText("tags")).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Tạo key" }));
    expect(await within(dialog).findByTestId("secret-gone")).toHaveTextContent("thu hồi yêu cầu");
  });

  it("Tenant Operator (không issue_privileged): chỉ key một lần của chính mình qua POST /enrollment/requests; không có tùy chọn đặc quyền", async () => {
    const { requests } = mockApi(apiFor("tenant_operator", { [`POST ${base}/enrollment/requests`]: json(201, keyIssue()) }));
    renderApp({ path: `/t/${TENANT_A}/enrollment-keys` });
    await userEvent.click(await screen.findByRole("button", { name: "Tạo pre-auth key" }));
    const dialog = screen.getByRole("dialog", { name: "Tạo pre-auth key" });
    expect(within(dialog).queryByTestId("key-owner")).toBeNull();
    expect(within(dialog).queryByTestId("key-tags")).toBeNull();
    expect(within(dialog).queryByLabelText(/Dùng nhiều lần/)).toBeNull();
    await userEvent.click(within(dialog).getByRole("button", { name: "Tạo key" }));
    await screen.findByRole("dialog", { name: "Pre-auth key (hiển thị một lần)" });
    expect(await posts(requests, "/enrollment/requests")[0]!.json()).toEqual({ method: "preauth_key", ttl_minutes: 15 });
    expect(posts(requests, "/enrollment/keys")).toHaveLength(0);
  });

  it("Tenant Viewer chỉ đọc (không tạo, không thao tác); End User không có mục (403 thống nhất)", async () => {
    mockApi(apiFor("tenant_viewer", { [`GET ${base}/enrollment/requests`]: listFor(queue) }));
    const { unmount } = renderApp({ path: `/t/${TENANT_A}/enrollment-keys` });
    const all = await screen.findByTestId("all-requests");
    expect(within(all).getAllByTestId("enroll-row")).toHaveLength(2);
    expect(screen.queryByRole("button", { name: /Tạo pre-auth key|Duyệt|Từ chối|Thu hồi/ })).toBeNull();
    expect(screen.queryByTestId("approval-queue")).toBeNull();
    unmount();
    mockApi(apiFor("end_user"));
    renderApp({ path: `/t/${TENANT_A}/enrollment-keys` });
    await screen.findByRole("heading", { name: "Không có quyền", level: 1 });
  });

  it("lọc trạng thái gửi ?status= tới API", async () => {
    const { requests } = mockApi(apiFor("tenant_admin", { [`GET ${base}/enrollment/requests`]: listFor(queue) }));
    renderApp({ path: `/t/${TENANT_A}/enrollment-keys` });
    await screen.findByTestId("all-requests");
    await userEvent.selectOptions(screen.getByLabelText("Trạng thái"), "revoked");
    expect(await screen.findByText("Chưa có yêu cầu nào.")).toBeInTheDocument();
    expect(requests.some((r) => r.method === "GET" && new URL(r.url).searchParams.get("status") === "revoked")).toBe(true);
  });
});
