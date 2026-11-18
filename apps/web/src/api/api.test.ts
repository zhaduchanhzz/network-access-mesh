// Tầng API: problem+json → ApiError, Retry-After, CSRF chỉ cho method không an toàn, lỗi mạng, query key theo tenant.
import { QueryClient } from "@tanstack/react-query";
import { describe, expect, it, vi } from "vitest";
import { json, mockApi, problem, TENANT_A } from "../test/helpers";
import { api, call, onApiError, setCsrfToken } from "./client";
import { ApiError, parseRetryAfter } from "./problem";
import { assertQueryKey, createQueryClient, GLOBAL, PLATFORM, queryKeys } from "./queryClient";

describe("parseRetryAfter", () => {
  it("delta-seconds, HTTP-date, giá trị lạ", () => {
    const now = Date.parse("2026-11-19T10:00:00Z");
    expect(parseRetryAfter("120", now)).toBe(120);
    expect(parseRetryAfter("Thu, 19 Nov 2026 10:00:30 GMT", now)).toBe(30);
    expect(parseRetryAfter("Thu, 19 Nov 2026 09:00:00 GMT", now)).toBe(0);
    expect(parseRetryAfter("-5", now)).toBeNull();
    expect(parseRetryAfter("soon", now)).toBeNull();
    expect(parseRetryAfter(null, now)).toBeNull();
  });
});

describe("ApiError.fromResponse", () => {
  it("problem+json: code, request id, Retry-After, errors[]", async () => {
    const r = problem(422, "validation_failed", { errors: [{ field: "name", code: "required", message: "bắt buộc" }] }, { "Retry-After": "3" });
    const e = ApiError.fromResponse(r, await r.clone().json());
    expect(e.status).toBe(422);
    expect(e.code).toBe("validation_failed");
    expect(e.requestId).toBe("req-problem-1");
    expect(e.retryAfter).toBe(3);
    expect(e.problem?.errors?.[0]?.field).toBe("name");
  });

  it("body không phải problem+json hoặc mã lạ ⇒ unexpected_response", () => {
    const html = new Response("<html/>", { status: 502, headers: { "Content-Type": "text/html" } });
    expect(ApiError.fromResponse(html, "<html/>").code).toBe("unexpected_response");
    const odd = new Response("{}", { status: 400, headers: { "Content-Type": "application/problem+json" } });
    expect(ApiError.fromResponse(odd, { type: "x", title: "t", status: 400, code: "made_up", request_id: "r" }).code).toBe(
      "unexpected_response",
    );
  });
});

describe("client", () => {
  it("chỉ gọi /api/v1 cùng origin; CSRF chỉ cho method không an toàn; credentials same-origin", async () => {
    const { requests } = mockApi({
      "GET /auth/session": json(200, { ok: true }),
      "POST /auth/logout": json(200, { redirect_to: "https://idp.example.test/logout" }),
    });
    setCsrfToken("tok-1");
    await call(api.GET("/auth/session"));
    await call(api.POST("/auth/logout"));
    const [get, post] = requests;
    expect(new URL(get!.url).origin).toBe(window.location.origin);
    expect(new URL(get!.url).pathname).toBe("/api/v1/auth/session");
    expect(get!.headers.get("X-CSRF-Token")).toBeNull();
    expect(post!.headers.get("X-CSRF-Token")).toBe("tok-1");
    expect(post!.credentials).toBe("same-origin");
  });

  it("lỗi ⇒ ApiError và listener được báo; notify:false thì không", async () => {
    mockApi({ "GET /auth/session": problem(401, "reauth_required") });
    const seen: string[] = [];
    const off = onApiError((e) => seen.push(e.code));
    await expect(call(api.GET("/auth/session"))).rejects.toMatchObject({ status: 401, code: "reauth_required" });
    await expect(call(api.GET("/auth/session"), { notify: false })).rejects.toBeInstanceOf(ApiError);
    off();
    expect(seen).toEqual(["reauth_required"]);
  });

  it("không tới được server ⇒ network_error", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new TypeError("Failed to fetch"))));
    await expect(call(api.GET("/auth/session"))).rejects.toMatchObject({ status: 0, code: "network_error" });
  });
});

describe("query key theo tenant", () => {
  it("chỉ chấp nhận key bắt đầu bằng tenantId (UUID), GLOBAL hoặc PLATFORM", () => {
    expect(() => {
      assertQueryKey(queryKeys.tenant(TENANT_A, "devices"));
    }).not.toThrow();
    expect(() => {
      assertQueryKey(queryKeys.session());
    }).not.toThrow();
    expect(() => {
      assertQueryKey(queryKeys.platform("tenants"));
    }).not.toThrow();
    expect(queryKeys.tenant(TENANT_A, "devices")[0]).toBe(TENANT_A);
    expect(queryKeys.session()[0]).toBe(GLOBAL);
    expect(queryKeys.platform()[0]).toBe(PLATFORM);
    expect(() => queryKeys.tenant("tenant-a", "devices")).toThrow();
    for (const bad of [["devices", TENANT_A], [42], [], [{ tenant: TENANT_A }]]) {
      expect(() => {
        assertQueryKey(bad);
      }).toThrow();
    }
  });

  it("QueryClient từ chối query có key sai ngay khi dùng", async () => {
    const qc = createQueryClient();
    await expect(qc.query({ queryKey: ["devices"], queryFn: () => 1 })).rejects.toThrow(/tenantId/);
    await expect(qc.query({ queryKey: queryKeys.tenant(TENANT_A, "x"), queryFn: () => 1 })).resolves.toBe(1);
  });

  it("cache của hai tenant tách biệt", async () => {
    const qc: QueryClient = createQueryClient();
    const B = "0190b000-0000-7000-8000-00000000000b";
    await qc.query({ queryKey: queryKeys.tenant(TENANT_A, "devices"), queryFn: () => ["a1"] });
    await qc.query({ queryKey: queryKeys.tenant(B, "devices"), queryFn: () => ["b1"] });
    expect(qc.getQueryData(queryKeys.tenant(TENANT_A, "devices"))).toEqual(["a1"]);
    expect(qc.getQueryData(queryKeys.tenant(B, "devices"))).toEqual(["b1"]);
    qc.removeQueries({ queryKey: [TENANT_A] });
    expect(qc.getQueryData(queryKeys.tenant(TENANT_A, "devices"))).toBeUndefined();
    expect(qc.getQueryData(queryKeys.tenant(B, "devices"))).toEqual(["b1"]);
  });

  it("thử lại 429/503 theo Retry-After (trần 60 s); 401/403/404 không thử lại", () => {
    const opts = createQueryClient().getDefaultOptions().queries!;
    const retry = opts.retry as (n: number, e: unknown) => boolean;
    const delay = opts.retryDelay as (n: number, e: unknown) => number;
    const e429 = new ApiError({ status: 429, code: "rate_limited", retryAfter: 7 });
    expect(retry(0, e429)).toBe(true);
    expect(retry(2, e429)).toBe(false);
    expect(delay(0, e429)).toBe(7000);
    expect(delay(0, new ApiError({ status: 503, code: "maintenance", retryAfter: 3600 }))).toBe(60_000);
    for (const [status, code] of [[401, "unauthenticated"], [403, "forbidden"], [404, "not_found"]] as const) {
      expect(retry(0, new ApiError({ status, code }))).toBe(false);
    }
  });
});
