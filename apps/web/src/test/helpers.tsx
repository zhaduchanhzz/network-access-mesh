// Công cụ test: API giả ở tầng fetch (đúng hợp đồng HTTP của spec — JSON / problem+json, header), session mẫu, và
// render toàn bộ App trên router bộ nhớ.
import { render } from "@testing-library/react";
import { createMemoryRouter } from "react-router";
import { vi } from "vitest";
import type { components } from "../api/schema";
import { createQueryClient } from "../api/queryClient";
import { App } from "../app/App";
import type { ConsoleKind } from "../app/console";
import { routes } from "../app/routes";

export type Session = components["schemas"]["Session"];
export type Problem = components["schemas"]["Problem"];

export const TENANT_A = "0190a000-0000-7000-8000-00000000000a";
export const TENANT_B = "0190b000-0000-7000-8000-00000000000b";
export const CSRF = "csrf-test-token-7f3a9c";

export function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "X-Request-Id": "req-test", ...headers },
  });
}

export function problem(status: number, code: Problem["code"], extra: Partial<Problem> = {}, headers: Record<string, string> = {}): Response {
  const body: Problem = {
    type: `urn:meshguard:problem:${code}`,
    title: code,
    status,
    code,
    request_id: "req-problem-1",
    ...extra,
  };
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/problem+json", "X-Request-Id": "req-problem-1", ...headers },
  });
}

export function tenantSession(memberships: { tenantId: string; slug: string; name: string; role: string }[]): Session {
  const now = Date.now();
  return {
    principal: { identity_id: "0190c000-0000-7000-8000-0000000000c1", scope: "tenant", idp_id: "0190c000-0000-7000-8000-0000000000d1", display_name: "Nguyễn Văn A", email: "a@example.test" },
    origin: "app",
    csrf_token: CSRF,
    auth_time: new Date(now - 60_000).toISOString(),
    idle_expires_at: new Date(now + 30 * 60_000).toISOString(),
    absolute_expires_at: new Date(now + 12 * 3600_000).toISOString(),
    memberships: memberships.map((m, i) => ({
      membership_id: `0190d000-0000-7000-8000-00000000000${i}`,
      tenant_id: m.tenantId,
      tenant_slug: m.slug,
      tenant_name: m.name,
      role: m.role,
      status: "active",
    })),
    support_grants: [],
  };
}

export function platformSession(role: string, grants: Session["support_grants"] = []): Session {
  const now = Date.now();
  return {
    principal: { identity_id: "0190e000-0000-7000-8000-0000000000e1", scope: "platform", idp_id: "0190e000-0000-7000-8000-0000000000f1", display_name: "Ops Staff", platform_role: role },
    origin: "admin",
    csrf_token: CSRF,
    auth_time: new Date(now - 60_000).toISOString(),
    idle_expires_at: new Date(now + 15 * 60_000).toISOString(),
    absolute_expires_at: new Date(now + 8 * 3600_000).toISOString(),
    memberships: [],
    support_grants: grants,
  };
}

export function tenantBody(id: string, slug: string, status: components["schemas"]["TenantStatus"] = "active") {
  return {
    id,
    slug,
    name: slug.toUpperCase(),
    status,
    deployment_region: "lab",
    plan: "standard",
    limits: {},
    control_url: `https://${slug}.mesh.example.test`,
    created_at: "2026-11-01T00:00:00Z",
    updated_at: "2026-11-01T00:00:00Z",
    version: 1,
  };
}

export type Handler = (req: Request) => Response | Promise<Response>;

/** Thay globalThis.fetch: `routes` theo khóa "METHOD /đường-dẫn-sau-/api/v1"; request không có route ⇒ 404 problem. */
export function mockApi(routes: Record<string, Handler | Response>) {
  const requests: Request[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = input instanceof Request ? input : new Request(input, init);
    requests.push(req.clone());
    const url = new URL(req.url);
    const path = url.pathname.replace(/^\/api\/v1/, "");
    const h = routes[`${req.method} ${path}`];
    if (h === undefined) return problem(404, "not_found");
    return h instanceof Response ? h.clone() : h(req);
  });
  vi.stubGlobal("fetch", fetchMock);
  return { requests, fetchMock };
}

export function renderApp(opts: { path: string; console?: ConsoleKind }) {
  const queryClient = createQueryClient();
  const defaults = queryClient.getDefaultOptions();
  queryClient.setDefaultOptions({ ...defaults, queries: { ...defaults.queries, retry: false } });
  const router = createMemoryRouter(routes, { initialEntries: [opts.path] });
  const utils = render(<App router={router} queryClient={queryClient} console={opts.console ?? "tenant"} />);
  return { ...utils, router, queryClient };
}
