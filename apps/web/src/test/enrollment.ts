// Dữ liệu mẫu của màn hình enrollment (P4-T08) — đúng schema của api/openapi.yaml (type sinh, P4-T06), chỉ dùng trong
// test. Key/mã/Auth ID là giá trị giả dựng bằng nối chuỗi (gitleaks), entropy thấp.
import type { components } from "../api/schema";
import { problem } from "./helpers";

type S = components["schemas"];

/** membership của phần tử đầu trong tenantSession() (helpers.ts) — "tôi" */
export const ME = "0190d000-0000-7000-8000-000000000000";
export const OTHER = "0190d000-0000-7000-8000-0000000000aa";
export const REQ_1 = "0190b100-0000-7000-8000-000000000001";
export const REQ_2 = "0190b100-0000-7000-8000-000000000002";
export const REQ_3 = "0190b100-0000-7000-8000-000000000003";
export const LOGIN_SERVER = "https://tenant-a.mesh.example.test";
export const AUTH_ID = "hskey-authreq-" + "AbCdEfGh1234".repeat(2);
export const AUTH_ID_2 = "hskey-authreq-" + "ZyXwVuTs9876".repeat(2);
export const PREAUTH_KEY = "hskey-auth-" + "k3yK3yK3y0".repeat(4);
export const ENROLL_CODE = "abcdefgh2345";
export const T0 = "2026-11-19T03:00:00Z";
export const SOON = new Date(Date.now() + 10 * 60_000).toISOString();

export function request(id: string, over: Partial<S["EnrollmentRequest"]> = {}): S["EnrollmentRequest"] {
  return {
    id,
    method: "web_auth",
    status: "issued",
    device_label: "laptop-an",
    tags: [],
    ephemeral: false,
    reusable: false,
    requested_by_membership_id: ME,
    target_membership_id: ME,
    approver_membership_id: null,
    approved_at: null,
    issued_at: T0,
    credential_expires_at: SOON,
    claimed_at: null,
    node_id: null,
    failure_code: null,
    login_server: LOGIN_SERVER,
    created_at: T0,
    updated_at: T0,
    version: 1,
    ...over,
  };
}

export function webIssue(over: Partial<S["EnrollmentRequest"]> = {}): S["EnrollmentIssue"] {
  return {
    request: request(REQ_1, over),
    credential: {
      kind: "enroll_code",
      enroll_code: ENROLL_CODE,
      hostname: `mg-${ENROLL_CODE}`,
      command: `tailscale up --login-server=${LOGIN_SERVER} --hostname=mg-${ENROLL_CODE}`,
      expires_at: SOON,
    },
  };
}

export function keyIssue(over: Partial<S["EnrollmentRequest"]> = {}): S["EnrollmentIssue"] {
  return {
    request: request(REQ_2, { method: "preauth_key", device_label: "ci-runner", ...over }),
    credential: {
      kind: "preauth_key",
      preauth_key: PREAUTH_KEY,
      command: `tailscale up --login-server=${LOGIN_SERVER} --auth-key="$TS_AUTHKEY"`,
      expires_at: SOON,
    },
  };
}

export function instructions(os: S["EnrollmentOS"], over: Partial<S["EnrollmentInstructions"]> = {}): S["EnrollmentInstructions"] {
  const mobile = os === "ios" || os === "android";
  return {
    os,
    login_server: LOGIN_SERVER,
    steps: ["step 1", "step 2", "step 3"],
    web_auth_command: mobile ? null : `tailscale up --login-server=${LOGIN_SERVER} --hostname=mg-<code>`,
    preauth_key_command: mobile ? null : `tailscale up --login-server=${LOGIN_SERVER} --auth-key="$TS_AUTHKEY"`,
    privacy_notice: "The official Tailscale client may send diagnostic logs…",
    managed_env: { TS_NO_LOGS_NO_SUPPORT: "true" },
    self_enroll: true,
    ...over,
  };
}

/** 409 của enrollment với lý do ổn định (Problem.errors[0].code — P4-T08). */
export function conflict(reason: string): Response {
  return problem(409, "conflict", { detail: "d", errors: [{ field: "request", code: reason, message: "d" }] });
}

export function invalid(field: string, reason: string): Response {
  return problem(422, "validation_failed", { detail: "d", errors: [{ field, code: reason, message: "d" }] });
}
