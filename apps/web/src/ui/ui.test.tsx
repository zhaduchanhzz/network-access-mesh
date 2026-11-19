// Hạ tầng UI dùng chung (P4-T04, hợp nhất với P4-T02): Location của job phạm vi tenant, Idempotency-Key tường minh,
// trạng thái cuối của job, thời gian tương đối. Hộp xác nhận: ui/ConfirmDialog.test.tsx.
import { renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { newIdempotencyKey, useIdempotencyKey } from "../api/idempotency";
import { isSettled, tenantJobFromLocation } from "../api/jobs";
import { TENANT_A, TENANT_B } from "../test/helpers";
import { formatRelative } from "./time";

const JOB = "0190a200-0000-7000-8000-000000000001";

describe("tenantJobFromLocation", () => {
  it("chỉ nhận /api/v1/tenants/<tenant đang xem>/jobs/<uuid> tương đối", () => {
    expect(tenantJobFromLocation(`/api/v1/tenants/${TENANT_A}/jobs/${JOB}`, TENANT_A)).toBe(JOB);
    expect(tenantJobFromLocation(`/api/v1/tenants/${TENANT_A.toUpperCase()}/jobs/${JOB.toUpperCase()}`, TENANT_A)).toBe(JOB);
    for (const bad of [
      `/api/v1/tenants/${TENANT_B}/jobs/${JOB}`,
      `https://evil.example/api/v1/tenants/${TENANT_A}/jobs/${JOB}`,
      `//evil.example/api/v1/tenants/${TENANT_A}/jobs/${JOB}`,
      `/api/v1/platform/jobs/${JOB}`,
      `/api/v1/tenants/${TENANT_A}/jobs/${JOB}/../x`,
      "",
    ]) {
      expect(tenantJobFromLocation(bad, TENANT_A), bad).toBeNull();
    }
    expect(tenantJobFromLocation(null, TENANT_A)).toBeNull();
  });
});

describe("idempotency", () => {
  it("một khóa cho một ý định; reset ⇒ khóa mới; khóa đúng pattern của spec", () => {
    const { result } = renderHook(() => useIdempotencyKey());
    const a = result.current.current();
    expect(result.current.current()).toBe(a);
    result.current.reset();
    expect(result.current.current()).not.toBe(a);
    expect(newIdempotencyKey()).toMatch(/^[\x21-\x7E]{8,255}$/);
  });
});

describe("jobs + time", () => {
  it("trạng thái cuối của job (ngừng poll) — failed_resumable chỉ đổi khi người vận hành /retry, /rollback (§11.3)", () => {
    expect(["succeeded", "failed", "cancelled", "rolled_back", "failed_resumable"].every((s) => isSettled(s as never))).toBe(true);
    expect(["queued", "running", "compensating"].some((s) => isSettled(s as never))).toBe(false);
    expect(isSettled(undefined)).toBe(false);
  });

  it("thời gian tương đối theo locale", () => {
    const now = Date.parse("2026-11-19T01:00:00Z");
    expect(formatRelative("2026-11-19T00:55:00Z", "vi", now)).toBe("5 phút trước");
    expect(formatRelative("2026-11-19T00:55:00Z", "en", now)).toBe("5 minutes ago");
    expect(formatRelative("2026-11-22T01:00:00Z", "en", now)).toBe("in 3 days");
    expect(formatRelative("không-phải", "vi", now)).toBe("");
  });
});
