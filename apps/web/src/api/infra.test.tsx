// Hạ tầng UI dùng chung của P4-T02 (dùng lại ở các task UI sau): Idempotency-Key, ETag/If-Match, poll job + Location,
// JSON chuẩn hóa của payload phê duyệt, phân trang con trỏ.
import { QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { ReactNode } from "react";
import { describe, expect, it } from "vitest";
import { json, mockApi, problem } from "../test/helpers";
import { canonicalJson, payloadSha256, sha256Hex } from "./canonical";
import { api } from "./client";
import { callWithETag, ifMatch, isMissingVersion, isStaleVersion } from "./etag";
import { fingerprintOf, IdempotencyKeys, newIdempotencyKey, useIdempotentMutation } from "./idempotency";
import { approvalFromLocation, isSettled, jobFromLocation, jobPollInterval, JOB_STATUSES, plannedSteps, PROVISION_STEPS } from "./jobs";
import { useCursorPager } from "./pagination";
import { ApiError } from "./problem";
import { createQueryClient } from "./queryClient";

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const J = "0190f100-0000-7000-8000-000000000001";
const T = "0190f000-0000-7000-8000-000000000001";

describe("Idempotency-Key", () => {
  it("khóa mới là UUID v4, khớp ràng buộc của spec (8–255 ký tự ASCII in được)", () => {
    const a = newIdempotencyKey();
    expect(a).toMatch(UUID_V4);
    expect(a).toMatch(/^[\x21-\x7E]{8,255}$/);
    expect(newIdempotencyKey()).not.toBe(a);
  });

  it("cùng nội dung ⇒ cùng khóa; nội dung đổi ⇒ khóa mới; settle ⇒ ý định mới", () => {
    const k = new IdempotencyKeys();
    const first = k.keyFor("a");
    expect(k.keyFor("a")).toBe(first);
    const second = k.keyFor("b");
    expect(second).not.toBe(first);
    expect(k.keyFor("a")).not.toBe(first); // quay lại nội dung cũ vẫn là ý định mới
    k.settle();
    expect(k.keyFor("a")).not.toBe(first);
  });

  it("fingerprint không phụ thuộc thứ tự khóa của object", () => {
    expect(fingerprintOf({ b: 1, a: { d: 2, c: [3, { y: 1, x: 2 }] } })).toBe(fingerprintOf({ a: { c: [3, { x: 2, y: 1 }], d: 2 }, b: 1 }));
    expect(fingerprintOf({ a: 1 })).not.toBe(fingerprintOf({ a: 2 }));
  });

  it("useIdempotentMutation: thử lại sau lỗi mạng dùng lại khóa; thành công xong ⇒ khóa mới", async () => {
    const seen: string[] = [];
    let fail = true;
    const qc = createQueryClient();
    const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
    const { result } = renderHook(
      () =>
        useIdempotentMutation({
          mutationFn: (v: { slug: string }, key: string) => {
            seen.push(`${v.slug}:${key}`);
            return fail ? Promise.reject(ApiError.network()) : Promise.resolve(v.slug);
          },
        }),
      { wrapper },
    );
    await act(async () => {
      await result.current.mutateAsync({ slug: "acme" }).catch(() => undefined);
    });
    fail = false;
    await act(async () => {
      await result.current.mutateAsync({ slug: "acme" });
    });
    await act(async () => {
      await result.current.mutateAsync({ slug: "acme" });
    });
    const keys = seen.map((s) => s.split(":")[1]);
    expect(keys[0]).toMatch(UUID_V4);
    expect(keys[1]).toBe(keys[0]); // cùng ý định, gửi lại
    expect(keys[2]).not.toBe(keys[0]); // đã thành công ⇒ ý định mới
  });
});

describe("ETag / If-Match", () => {
  it("callWithETag trả dữ liệu kèm ETag nguyên văn", async () => {
    mockApi({ [`GET /platform/tenants/${T}`]: json(200, { id: T }, { ETag: 'W/"7"' }) });
    const r = await callWithETag(api.GET("/platform/tenants/{tenantId}", { params: { path: { tenantId: T } } }));
    expect(r.etag).toBe('W/"7"');
    expect(r.data.id).toBe(T);
  });

  it("If-Match chỉ với ETag thật (không `*`, không thiếu)", () => {
    expect(ifMatch('"3"')).toEqual({ "If-Match": '"3"' });
    expect(() => ifMatch(null)).toThrow();
    expect(() => ifMatch("*")).toThrow();
    expect(isStaleVersion(new ApiError({ status: 412, code: "precondition_failed" }))).toBe(true);
    expect(isMissingVersion(new ApiError({ status: 428, code: "precondition_required" }))).toBe(true);
    expect(isStaleVersion(new ApiError({ status: 409, code: "conflict" }))).toBe(false);
  });

  it("412 của server ⇒ ApiError precondition_failed", async () => {
    mockApi({ [`GET /platform/tenants/${T}`]: problem(412, "precondition_failed") });
    await expect(callWithETag(api.GET("/platform/tenants/{tenantId}", { params: { path: { tenantId: T } } }), { notify: false })).rejects.toSatisfy(
      isStaleVersion,
    );
  });
});

describe("job: Location + poll", () => {
  it("Location ⇒ job/approval chỉ với dạng của spec", () => {
    expect(jobFromLocation(`/api/v1/platform/jobs/${J}`)).toEqual({ scope: "platform", jobId: J });
    expect(jobFromLocation(`/api/v1/tenants/${T}/jobs/${J.toUpperCase()}`)).toEqual({ scope: "tenant", tenantId: T, jobId: J });
    for (const bad of [null, "", `https://evil.test/api/v1/platform/jobs/${J}`, `/api/v1/platform/jobs/${J}/x`, "/api/v1/platform/jobs/1", `//x/api/v1/platform/jobs/${J}`]) {
      expect(jobFromLocation(bad)).toBeNull();
    }
    expect(approvalFromLocation(`/api/v1/platform/approvals/${J}`)).toBe(J);
    expect(approvalFromLocation(`/api/v1/tenants/${T}/approvals/${J}`)).toBe(J);
    expect(approvalFromLocation(`/api/v1/platform/jobs/${J}`)).toBeNull();
  });

  it("poll: 2 s phút đầu, rồi 5 s; dừng ở trạng thái cuối (gồm failed_resumable — chờ người vận hành)", () => {
    expect(jobPollInterval("queued", 0, 10_000)).toBe(2_000);
    expect(jobPollInterval("running", 0, 61_000)).toBe(5_000);
    expect(jobPollInterval(undefined, 0, 0)).toBe(2_000);
    for (const s of JOB_STATUSES) {
      const settled = ["succeeded", "failed", "cancelled", "rolled_back", "failed_resumable"].includes(s);
      expect(isSettled(s)).toBe(settled);
      expect(jobPollInterval(s, 0, 0) === false).toBe(settled);
    }
  });

  it("19 bước của tenant.provision trùng orchestrator.Steps (Go)", () => {
    const go = readFileSync(join(import.meta.dirname, "../../../../internal/provisioning/orchestrator/model.go"), "utf8");
    const consts = new Map([...go.matchAll(/^\s+(Step\w+)\s+=\s+"([^"]+)"/gm)].map((m) => [m[1], m[2]]));
    const list = /var Steps = \[\]string\{([^}]+)\}/.exec(go)?.[1] ?? "";
    const goSteps = list
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .map((n) => consts.get(n));
    expect(goSteps).toHaveLength(19);
    expect([...PROVISION_STEPS]).toEqual(goSteps);
    expect(plannedSteps("tenant.provision")).toBe(PROVISION_STEPS);
    expect(plannedSteps("tenant.suspend")).toEqual([]);
  });
});

describe("JSON chuẩn hóa + payload_sha256 (giống internal/authz/approvals/canonical.go)", () => {
  // vector: mã hóa Go (encoding/json, SetEscapeHTML(false), khóa sắp theo byte) — tính lại bằng scripts của evidence
  it("payload xóa tenant và payload tắt 4-eyes", async () => {
    const del = { tenant_id: "0190f000-0000-7000-8000-000000000001", slug: "acme", skip_final_backup: false };
    expect(canonicalJson(del)).toBe('{"skip_final_backup":false,"slug":"acme","tenant_id":"0190f000-0000-7000-8000-000000000001"}');
    expect(await payloadSha256(del)).toBe("8849b3e4f9be00afd652626bbad0ea938cb8af66ac5afd3820a7a2621be07d06");
    expect(await payloadSha256({ value: false, setting: "policy.four_eyes" })).toBe(
      "76cf6b9a69d3db7f28f8ef8f52d1b08f41244c284f513b0fe82f30e2503caae1",
    );
  });

  it("escape như Go (không escape HTML; U+2028; ký tự điều khiển), khóa theo byte UTF-8 (khác thứ tự UTF-16)", async () => {
    const v = {
      b: "x y",
      a: '<&>"\\\n\t\u0001é',
      n: [1, -2, 9007199254740991, null, true],
      o: { z: 1, Z: 2, é: 3, e: 4, "\u{1F600}": 5, "～": 6 },
    };
    expect(canonicalJson(v)).toBe(
      '{"a":"<&>\\"\\\\\\n\\t\\u0001é","b":"x\\u2028y","n":[1,-2,9007199254740991,null,true],"o":{"Z":2,"e":4,"z":1,"é":3,"～":6,"\u{1F600}":5}}',
    );
    expect(await payloadSha256(v)).toBe("082d112332303a033749a7601eb4f06b17fcd3243311fb005a283cc0df9e7cd6");
  });

  it("không chuẩn hóa được ⇒ null (số thực, số vượt 2^53, không phải object)", async () => {
    expect(await payloadSha256({ x: 1.5 })).toBeNull();
    expect(await payloadSha256({ x: 2 ** 60 })).toBeNull();
    expect(await payloadSha256([1])).toBeNull();
    expect(await payloadSha256("x")).toBeNull();
    expect(await sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });
});

describe("phân trang con trỏ", () => {
  it("tới / lùi / đổi bộ lọc ⇒ về trang đầu", () => {
    const { result, rerender } = renderHook(({ key }) => useCursorPager(key), { initialProps: { key: "a" } });
    expect(result.current.cursor).toBeUndefined();
    act(() => {
      result.current.next("c1");
    });
    act(() => {
      result.current.next("c2");
    });
    expect(result.current.cursor).toBe("c2");
    expect(result.current.page).toBe(3);
    act(() => {
      result.current.previous();
    });
    expect(result.current.cursor).toBe("c1");
    rerender({ key: "b" });
    expect(result.current.cursor).toBeUndefined();
    expect(result.current.hasPrevious).toBe(false);
  });

  it("dùng với query thật: cursor đi vào tham số", async () => {
    const { requests } = mockApi({ "GET /platform/jobs": json(200, { items: [], next_cursor: null }) });
    await api.GET("/platform/jobs", { params: { query: { limit: 25, cursor: "abc" } } });
    await waitFor(() => {
      expect(requests).toHaveLength(1);
    });
    expect(new URL(requests[0]!.url).search).toBe("?limit=25&cursor=abc");
  });
});
