// Hạ tầng UI dùng chung (P4-T04, hợp nhất với P4-T02): Location của job phạm vi tenant, Idempotency-Key tường minh,
// trạng thái cuối của job, thời gian tương đối. Hộp xác nhận: ui/ConfirmDialog.test.tsx.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { render, renderHook, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { newIdempotencyKey, useIdempotencyKey } from "../api/idempotency";
import { isSettled, tenantJobFromLocation } from "../api/jobs";
import { TENANT_A, TENANT_B } from "../test/helpers";
import { i18n } from "../i18n";
import { formatRelative, freshNow, NOW_TOLERANCE_S, ObservedAt, Timestamp } from "./time";

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

// G4b-E8: mốc vừa xảy ra không được thành "sau 17 giây nữa" — useNow() chỉ đổi mỗi 30 s nên "bây giờ" của nó có thể cũ
// hơn timestamp vừa trả về; lệch nhỏ (đồng hồ, mạng) ⇒ "bây giờ".
describe("thời gian tương đối không sai chiều (G4b-E8)", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("|lệch| dưới ngưỡng ⇒ bây giờ; ngoài ngưỡng giữ chiều đúng", () => {
    const now = Date.parse("2026-11-19T01:00:00Z");
    expect(formatRelative("2026-11-19T01:00:05Z", "vi", now)).toBe("bây giờ");
    expect(formatRelative("2026-11-19T00:59:55Z", "en", now)).toBe("now");
    expect(formatRelative(new Date(now + NOW_TOLERANCE_S * 1000).toISOString(), "en", now)).toBe("in 10 seconds");
    expect(formatRelative("2026-11-19T00:59:30Z", "en", now)).toBe("30 seconds ago");
  });

  it("freshNow lấy giá trị muộn hơn của 'bây giờ' đã lưu và đồng hồ thật", () => {
    vi.useFakeTimers({ now: Date.parse("2026-11-19T01:00:20Z") });
    const stale = Date.parse("2026-11-19T01:00:00Z");
    expect(freshNow(stale)).toBe(Date.parse("2026-11-19T01:00:20Z"));
    expect(freshNow(Date.parse("2026-11-19T01:00:30Z"))).toBe(Date.parse("2026-11-19T01:00:30Z"));
  });

  it("Timestamp: mốc vừa trả về sau lần cập nhật cuối của useNow ⇒ không ở tương lai", () => {
    vi.useFakeTimers({ now: Date.parse("2026-11-19T01:00:00Z") });
    const { rerender } = render(<Timestamp iso="2026-11-19T00:59:00Z" />);
    // 25 s sau (useNow chưa đổi — chu kỳ 30 s), server trả mốc vừa xảy ra
    vi.setSystemTime(Date.parse("2026-11-19T01:00:25Z"));
    rerender(<Timestamp iso="2026-11-19T01:00:24Z" />);
    const time = document.querySelector("time")!;
    expect(time).toHaveTextContent("(bây giờ)");
    expect(time).not.toHaveTextContent("nữa");
  });
});

// G4b-E9: không ghép "… lúc" với "chưa từng" ⇒ một câu riêng cho từng loại mốc.
describe("ObservedAt khi chưa có mốc (G4b-E9)", () => {
  it.each([
    ["ui.syncedAt", "Chưa đồng bộ từ Headscale lần nào.", "Never synced from Headscale."],
    ["ui.checkedAt", "Chưa kiểm tra lần nào.", "Never checked."],
    ["diagnostics.readAt", "Chưa đọc lần nào.", "Never read."],
  ])("%s", async (labelKey, viText, enText) => {
    const { unmount } = render(<ObservedAt labelKey={labelKey} iso={null} />);
    expect(screen.getByTestId("observed-never")).toHaveTextContent(viText);
    expect(document.body).not.toHaveTextContent(i18n.t(labelKey));
    expect(document.body).not.toHaveTextContent("chưa từng");
    unmount();
    await i18n.changeLanguage("en");
    render(<ObservedAt labelKey={labelKey} iso={null} />);
    expect(screen.getByTestId("observed-never")).toHaveTextContent(enText);
    expect(document.body).not.toHaveTextContent(" at never");
  });

  it("có mốc ⇒ nhãn + thời điểm như cũ", () => {
    render(<ObservedAt labelKey="ui.syncedAt" iso="2026-11-19T00:55:00Z" />);
    expect(screen.getByText(/Đồng bộ từ Headscale lúc/)).toBeInTheDocument();
    expect(document.querySelector('time[datetime="2026-11-19T00:55:00Z"]')).not.toBeNull();
  });
});

// G4b-E5: span sr-only (absolute) trong tiêu đề cột thoát khỏi vùng cuộn nếu wrapper của bảng không `relative` ⇒ trang
// cuộn ngang ở 390 px. jsdom không đo bố cục ⇒ kiểm ở mã nguồn: mọi `<table className="data-table"` nằm ngay trong một
// wrapper `relative overflow-x-auto` (bố cục thật: Playwright 390 px).
describe("wrapper của bảng dữ liệu (G4b-E5)", () => {
  it("mọi data-table nằm trong wrapper relative overflow-x-auto", () => {
    const root = join(import.meta.dirname, "..");
    const files: string[] = [];
    const walk = (d: string) => {
      for (const n of readdirSync(d)) {
        const p = join(d, n);
        if (statSync(p).isDirectory()) walk(p);
        else if (n.endsWith(".tsx") && !n.endsWith(".test.tsx")) files.push(p);
      }
    };
    walk(root);
    let tables = 0;
    const bad: string[] = [];
    for (const f of files) {
      const lines = readFileSync(f, "utf8").split(/\r?\n/);
      lines.forEach((line, i) => {
        if (!line.includes('<table className="data-table')) return;
        tables++;
        const wrapper = lines[i - 1] ?? "";
        if (!/className="[^"]*relative[^"]*overflow-x-auto/.test(wrapper)) bad.push(`${f}:${String(i + 1)}`);
      });
    }
    expect(tables).toBeGreaterThanOrEqual(25);
    expect(bad).toEqual([]);
  });
});
