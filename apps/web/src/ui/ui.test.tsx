// Hạ tầng UI dùng chung (P4-T04): Location của job, Idempotency-Key, thời gian tương đối, hộp xác nhận (a11y, bàn phím).
import { render, renderHook, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { TENANT_A, TENANT_B } from "../test/helpers";
import { ConfirmDialog } from "./ConfirmDialog";
import { tenantJobFromLocation } from "./http";
import { newIdempotencyKey, useIdempotencyKey } from "./idempotency";
import { isTerminalJob } from "./jobs";
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
  it("trạng thái kết thúc của job", () => {
    expect(["succeeded", "failed", "cancelled", "rolled_back"].every((s) => isTerminalJob(s as never))).toBe(true);
    expect(["queued", "running", "failed_resumable", "compensating"].some((s) => isTerminalJob(s as never))).toBe(false);
    expect(isTerminalJob(undefined)).toBe(false);
  });

  it("thời gian tương đối theo locale", () => {
    const now = Date.parse("2026-11-19T01:00:00Z");
    expect(formatRelative("2026-11-19T00:55:00Z", "vi", now)).toBe("5 phút trước");
    expect(formatRelative("2026-11-19T00:55:00Z", "en", now)).toBe("5 minutes ago");
    expect(formatRelative("2026-11-22T01:00:00Z", "en", now)).toBe("in 3 days");
    expect(formatRelative("không-phải", "vi", now)).toBe("");
  });
});

describe("ConfirmDialog", () => {
  function Harness({ onConfirm }: { onConfirm: () => void }) {
    const [open, setOpen] = useState(false);
    return (
      <>
        <button type="button" onClick={() => setOpen(true)}>
          open
        </button>
        <ConfirmDialog open={open} title="T" confirmLabel="OK" destructive onConfirm={onConfirm} onCancel={() => setOpen(false)}>
          <p>mô tả</p>
        </ConfirmDialog>
      </>
    );
  }

  it("alertdialog có tên + mô tả, focus vào Hủy, Tab giữ trong hộp, Escape đóng và trả focus", async () => {
    const onConfirm = vi.fn();
    render(<Harness onConfirm={onConfirm} />);
    const opener = screen.getByRole("button", { name: "open" });
    await userEvent.click(opener);
    const dialog = screen.getByRole("alertdialog", { name: "T" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAccessibleDescription("mô tả");
    expect(screen.getByRole("button", { name: "Hủy" })).toHaveFocus();
    await userEvent.tab();
    expect(screen.getByRole("button", { name: "OK" })).toHaveFocus();
    await userEvent.tab();
    expect(screen.getByRole("button", { name: "Hủy" })).toHaveFocus();
    await userEvent.tab({ shift: true });
    expect(screen.getByRole("button", { name: "OK" })).toHaveFocus();
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(opener).toHaveFocus();
    expect(onConfirm).not.toHaveBeenCalled();
    await userEvent.click(opener);
    await userEvent.click(screen.getByRole("button", { name: "OK" }));
    expect(onConfirm).toHaveBeenCalledOnce();
  });
});
