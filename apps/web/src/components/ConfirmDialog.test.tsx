// Hộp xác nhận thao tác phá hủy (dùng chung): alertdialog có tên + mô tả, gõ lại giá trị mới bật nút, Esc đóng (trừ
// khi đang gửi), lỗi server hiện trong hộp, focus vào trong hộp và trả về nút đã mở; không chèn <style> (CSP).
import { QueryClientProvider } from "@tanstack/react-query";
import { render as rtlRender, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { useState, type ReactElement } from "react";
import { describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router";
import { ApiError } from "../api/problem";
import { createQueryClient } from "../api/queryClient";
import { ConfirmDialog } from "./ConfirmDialog";

const render = (ui: ReactElement) =>
  rtlRender(
    <QueryClientProvider client={createQueryClient()}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );

function Harness(props: { pending?: boolean; error?: unknown; onConfirm: () => void; canConfirm?: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" onClick={() => { setOpen(true); }}>
        open
      </button>
      <ConfirmDialog
        isOpen={open}
        onOpenChange={setOpen}
        title="Delete acme?"
        description={<p>This cannot be undone.</p>}
        confirmLabel="Delete"
        destructive
        typedConfirmation={{ expected: "acme", label: "Type the slug" }}
        canConfirm={props.canConfirm}
        pending={props.pending}
        error={props.error}
        onConfirm={props.onConfirm}
      />
    </>
  );
}

describe("ConfirmDialog", () => {
  it("alertdialog: tên, mô tả, gõ đúng slug mới bật nút; Esc đóng và trả focus", async () => {
    const onConfirm = vi.fn();
    render(<Harness onConfirm={onConfirm} />);
    const opener = screen.getByRole("button", { name: "open" });
    await userEvent.click(opener);
    const dialog = await screen.findByRole("alertdialog", { name: "Delete acme?" });
    expect(dialog).toHaveAccessibleDescription("This cannot be undone.");
    const confirm = screen.getByRole("button", { name: "Delete" });
    expect(confirm).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Type the slug"), "ACME");
    expect(confirm).toBeDisabled(); // phân biệt hoa thường
    await userEvent.clear(screen.getByLabelText("Type the slug"));
    await userEvent.type(screen.getByLabelText("Type the slug"), "acme");
    expect(confirm).toBeEnabled();
    await userEvent.click(confirm);
    expect(onConfirm).toHaveBeenCalledTimes(1);
    await userEvent.keyboard("{Escape}");
    await waitFor(() => {
      expect(screen.queryByRole("alertdialog")).toBeNull();
    });
    await waitFor(() => {
      expect(opener).toHaveFocus();
    });
    // mở lại: giá trị đã gõ không còn
    await userEvent.click(opener);
    expect(await screen.findByLabelText("Type the slug")).toHaveValue("");
  });

  it("đang gửi: không đóng bằng Esc, nút bị khóa; lỗi server hiện trong hộp", async () => {
    const error = new ApiError({ status: 409, code: "conflict", problem: { type: "urn:meshguard:problem:conflict", title: "c", status: 409, code: "conflict", request_id: "req-9", detail: "a lifecycle job is running" } });
    render(<Harness onConfirm={vi.fn()} pending error={error} />);
    await userEvent.click(screen.getByRole("button", { name: "open" }));
    const dialog = await screen.findByRole("alertdialog");
    await userEvent.keyboard("{Escape}");
    expect(dialog).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("a lifecycle job is running");
    expect(screen.getByRole("alert")).toHaveTextContent("req-9");
    for (const b of screen.getAllByRole("button").filter((x) => dialog.contains(x))) expect(b).toBeDisabled();
  });

  it("canConfirm=false giữ nút khóa dù đã gõ đúng", async () => {
    render(<Harness onConfirm={vi.fn()} canConfirm={false} />);
    await userEvent.click(screen.getByRole("button", { name: "open" }));
    await userEvent.type(await screen.findByLabelText("Type the slug"), "acme");
    expect(screen.getByRole("button", { name: "Delete" })).toBeDisabled();
  });

  it("axe 0 vi phạm khi mở; react-aria không chèn <style> (CSP) ở chế độ production", async () => {
    const env = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      render(<Harness onConfirm={vi.fn()} />);
      await userEvent.click(screen.getByRole("button", { name: "open" }));
      await screen.findByRole("alertdialog");
      expect(document.querySelectorAll("style")).toHaveLength(0);
      const r = await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } });
      expect(r.violations.map((v) => v.id)).toEqual([]);
    } finally {
      process.env.NODE_ENV = env;
    }
  });
});
