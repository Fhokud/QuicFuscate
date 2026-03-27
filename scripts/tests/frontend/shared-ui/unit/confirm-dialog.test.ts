import { describe, expect, test, vi } from "vitest";
import { render, screen } from "./testing-library";

import ConfirmDialog from "../../../../../packages/ui/ConfirmDialog.svelte";

function renderDialog(overrides: Record<string, unknown> = {}) {
  return render(ConfirmDialog, {
    props: {
      open: true,
      title: "Delete item?",
      message: "This action cannot be undone.",
      onconfirm: vi.fn(),
      oncancel: vi.fn(),
      ...overrides,
    },
  });
}

describe("ConfirmDialog", () => {
  test("renders title and message when open", () => {
    renderDialog();
    expect(screen.getByText("Delete item?")).not.toBeNull();
    expect(screen.getByText("This action cannot be undone.")).not.toBeNull();
  });

  test("renders default confirm and cancel labels", () => {
    renderDialog();
    expect(screen.getByText("Confirm")).not.toBeNull();
    expect(screen.getByText("Cancel")).not.toBeNull();
  });

  test("renders custom confirm and cancel labels", () => {
    renderDialog({ confirmLabel: "Yes, delete", cancelLabel: "Keep it" });
    expect(screen.getByText("Yes, delete")).not.toBeNull();
    expect(screen.getByText("Keep it")).not.toBeNull();
  });

  test("applies destructive styling when destructive prop is true", () => {
    renderDialog({ destructive: true });
    // bits-ui Dialog portals to body, so search document.body
    const buttons = document.body.querySelectorAll("button");
    const confirmBtn = Array.from(buttons).find((b) =>
      b.textContent?.includes("Confirm")
    );
    expect(confirmBtn).toBeDefined();
    expect(confirmBtn!.className).toContain("action-disconnect-btn");
  });

  test("applies save styling when destructive is false", () => {
    renderDialog({ destructive: false });
    const buttons = document.body.querySelectorAll("button");
    const confirmBtn = Array.from(buttons).find((b) =>
      b.textContent?.includes("Confirm")
    );
    expect(confirmBtn).toBeDefined();
    expect(confirmBtn!.className).toContain("action-save-btn");
  });
});
