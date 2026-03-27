import { beforeEach, describe, expect, test, vi } from "vitest";
import { fireEvent, render, screen } from "../../../testing-library";

import ErrorBanner from "../../../../../../../../apps/svelte-desktop/src/lib/components/ui/ErrorBanner.svelte";

describe("ui/ErrorBanner", () => {
  let dismissFn: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    dismissFn = vi.fn();
  });

  test("renders error message from string", () => {
    render(ErrorBanner, { error: "Something went wrong", ondismiss: dismissFn });
    expect(screen.getByText("Something went wrong")).toBeInTheDocument();
  });

  test("renders error message from Error object", () => {
    render(ErrorBanner, { error: new Error("Network failure"), ondismiss: dismissFn });
    expect(screen.getByText("Error: Network failure")).toBeInTheDocument();
  });

  test("does not render when error is null", () => {
    const { container } = render(ErrorBanner, { error: null, ondismiss: dismissFn });
    expect(container.querySelector("[role='alert']")).toBeNull();
  });

  test("has role=alert and aria-live=assertive for accessibility", () => {
    render(ErrorBanner, { error: "fail", ondismiss: dismissFn });
    const alert = screen.getByRole("alert");
    expect(alert).toBeInTheDocument();
    expect(alert.getAttribute("aria-live")).toBe("assertive");
  });

  test("dismiss button triggers ondismiss callback", async () => {
    render(ErrorBanner, { error: "fail", ondismiss: dismissFn });
    const dismissBtn = screen.getByLabelText("Dismiss error");
    await fireEvent.click(dismissBtn);
    expect(dismissFn).toHaveBeenCalledOnce();
  });
});
