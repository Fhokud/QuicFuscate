import { beforeEach, describe, expect, test, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "../../testing-library";

const gotoMock = vi.hoisted(() => vi.fn());

vi.mock("$app/navigation", async () => {
  const actual = await vi.importActual<typeof import("$app/navigation")>("$app/navigation");
  return {
    ...actual,
    goto: (...args: unknown[]) => gotoMock(...args),
  };
});

import AdminErrorPage from "../../../../../../../apps/svelte-admin/src/routes/+error.svelte";

describe("admin error page", () => {
  beforeEach(() => {
    gotoMock.mockReset();
  });

  test("renders crash details and wires copy and retry actions", async () => {
    render(AdminErrorPage, {
      error: new Error("boom"),
      status: 500,
    });

    expect(screen.getByText("Something went wrong")).toBeInTheDocument();
    expect(screen.getByText(/HTTP 500/)).toBeInTheDocument();
    expect(screen.getByText(/boom/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try Again" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy Details" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reload App" })).toBeInTheDocument();

    await fireEvent.click(screen.getByRole("button", { name: "Copy Details" }));
    await waitFor(() => {
      expect(window.navigator.clipboard.writeText).toHaveBeenCalled();
    });

    await fireEvent.click(screen.getByRole("button", { name: "Try Again" }));
    expect(gotoMock).toHaveBeenCalledWith("/");
  });
});
