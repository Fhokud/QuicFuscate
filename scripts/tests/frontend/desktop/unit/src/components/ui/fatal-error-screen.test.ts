import { describe, expect, test, vi } from "vitest";
import { fireEvent, render, screen } from "../../../testing-library";

import FatalErrorScreen from "../../../../../../../../apps/svelte-desktop/src/lib/components/ui/FatalErrorScreen.svelte";

describe("desktop fatal error screen", () => {
  test("renders fallback UI and exposes retry action", async () => {
    const onretry = vi.fn();
    render(FatalErrorScreen, { error: "boom", onretry });

    expect(screen.getByText("Something went wrong")).toBeInTheDocument();
    expect(screen.getByText("boom")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try Again" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Restart App" })).toBeInTheDocument();

    await fireEvent.click(screen.getByRole("button", { name: "Try Again" }));
    expect(onretry).toHaveBeenCalledTimes(1);
  });
});
