import { describe, expect, test } from "vitest";
import { render, screen } from "../../testing-library";

import ErrorBoundaryHost from "./fixtures/error-boundary-host.svelte";

describe("web admin error boundary", () => {
  test("catches child render failures and renders the fallback", async () => {
    render(ErrorBoundaryHost);

    expect(await screen.findByText(/caught:/)).toBeInTheDocument();
    expect(screen.getByText(/boom/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reset" })).toBeInTheDocument();
  });
});
