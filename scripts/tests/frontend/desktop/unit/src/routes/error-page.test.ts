import { describe, expect, test } from "vitest";
import { render, screen } from "../../testing-library";

import DesktopErrorPage from "../../../../../../../apps/svelte-desktop/src/routes/+error.svelte";

describe("desktop error page", () => {
  test("renders error message with status and retry action", () => {
    render(DesktopErrorPage, {
      error: new Error("connection refused"),
      status: 503,
    });

    expect(screen.getByText("Something went wrong")).toBeInTheDocument();
    expect(screen.getByText(/HTTP 503/)).toBeInTheDocument();
    expect(screen.getByText(/connection refused/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try Again" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Restart App" })).toBeInTheDocument();
  });

  test("renders string error without status prefix confusion", () => {
    render(DesktopErrorPage, {
      error: "disk full",
      status: 500,
    });

    expect(screen.getByText(/HTTP 500/)).toBeInTheDocument();
    expect(screen.getByText(/disk full/)).toBeInTheDocument();
  });
});
