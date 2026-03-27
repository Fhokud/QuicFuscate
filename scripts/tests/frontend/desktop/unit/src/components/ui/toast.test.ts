import { describe, expect, test } from "vitest";
import { render, screen, waitFor } from "../../../testing-library";

import Toast from "../../../../../../../../packages/ui/Toast.svelte";
import {
  addToast,
  setAnchor,
} from "../../../../../../../../packages/ui/toast-store.svelte";

describe("toast overlay", () => {
  test("renders toast when a message is pushed to the shared store", async () => {
    setAnchor({ x: 120, y: 42 });
    render(Toast);

    addToast("Hello", "success", 10_000);

    expect(screen.getByTestId("toast-container")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText("Hello")).toBeInTheDocument();
    });
  });
});
