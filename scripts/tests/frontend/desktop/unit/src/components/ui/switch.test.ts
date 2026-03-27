import { beforeEach, describe, expect, test, vi } from "vitest";
import { fireEvent, render, screen } from "../../../testing-library";

import Switch from "../../../../../../../../packages/ui/Switch.svelte";

describe("ui/Switch", () => {
  let changeFn: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    changeFn = vi.fn();
  });

  test("renders with role=switch", () => {
    render(Switch, { onchange: changeFn });
    expect(screen.getByRole("switch")).toBeInTheDocument();
  });

  test("aria-checked is false when unchecked", () => {
    render(Switch, { checked: false, onchange: changeFn });
    expect(screen.getByRole("switch")).toHaveAttribute("aria-checked", "false");
  });

  test("aria-checked is true when checked", () => {
    render(Switch, { checked: true, onchange: changeFn });
    expect(screen.getByRole("switch")).toHaveAttribute("aria-checked", "true");
  });

  test("click fires onchange with toggled value (false -> true)", async () => {
    render(Switch, { checked: false, onchange: changeFn });
    await fireEvent.click(screen.getByRole("switch"));
    expect(changeFn).toHaveBeenCalledWith(true);
  });

  test("click fires onchange with toggled value (true -> false)", async () => {
    render(Switch, { checked: true, onchange: changeFn });
    await fireEvent.click(screen.getByRole("switch"));
    expect(changeFn).toHaveBeenCalledWith(false);
  });

  test("disabled switch does not fire onchange", async () => {
    render(Switch, { checked: false, disabled: true, onchange: changeFn });
    await fireEvent.click(screen.getByRole("switch"));
    expect(changeFn).not.toHaveBeenCalled();
  });

  test("disabled switch has disabled attribute", () => {
    render(Switch, { disabled: true, onchange: changeFn });
    expect(screen.getByRole("switch")).toBeDisabled();
  });

  test("uses custom label for aria-label", () => {
    render(Switch, { label: "Enable stealth", onchange: changeFn });
    expect(screen.getByRole("switch")).toHaveAttribute("aria-label", "Enable stealth");
  });

  test("uses default 'Toggle' aria-label when no label provided", () => {
    render(Switch, { onchange: changeFn });
    expect(screen.getByRole("switch")).toHaveAttribute("aria-label", "Toggle");
  });
});
