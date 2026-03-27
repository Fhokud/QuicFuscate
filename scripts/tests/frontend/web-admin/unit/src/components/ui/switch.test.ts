import { beforeEach, describe, expect, test, vi } from "vitest";
import { fireEvent, render, screen } from "../../../testing-library";

import Switch from "../../../../../../../../packages/ui/Switch.svelte";

describe("Switch", () => {
  let onchange: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    onchange = vi.fn();
  });

  test("renders a switch role element", () => {
    render(Switch, { props: { checked: false, onchange } });
    expect(screen.getByRole("switch")).toBeInTheDocument();
  });

  test("reflects checked=true via aria-checked", () => {
    render(Switch, { props: { checked: true, onchange } });
    expect(screen.getByRole("switch").getAttribute("aria-checked")).toBe("true");
  });

  test("reflects checked=false via aria-checked", () => {
    render(Switch, { props: { checked: false, onchange } });
    expect(screen.getByRole("switch").getAttribute("aria-checked")).toBe("false");
  });

  test("calls onchange with true when toggling off to on", async () => {
    render(Switch, { props: { checked: false, onchange } });
    await fireEvent.click(screen.getByRole("switch"));
    expect(onchange).toHaveBeenCalledWith(true);
  });

  test("calls onchange with false when toggling on to off", async () => {
    render(Switch, { props: { checked: true, onchange } });
    await fireEvent.click(screen.getByRole("switch"));
    expect(onchange).toHaveBeenCalledWith(false);
  });

  test("applies aria-label when label prop provided", () => {
    render(Switch, { props: { checked: false, onchange, label: "Enable feature" } });
    expect(screen.getByLabelText("Enable feature")).toBeInTheDocument();
  });

  test("is disabled when disabled prop is true", () => {
    render(Switch, { props: { checked: false, onchange, disabled: true } });
    expect(screen.getByRole("switch")).toBeDisabled();
  });

  test("is not disabled by default", () => {
    render(Switch, { props: { checked: false, onchange } });
    expect(screen.getByRole("switch")).not.toBeDisabled();
  });

  test("applies opacity class when disabled", () => {
    render(Switch, { props: { checked: false, onchange, disabled: true } });
    const el = screen.getByRole("switch");
    expect(el.className).toContain("opacity-35");
  });
});
