import { beforeEach, describe, expect, test, vi } from "vitest";
import { render, screen } from "../../../testing-library";

import Select from "../../../../../../../../packages/ui/Select.svelte";

const TEST_OPTIONS = [
  { value: "auto", label: "Auto" },
  { value: "manual", label: "Manual" },
  { value: "off", label: "Off" },
];

describe("ui/Select", () => {
  let changeFn: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    changeFn = vi.fn();
  });

  test("renders the selected option label in the trigger", () => {
    render(Select, { value: "manual", options: TEST_OPTIONS, onchange: changeFn });
    expect(screen.getByText("Manual")).toBeInTheDocument();
  });

  test("renders fallback to raw value when no option matches", () => {
    render(Select, { value: "unknown", options: TEST_OPTIONS, onchange: changeFn });
    expect(screen.getByText("unknown")).toBeInTheDocument();
  });

  test("trigger has aria-label when label prop is provided", () => {
    render(Select, { value: "auto", options: TEST_OPTIONS, onchange: changeFn, label: "FEC Mode" });
    const trigger = screen.getByRole("button");
    expect(trigger.getAttribute("aria-label")).toContain("FEC Mode");
    expect(trigger.getAttribute("aria-label")).toContain("Auto");
  });

  test("disabled select has disabled state on trigger", () => {
    render(Select, { value: "auto", options: TEST_OPTIONS, onchange: changeFn, disabled: true });
    const trigger = screen.getByRole("button");
    expect(trigger).toBeDisabled();
  });
});
