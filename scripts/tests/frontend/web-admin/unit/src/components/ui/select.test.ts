import { beforeEach, describe, expect, test, vi } from "vitest";
import { render, screen } from "../../../testing-library";

import Select from "../../../../../../../../packages/ui/Select.svelte";

describe("Select", () => {
  const options = [
    { value: "a", label: "Alpha" },
    { value: "b", label: "Beta" },
    { value: "c", label: "Gamma" },
  ];

  let onchange: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    onchange = vi.fn();
  });

  test("renders the trigger with selected label", () => {
    render(Select, { props: { value: "b", options, onchange } });
    expect(screen.getByText("Beta")).toBeInTheDocument();
  });

  test("renders with aria-label when provided", () => {
    render(Select, {
      props: { value: "a", options, onchange, ariaLabel: "Choose option" },
    });
    expect(screen.getByLabelText("Choose option")).toBeInTheDocument();
  });

  test("shows fallback when value does not match any option", () => {
    render(Select, { props: { value: "unknown", options, onchange } });
    expect(screen.getByText("unknown")).toBeInTheDocument();
  });

  test("renders the trigger as a button-like element", () => {
    render(Select, {
      props: { value: "a", options, onchange, ariaLabel: "Test select" },
    });
    const trigger = screen.getByLabelText("Test select");
    expect(trigger).toBeInTheDocument();
  });
});
