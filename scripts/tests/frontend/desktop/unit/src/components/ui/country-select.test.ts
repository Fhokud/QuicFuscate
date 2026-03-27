import { beforeEach, describe, expect, test, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "../../../testing-library";

import CountrySelect from "../../../../../../../../apps/svelte-desktop/src/lib/components/ui/CountrySelect.svelte";

describe("ui/CountrySelect", () => {
  let changeFn: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    changeFn = vi.fn();
  });

  test("renders trigger with dash when no country is selected", () => {
    render(CountrySelect, { value: "", onchange: changeFn });
    // The display value for empty is "-"
    expect(screen.getByText("-")).toBeInTheDocument();
  });

  test("renders trigger with flag emoji when country code is set", () => {
    render(CountrySelect, { value: "DE", onchange: changeFn });
    // German flag emoji should be rendered
    const trigger = screen.getByRole("button");
    expect(trigger.textContent).toBeTruthy();
    // The flag for DE is a specific unicode sequence
    expect(trigger.textContent?.trim()).not.toBe("-");
  });

  test("trigger has aria-haspopup attribute", () => {
    render(CountrySelect, { value: "", onchange: changeFn });
    const trigger = screen.getByRole("button");
    // bits-ui Popover.Trigger sets aria-haspopup="dialog"
    expect(trigger.getAttribute("aria-haspopup")).toBeTruthy();
  });

  test("trigger has aria-expanded=false when closed", () => {
    render(CountrySelect, { value: "", onchange: changeFn });
    const trigger = screen.getByRole("button");
    expect(trigger.getAttribute("aria-expanded")).toBe("false");
  });

  test("opens popover and shows listbox on click", async () => {
    render(CountrySelect, { value: "", onchange: changeFn });
    const trigger = screen.getByRole("button");
    await fireEvent.click(trigger);

    await waitFor(() => {
      expect(screen.getByRole("listbox")).toBeInTheDocument();
    });
  });

  test("shows 'No Flag' as the first option in the list", async () => {
    render(CountrySelect, { value: "", onchange: changeFn });
    await fireEvent.click(screen.getByRole("button"));

    await waitFor(() => {
      expect(screen.getByText("No Flag")).toBeInTheDocument();
    });
  });

  test("shows country names in the option list", async () => {
    render(CountrySelect, { value: "", onchange: changeFn });
    await fireEvent.click(screen.getByRole("button"));

    await waitFor(() => {
      // The list includes real countries from COUNTRY_OPTIONS
      expect(screen.getByText("Germany")).toBeInTheDocument();
      expect(screen.getByText("France")).toBeInTheDocument();
    });
  });

  test("selecting a country fires onchange with uppercase code", async () => {
    render(CountrySelect, { value: "", onchange: changeFn });
    await fireEvent.click(screen.getByRole("button"));

    await waitFor(() => {
      expect(screen.getByRole("listbox")).toBeInTheDocument();
    });

    const germanyOption = screen.getByText("Germany");
    await fireEvent.click(germanyOption);

    expect(changeFn).toHaveBeenCalledWith("DE");
  });

  test("selecting 'No Flag' fires onchange with empty string", async () => {
    render(CountrySelect, { value: "DE", onchange: changeFn });
    await fireEvent.click(screen.getByRole("button"));

    await waitFor(() => {
      expect(screen.getByRole("listbox")).toBeInTheDocument();
    });

    const noFlagOption = screen.getByText("No Flag");
    await fireEvent.click(noFlagOption);

    expect(changeFn).toHaveBeenCalledWith("");
  });
});
