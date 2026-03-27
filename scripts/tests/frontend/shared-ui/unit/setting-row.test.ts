import { describe, expect, test } from "vitest";
import { render, screen } from "./testing-library";
import { createRawSnippet } from "svelte";

import SettingRow from "../../../../../packages/ui/SettingRow.svelte";

const dummyChildren = createRawSnippet(() => ({
  render: () => `<span>control-slot</span>`,
}));

describe("SettingRow", () => {
  test("renders the label text", () => {
    render(SettingRow, { props: { label: "Auto-connect", children: dummyChildren } });
    expect(screen.getByText("Auto-connect")).not.toBeNull();
  });

  test("renders description when provided", () => {
    render(SettingRow, {
      props: { label: "Theme", description: "Choose light or dark mode", children: dummyChildren },
    });
    expect(screen.getByText("Choose light or dark mode")).not.toBeNull();
  });

  test("does not render description element when not provided", () => {
    const { container } = render(SettingRow, { props: { label: "Updates", children: dummyChildren } });
    const descEl = container.querySelector(".text-text-tertiary");
    expect(descEl).toBeNull();
  });

  test("renders the control slot content", () => {
    render(SettingRow, { props: { label: "Volume", children: dummyChildren } });
    expect(screen.getByText("control-slot")).not.toBeNull();
  });

  test("uses flex layout for label and control alignment", () => {
    const { container } = render(SettingRow, { props: { label: "Proxy", children: dummyChildren } });
    const root = container.firstElementChild as HTMLElement;
    expect(root.className).toContain("flex");
    expect(root.className).toContain("items-center");
    expect(root.className).toContain("justify-between");
  });
});
