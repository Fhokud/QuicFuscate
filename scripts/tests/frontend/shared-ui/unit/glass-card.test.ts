import { describe, expect, test } from "vitest";
import { render } from "./testing-library";

import GlassCard from "../../../../../packages/ui/GlassCard.svelte";
import { createRawSnippet } from "svelte";

const dummyChildren = createRawSnippet(() => ({
  render: () => `<span>card content</span>`,
}));

describe("GlassCard", () => {
  test("renders children content", () => {
    const { container } = render(GlassCard, {
      props: { children: dummyChildren },
    });
    expect(container.textContent).toContain("card content");
  });

  test("applies glass class by default", () => {
    const { container } = render(GlassCard, {
      props: { children: dummyChildren },
    });
    const root = container.firstElementChild as HTMLElement;
    expect(root.className).toContain("glass");
    expect(root.className).toContain("rounded-xl");
  });

  test("applies custom class via class prop", () => {
    const { container } = render(GlassCard, {
      props: { children: dummyChildren, class: "mt-4 p-6" },
    });
    const root = container.firstElementChild as HTMLElement;
    expect(root.className).toContain("mt-4");
    expect(root.className).toContain("p-6");
  });

  test("subtle variant applies glass-subtle class", () => {
    const { container } = render(GlassCard, {
      props: { children: dummyChildren, variant: "subtle" },
    });
    const root = container.firstElementChild as HTMLElement;
    expect(root.className).toContain("glass-subtle");
  });

  test("strong variant applies glass class", () => {
    const { container } = render(GlassCard, {
      props: { children: dummyChildren, variant: "strong" },
    });
    const root = container.firstElementChild as HTMLElement;
    expect(root.className).toContain("glass");
  });
});
