import { describe, expect, test } from "vitest";
import { render } from "./testing-library";

import Skeleton from "../../../../../packages/ui/Skeleton.svelte";

describe("Skeleton", () => {
  test("renders with animate-pulse class", () => {
    const { container } = render(Skeleton);
    const el = container.firstElementChild as HTMLElement;
    expect(el.className).toContain("animate-pulse");
  });

  test("renders with rounded-md and bg-surface-3 classes", () => {
    const { container } = render(Skeleton);
    const el = container.firstElementChild as HTMLElement;
    expect(el.className).toContain("rounded-md");
    expect(el.className).toContain("bg-surface-3");
  });

  test("accepts custom width and height via style", () => {
    const { container } = render(Skeleton, {
      props: { width: "200px", height: "24px" },
    });
    const el = container.firstElementChild as HTMLElement;
    expect(el.style.width).toBe("200px");
    expect(el.style.height).toBe("24px");
  });

  test("has role=status and aria-label for accessibility", () => {
    const { container } = render(Skeleton);
    const el = container.firstElementChild as HTMLElement;
    expect(el.getAttribute("role")).toBe("status");
    expect(el.getAttribute("aria-label")).toBe("Loading");
  });

  test("accepts custom class that merges with defaults", () => {
    const { container } = render(Skeleton, {
      props: { class: "w-full h-8" },
    });
    const el = container.firstElementChild as HTMLElement;
    expect(el.className).toContain("animate-pulse");
    expect(el.className).toContain("w-full");
    expect(el.className).toContain("h-8");
  });
});
