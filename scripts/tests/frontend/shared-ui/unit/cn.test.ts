import { describe, expect, test } from "vitest";
import { cn } from "../../../../../packages/ui/cn";

describe("cn", () => {
  test("merges multiple class strings", () => {
    expect(cn("px-2", "py-4")).toBe("px-2 py-4");
  });

  test("handles undefined values", () => {
    expect(cn("px-2", undefined, "py-4")).toBe("px-2 py-4");
  });

  test("handles null values", () => {
    expect(cn("px-2", null, "py-4")).toBe("px-2 py-4");
  });

  test("handles false values", () => {
    expect(cn("px-2", false, "py-4")).toBe("px-2 py-4");
  });

  test("handles empty strings", () => {
    expect(cn("px-2", "", "py-4")).toBe("px-2 py-4");
  });

  test("returns empty string for no arguments", () => {
    expect(cn()).toBe("");
  });

  test("returns empty string for all falsy arguments", () => {
    expect(cn(undefined, null, false, "")).toBe("");
  });

  test("merges tailwind classes with conflict resolution", () => {
    // tailwind-merge should resolve conflicting utilities
    expect(cn("px-2", "px-4")).toBe("px-4");
  });

  test("merges conflicting text colors (last wins)", () => {
    expect(cn("text-red-500", "text-blue-500")).toBe("text-blue-500");
  });

  test("preserves non-conflicting classes", () => {
    expect(cn("px-2", "text-red-500", "bg-blue-500")).toBe("px-2 text-red-500 bg-blue-500");
  });

  test("handles conditional class patterns", () => {
    const isActive = true;
    const isDisabled = false;
    expect(cn("base", isActive && "active", isDisabled && "disabled")).toBe("base active");
  });

  test("handles array input via clsx", () => {
    expect(cn(["px-2", "py-4"])).toBe("px-2 py-4");
  });

  test("handles object input via clsx", () => {
    expect(cn({ "px-2": true, "py-4": false, "mt-2": true })).toBe("px-2 mt-2");
  });

  test("handles mixed input types", () => {
    expect(cn("base", ["px-2"], { "mt-4": true })).toBe("base px-2 mt-4");
  });
});
