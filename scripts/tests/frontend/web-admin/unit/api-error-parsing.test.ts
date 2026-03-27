import { describe, expect, test } from "vitest";

import {
  ApiError,
  parseErrorMessageBody,
  sanitizeErrorMessage,
} from "../../../../../apps/svelte-admin/src/lib/api";

describe("parseErrorMessageBody", () => {
  test("returns null for empty input", () => {
    expect(parseErrorMessageBody("   ")).toBeNull();
  });

  test("parses JSON message field", () => {
    expect(parseErrorMessageBody('{ "message": "Login failed" }')).toBe("Login failed");
  });

  test("parses JSON error field", () => {
    expect(parseErrorMessageBody('{ "error": "Forbidden" }')).toBe("Forbidden");
  });

  test("parses direct JSON string", () => {
    expect(parseErrorMessageBody('"rate limited"')).toBe("rate limited");
  });

  test("falls back to plain text", () => {
    expect(parseErrorMessageBody("Plain error text")).toBe("Plain error text");
  });

  test("truncates long plain text", () => {
    const long = "x".repeat(260);
    const out = parseErrorMessageBody(long);
    expect(out).not.toBeNull();
    expect(out?.length).toBe(243);
    expect(out?.endsWith("...")).toBe(true);
  });
});

describe("sanitizeErrorMessage", () => {
  test("returns empty string for explicit not found text", () => {
    expect(sanitizeErrorMessage("Not Found", "Fallback")).toBe("");
    expect(sanitizeErrorMessage("404 Not Found", "Fallback")).toBe("");
    expect(sanitizeErrorMessage("endpoint not found", "Fallback")).toBe("");
  });

  test("filters generic failure phrases", () => {
    expect(sanitizeErrorMessage("Failed to load", "Fallback")).toBe("");
  });

  test("keeps meaningful API error text", () => {
    expect(sanitizeErrorMessage("Unauthorized", "Fallback")).toBe("Unauthorized");
  });

  test("masks server errors and empty fallbacks", () => {
    expect(sanitizeErrorMessage(new ApiError("Internal Server Error", 500), "Fallback")).toBe("");
    expect(sanitizeErrorMessage("", "Failed")).toBe("");
  });
});
