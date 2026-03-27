import { describe, expect, test } from "vitest";

import {
  extractBlockedIps,
  mergeBlockedIps,
  optimisticBlock,
  optimisticUnblock,
} from "../../../../../apps/svelte-admin/src/lib/blocked-ips";

describe("ip access control optimistic helpers", () => {
  test("optimisticBlock adds unique ip", () => {
    expect(optimisticBlock(["1.1.1.1"], "2.2.2.2")).toEqual(["1.1.1.1", "2.2.2.2"]);
  });

  test("optimisticBlock keeps existing ip only once", () => {
    expect(optimisticBlock(["1.1.1.1"], "1.1.1.1")).toEqual(["1.1.1.1"]);
  });

  test("optimisticUnblock removes ip", () => {
    expect(optimisticUnblock(["1.1.1.1", "2.2.2.2"], "1.1.1.1")).toEqual(["2.2.2.2"]);
  });

  test("mergeBlockedIps applies pending block over server state", () => {
    const merged = mergeBlockedIps(["10.0.0.1"], {
      "10.0.0.2": "block",
    });
    expect(merged).toEqual(["10.0.0.1", "10.0.0.2"]);
  });

  test("mergeBlockedIps applies pending unblock over server state", () => {
    const merged = mergeBlockedIps(["10.0.0.1", "10.0.0.2"], {
      "10.0.0.1": "unblock",
    });
    expect(merged).toEqual(["10.0.0.2"]);
  });

  test("mergeBlockedIps de-duplicates and trims server data", () => {
    const merged = mergeBlockedIps([" 10.0.0.1 ", "10.0.0.1", "10.0.0.2"], {});
    expect(merged).toEqual(["10.0.0.1", "10.0.0.2"]);
  });

  test("extractBlockedIps supports canonical ips response", () => {
    const parsed = extractBlockedIps({
      ips: ["10.0.0.1", "10.0.0.2"],
    });
    expect(parsed).toEqual(["10.0.0.1", "10.0.0.2"]);
  });

  test("extractBlockedIps supports legacy blocked response and de-duplicates", () => {
    const parsed = extractBlockedIps({
      blocked: [" 10.0.0.1 ", "10.0.0.1", "10.0.0.2", 123],
    });
    expect(parsed).toEqual(["10.0.0.1", "10.0.0.2"]);
  });
});
