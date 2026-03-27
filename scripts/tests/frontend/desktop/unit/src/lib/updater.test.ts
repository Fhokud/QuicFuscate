import { describe, expect, it, vi } from "vitest";

import {
  checkForUpdates,
  downloadAndInstallUpdate,
  toTerminalUpdaterErrorState,
  updaterEnabledByPolicy,
  type UpdaterDriver,
  type UpdaterHandle,
} from "../../../../../../../apps/svelte-desktop/src/lib/updater";

function fakeUpdate(overrides?: Partial<UpdaterHandle>): UpdaterHandle {
  return {
    currentVersion: "1.0.0",
    version: "1.1.0",
    date: "2026-02-12",
    body: "update body",
    downloadAndInstall: vi.fn(async (onEvent) => {
      onEvent?.({ event: "Started", data: { contentLength: 100 } });
      onEvent?.({ event: "Progress", data: { chunkLength: 60 } });
      onEvent?.({ event: "Progress", data: { chunkLength: 40 } });
      onEvent?.({ event: "Finished", data: {} });
    }),
    ...overrides,
  };
}

function fakeDriver(update: UpdaterHandle | null): UpdaterDriver {
  return {
    check: vi.fn(async () => update),
  };
}

describe("updater policy", () => {
  it("disables updater outside tauri runtime", () => {
    const result = updaterEnabledByPolicy(false, true, true);
    expect(result.enabled).toBe(false);
    expect(result.reason).toContain("desktop runtime");
  });

  it("disables updater when policy toggle is false", () => {
    const result = updaterEnabledByPolicy(true, false, true);
    expect(result.enabled).toBe(false);
    expect(result.reason).toContain("disabled by policy");
  });

  it("enables updater only when all gates pass", () => {
    const result = updaterEnabledByPolicy(true, true, true);
    expect(result).toEqual({ enabled: true });
  });
});

describe("updater flow", () => {
  it("reports no update when backend returns null", async () => {
    const result = await checkForUpdates(fakeDriver(null));
    expect(result).toEqual({ kind: "none" });
  });

  it("reports optional update metadata", async () => {
    const result = await checkForUpdates(fakeDriver(fakeUpdate()));
    expect(result.kind).toBe("available");
    if (result.kind === "available") {
      expect(result.version).toBe("1.1.0");
      expect(result.mandatory).toBe(false);
    }
  });

  it("marks mandatory update when version prefix matches", async () => {
    const result = await checkForUpdates(fakeDriver(fakeUpdate({ version: "2.0.1" })), ["2."]);
    expect(result.kind).toBe("available");
    if (result.kind === "available") {
      expect(result.mandatory).toBe(true);
    }
  });

  it("streams download progress cumulatively", async () => {
    const progress: string[] = [];
    await downloadAndInstallUpdate(fakeUpdate(), (event) => {
      if (event.event === "started") {
        progress.push(`start:${event.contentLength ?? 0}`);
      } else if (event.event === "progress") {
        progress.push(`progress:${event.chunkLength}`);
      } else {
        progress.push("finished");
      }
    });

    expect(progress).toEqual(["start:100", "progress:60", "progress:100", "finished"]);
  });

  it("maps signature failures to signature-failure state", () => {
    const state = toTerminalUpdaterErrorState(new Error("invalid updater signature"));
    expect(state).toEqual({ status: "signature-failure", message: "invalid updater signature" });
  });

  it("maps generic errors to error state", () => {
    const state = toTerminalUpdaterErrorState(new Error("network timeout"));
    expect(state).toEqual({ status: "error", message: "network timeout" });
  });
});
