import { describe, expect, test, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { HeroUIProvider } from "@heroui/react";
import { Provider } from "jotai";
import { createStore } from "jotai/vanilla";
import { LogsView } from "@/views/logs-view";
import { logsAtom } from "@/stores/atoms";
import type { LogEntry } from "@/stores/types";

const invokeMock = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invokeMock(...args),
}));

function renderWithProviders(store = createStore()) {
  return {
    store,
    ...render(
      <HeroUIProvider>
        <Provider store={store}>
          <LogsView />
        </Provider>
      </HeroUIProvider>,
    ),
  };
}

describe("LogsView button semantics", () => {
  const originalClipboard = Object.getOwnPropertyDescriptor(globalThis.navigator, "clipboard");
  const writeTextMock = vi.fn();

  beforeEach(() => {
    invokeMock.mockReset();
    writeTextMock.mockReset();
    Object.defineProperty(globalThis.navigator, "clipboard", {
      configurable: true,
      value: { writeText: writeTextMock },
    });
  });

  afterEach(() => {
    if (originalClipboard) {
      Object.defineProperty(globalThis.navigator, "clipboard", originalClipboard);
    }
  });

  test("Copy copies all visible log entries", async () => {
    const store = createStore();
    const entries: LogEntry[] = [
      { timestamp: 1710000000000, level: "info", message: "connected" },
      { timestamp: 1710000005000, level: "warn", message: "latency spike" },
    ];
    store.set(logsAtom, entries);
    renderWithProviders(store);

    fireEvent.click(screen.getByTitle("Copy all logs"));

    await waitFor(() => {
      expect(writeTextMock).toHaveBeenCalledTimes(1);
    });
    const copied = String(writeTextMock.mock.calls[0]?.[0] ?? "");
    expect(copied).toContain("[INFO] connected");
    expect(copied).toContain("[WARN] latency spike");
  });

  test("Clear clears log container and calls engine clear command", async () => {
    const store = createStore();
    const entries: LogEntry[] = [
      { timestamp: 1710000000000, level: "info", message: "connected" },
      { timestamp: 1710000005000, level: "warn", message: "latency spike" },
    ];
    store.set(logsAtom, entries);
    invokeMock.mockResolvedValue(undefined);
    renderWithProviders(store);

    fireEvent.click(screen.getByRole("button", { name: "Clear" }));
    const dialogTitle = await screen.findByText("Clear Live Output");
    const dialog = dialogTitle.closest('[role="dialog"]') as HTMLElement;
    fireEvent.click(within(dialog).getByRole("button", { name: "Clear" }));

    await waitFor(() => {
      expect(store.get(logsAtom)).toEqual([]);
    });
    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith("engine_logs_clear");
    });
  });
});
