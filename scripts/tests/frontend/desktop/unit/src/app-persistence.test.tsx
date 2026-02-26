import { describe, expect, test, vi, beforeEach, afterEach } from "vitest";
import { act, render } from "@testing-library/react";
import { HeroUIProvider } from "@heroui/react";
import { Provider } from "jotai";
import { createStore } from "jotai/vanilla";
import { App } from "@/App";
import { selectedTunnelIdAtom, settingsAtom, tunnelsAtom } from "@/stores/atoms";

function renderApp(store = createStore()) {
  return render(
    <HeroUIProvider>
      <Provider store={store}>
        <App />
      </Provider>
    </HeroUIProvider>,
  );
}

describe("App persistence", () => {
  const prev = (globalThis as any).__TAURI_INTERNALS__;
  const invokeMock = vi.fn();

  beforeEach(() => {
    invokeMock.mockReset();
    vi.useFakeTimers();
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    // Some code paths check window.__TAURI_INTERNALS__ specifically.
    (globalThis as any).window.__TAURI_INTERNALS__ = { invoke: invokeMock };

    invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === "load_state") return null;
      if (cmd === "save_state") return null;
      if (cmd === "engine_status") return { state: "Disconnected", activeTunnelId: null, lastError: null };
      if (cmd === "engine_stats") return null;
      if (cmd === "engine_logs_since") return { cursor: 0, lines: [] };
      return null;
    });
  });

  afterEach(() => {
    vi.runOnlyPendingTimers();
    vi.useRealTimers();
    if (prev) (globalThis as any).__TAURI_INTERNALS__ = prev;
    else delete (globalThis as any).__TAURI_INTERNALS__;
  });

  test("changing settings triggers debounced save_state with updated general settings", async () => {
    const store = createStore();
    renderApp(store);

    // Flush the initial debounced persistence on mount (defaults).
    await act(async () => {
      await vi.advanceTimersByTimeAsync(600);
    });
    invokeMock.mockClear();

    const prevSettings = store.get(settingsAtom);
    await act(async () => {
      store.set(settingsAtom, {
        ...prevSettings,
        general: { ...prevSettings.general, logLevel: "debug" },
      });
    });
    // Let effects schedule the debounce, then advance timers to fire it.
    await act(async () => {
      await Promise.resolve();
      await vi.advanceTimersByTimeAsync(600);
    });

    const calls = invokeMock.mock.calls.filter((c) => c[0] === "save_state");
    expect(calls.length).toBeGreaterThan(0);

    const last = calls[calls.length - 1]!;
    const payload = last[1]?.data;
    expect(payload).toBeTruthy();
    expect(payload.settings?.general?.logLevel).toBe("debug");
  });

  test("does not persist before hydration completes when load_state is delayed", async () => {
    const store = createStore();
    let resolveLoad: ((value: any) => void) | null = null;
    const loadPromise = new Promise<any>((resolve) => { resolveLoad = resolve; });

    invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === "load_state") return await loadPromise;
      if (cmd === "save_state") return null;
      if (cmd === "engine_status") return { state: "Disconnected", activeTunnelId: null, lastError: null };
      if (cmd === "engine_stats") return null;
      if (cmd === "engine_logs_since") return { cursor: 0, lines: [] };
      return null;
    });

    renderApp(store);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(invokeMock.mock.calls.filter((c) => c[0] === "save_state")).toHaveLength(0);

    await act(async () => {
      resolveLoad?.(null);
      await Promise.resolve();
      await Promise.resolve();
    });

    await act(async () => {
      const prevSettings = store.get(settingsAtom);
      store.set(settingsAtom, {
        ...prevSettings,
        general: { ...prevSettings.general, logLevel: "debug" },
      });
      await Promise.resolve();
      await vi.advanceTimersByTimeAsync(700);
    });
    expect(invokeMock.mock.calls.filter((c) => c[0] === "save_state").length).toBeGreaterThan(0);
  });

  test("load_state hydrates tunnels and selectedTunnelId", async () => {
    const store = createStore();
    invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === "load_state") {
        return {
          schemaVersion: 1,
          tunnels: [
            {
              id: "t1",
              name: "One",
              remote: "vpn.example.com:4433",
              sni: "cdn.example.com",
              qkey: "",
              hasToken: false,
              createdAt: 0,
            },
            {
              id: "t2",
              name: "Two",
              remote: "vpn2.example.com:4433",
              sni: "cdn2.example.com",
              qkey: "",
              hasToken: false,
              createdAt: 0,
            },
          ],
          selectedTunnelId: "t2",
          settings: { connection: { fecPreset: "auto" } },
        };
      }
      if (cmd === "save_state") return null;
      if (cmd === "engine_status") return { state: "Disconnected", activeTunnelId: null, lastError: null };
      if (cmd === "engine_stats") return null;
      if (cmd === "engine_logs_since") return { cursor: 0, lines: [] };
      return null;
    });

    renderApp(store);

    await act(async () => {
      await Promise.resolve();
    });

    expect(store.get(tunnelsAtom)).toHaveLength(2);
    expect(store.get(selectedTunnelIdAtom)).toBe("t2");
    expect((store.get(settingsAtom) as any).connection).toBeUndefined();
  });

  test("load_state selects the first tunnel when selectedTunnelId is missing", async () => {
    const store = createStore();
    invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === "load_state") {
        return {
          schemaVersion: 1,
          tunnels: [
            {
              id: "t1",
              name: "One",
              remote: "vpn.example.com:4433",
              sni: "cdn.example.com",
              qkey: "",
              hasToken: false,
              createdAt: 0,
            },
          ],
          settings: null,
        };
      }
      if (cmd === "save_state") return null;
      if (cmd === "engine_status") return { state: "Disconnected", activeTunnelId: null, lastError: null };
      if (cmd === "engine_stats") return null;
      if (cmd === "engine_logs_since") return { cursor: 0, lines: [] };
      return null;
    });

    renderApp(store);

    await act(async () => {
      await Promise.resolve();
    });

    expect(store.get(tunnelsAtom)).toHaveLength(1);
    expect(store.get(selectedTunnelIdAtom)).toBe("t1");
  });

  test("load_state selects the first tunnel when selectedTunnelId is invalid", async () => {
    const store = createStore();
    invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === "load_state") {
        return {
          schemaVersion: 1,
          tunnels: [
            {
              id: "t1",
              name: "One",
              remote: "vpn.example.com:4433",
              sni: "cdn.example.com",
              qkey: "",
              hasToken: false,
              createdAt: 0,
            },
            {
              id: "t2",
              name: "Two",
              remote: "vpn2.example.com:4433",
              sni: "cdn2.example.com",
              qkey: "",
              hasToken: false,
              createdAt: 0,
            },
          ],
          selectedTunnelId: "does-not-exist",
          settings: null,
        };
      }
      if (cmd === "save_state") return null;
      if (cmd === "engine_status") return { state: "Disconnected", activeTunnelId: null, lastError: null };
      if (cmd === "engine_stats") return null;
      if (cmd === "engine_logs_since") return { cursor: 0, lines: [] };
      return null;
    });

    renderApp(store);

    await act(async () => {
      await Promise.resolve();
    });

    expect(store.get(tunnelsAtom)).toHaveLength(2);
    expect(store.get(selectedTunnelIdAtom)).toBe("t1");
  });

  test("load_state filters malformed tunnels and keeps only valid entries", async () => {
    const store = createStore();
    invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === "load_state") {
        return {
          schemaVersion: 1,
          tunnels: [
            null,
            { id: "", remote: "vpn.example.com:4433", sni: "cdn.example.com", qkey: "", hasToken: false, createdAt: 0 },
            { id: "bad-no-remote", name: "Bad", remote: "", sni: "cdn.example.com", qkey: "", hasToken: false, createdAt: 0 },
            {
              id: "good-1",
              name: "",
              remote: "vpn.example.com:4433",
              sni: "cdn.example.com",
              qkey: "QKey-TEST",
              hasToken: true,
              createdAt: 123,
              countryCode: "de",
              location: "  Frankfurt  ",
            },
          ],
          selectedTunnelId: "missing-id",
          settings: null,
        };
      }
      if (cmd === "save_state") return null;
      if (cmd === "engine_status") return { state: "Disconnected", activeTunnelId: null, lastError: null };
      if (cmd === "engine_stats") return null;
      if (cmd === "engine_logs_since") return { cursor: 0, lines: [] };
      return null;
    });

    renderApp(store);

    await act(async () => {
      await Promise.resolve();
    });

    const tunnels = store.get(tunnelsAtom);
    expect(tunnels).toHaveLength(1);
    expect(tunnels[0]!.id).toBe("good-1");
    expect(tunnels[0]!.name).toBe("vpn.example.com:4433");
    expect(tunnels[0]!.countryCode).toBe("DE");
    expect(tunnels[0]!.location).toBe("Frankfurt");
    expect(store.get(selectedTunnelIdAtom)).toBe("good-1");
  });

  test("load_state ignores invalid selectedTunnelId type and picks first valid tunnel", async () => {
    const store = createStore();
    invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === "load_state") {
        return {
          schemaVersion: 1,
          tunnels: [
            {
              id: "t1",
              name: "One",
              remote: "vpn.example.com:4433",
              sni: "cdn.example.com",
              qkey: "",
              hasToken: false,
              createdAt: 0,
            },
          ],
          selectedTunnelId: 42,
          settings: null,
        };
      }
      if (cmd === "save_state") return null;
      if (cmd === "engine_status") return { state: "Disconnected", activeTunnelId: null, lastError: null };
      if (cmd === "engine_stats") return null;
      if (cmd === "engine_logs_since") return { cursor: 0, lines: [] };
      return null;
    });

    renderApp(store);

    await act(async () => {
      await Promise.resolve();
    });

    expect(store.get(tunnelsAtom)).toHaveLength(1);
    expect(store.get(selectedTunnelIdAtom)).toBe("t1");
  });
});
