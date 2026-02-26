import { describe, expect, test, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { HeroUIProvider } from "@heroui/react";
import { Provider } from "jotai";
import { createStore } from "jotai/vanilla";
import { TunnelDetail } from "@/components/tunnel/tunnel-detail";
import { selectedTunnelIdAtom, tunnelStatesAtom, tunnelsAtom } from "@/stores/atoms";

function renderWithProviders(ui: React.ReactNode, store = createStore()) {
  return {
    store,
    ...render(
      <HeroUIProvider>
        <Provider store={store}>{ui}</Provider>
      </HeroUIProvider>,
    ),
  };
}

function seedOneTunnel(store = createStore(), overrides?: Partial<any>) {
  const tunnel = {
    id: "t1",
    name: "Test",
    remote: "vpn.example.com:4433",
    sni: "cdn.example.com",
    qkey: "QKey-ABC_def-123==",
    createdAt: Date.now(),
    hasToken: true,
    ...overrides,
  };
  store.set(tunnelsAtom, [tunnel]);
  store.set(selectedTunnelIdAtom, tunnel.id);
  return tunnel;
}

describe("TunnelDetail", () => {
  const prev = (globalThis as any).__TAURI_INTERNALS__;
  const invokeMock = vi.fn();

  beforeEach(() => {
    invokeMock.mockReset();
    delete (globalThis as any).__TAURI_INTERNALS__;
  });

  afterEach(() => {
    if (prev) (globalThis as any).__TAURI_INTERNALS__ = prev;
    else delete (globalThis as any).__TAURI_INTERNALS__;
  });

  test("connect in browser mode shows runtime error", async () => {
    const store = createStore();
    seedOneTunnel(store);
    renderWithProviders(<TunnelDetail />, store);

    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await expect(screen.findByText("Connect requires the desktop app runtime")).resolves.toBeInTheDocument();
  });

  test("missing QKey routes primary action to Set QKey dialog", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    seedOneTunnel(store, { qkey: "", hasToken: false });
    renderWithProviders(<TunnelDetail />, store);

    fireEvent.click(screen.getAllByRole("button", { name: "Set QKey" })[0]!);
    await expect(screen.findByLabelText("QKey String")).resolves.toBeInTheDocument();
    expect(invokeMock.mock.calls.filter((c) => c[0] === "engine_connect").length).toBe(0);
  });

  test("connect failure sets error and returns state to inactive", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    const tunnel = seedOneTunnel(store);
    renderWithProviders(<TunnelDetail />, store);

    invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === "qkey_parse") return { stealth: null, fec: null };
      if (cmd === "engine_connect") throw "boom";
      throw `unexpected command: ${cmd}`;
    });

    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await expect(screen.findByText(/boom/i)).resolves.toBeInTheDocument();

    await waitFor(() => {
      const states = store.get(tunnelStatesAtom);
      expect(states[tunnel.id]).toBe("inactive");
    });
  });

  test("connect becomes disabled while activating and does not double-invoke", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    const tunnel = seedOneTunnel(store);
    renderWithProviders(<TunnelDetail />, store);

    let resolveConnect: (() => void) | null = null;
    const connectPromise = new Promise<void>((resolve) => { resolveConnect = resolve; });

    invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === "qkey_parse") return { stealth: null, fec: null };
      if (cmd === "engine_connect") return await connectPromise;
      throw `unexpected command: ${cmd}`;
    });

    const connectBtn = screen.getByRole("button", { name: "Connect" });
    fireEvent.click(connectBtn);

    // Immediately after clicking, state should flip to "activating" and the button should be disabled.
    await waitFor(() => {
      expect(store.get(tunnelStatesAtom)[tunnel.id]).toBe("activating");
    });
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Connect" })).toBeDisabled();
    });

    // Try clicking again (should be ignored because button is disabled/isBusy).
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    expect(invokeMock.mock.calls.filter((c) => c[0] === "engine_connect").length).toBe(1);

    resolveConnect?.();
    await waitFor(() => {
      expect(store.get(tunnelStatesAtom)[tunnel.id]).toBe("active");
    });
  });

  test("disconnect confirmation calls engine_disconnect and handles failure", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    const tunnel = seedOneTunnel(store);
    store.set(tunnelStatesAtom, { [tunnel.id]: "active" });
    renderWithProviders(<TunnelDetail />, store);

    invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === "qkey_parse") return { stealth: null, fec: null };
      if (cmd === "engine_disconnect") throw "disconnect exploded";
      throw `unexpected command: ${cmd}`;
    });

    fireEvent.click(screen.getByRole("button", { name: "Disconnect" }));
    await expect(screen.findByText("Disconnect Tunnel")).resolves.toBeInTheDocument();

    fireEvent.click(screen.getAllByRole("button", { name: "Disconnect" }).slice(-1)[0]!);
    await expect(screen.findByText(/disconnect exploded/i)).resolves.toBeInTheDocument();

    await waitFor(() => {
      const states = store.get(tunnelStatesAtom);
      expect(states[tunnel.id]).toBe("inactive");
    });
  });

  test("set qkey dialog updates tunnel qkey and endpoint fields", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    seedOneTunnel(store, { qkey: "", hasToken: false, remote: "manual.example.com:4433", sni: "manual.example.com" });
    renderWithProviders(<TunnelDetail />, store);

    invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === "qkey_parse") return { remote: "vpn.example.com:4433", sni: "cdn.example.com", hasToken: true, stealth: null, fec: null };
      throw `unexpected command: ${cmd}`;
    });

    fireEvent.click(screen.getAllByRole("button", { name: "Set QKey" })[0]!);
    const field = await screen.findByLabelText("QKey String");
    fireEvent.change(field, { target: { value: "hello QKey-ABC_def-123==" } });

    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => {
      const tunnels = store.get(tunnelsAtom);
      expect(tunnels[0].qkey).toBe("QKey-ABC_def-123==");
      expect(tunnels[0].hasToken).toBe(true);
      expect(tunnels[0].remote).toBe("vpn.example.com:4433");
      expect(tunnels[0].sni).toBe("cdn.example.com");
    });
  });

  test("set qkey dialog shows parse error and does not update tunnel on failure", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    seedOneTunnel(store, { qkey: "", hasToken: false, remote: "manual.example.com:4433", sni: "manual.example.com" });
    renderWithProviders(<TunnelDetail />, store);

    invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === "qkey_parse") throw "Invalid QKey";
      throw `unexpected command: ${cmd}`;
    });

    fireEvent.click(screen.getAllByRole("button", { name: "Set QKey" })[0]!);
    const field = await screen.findByLabelText("QKey String");
    fireEvent.change(field, { target: { value: "hello QKey-ABC_def-123==" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    });
    const tunnels = store.get(tunnelsAtom);
    expect(tunnels[0].qkey).toBe("");
    expect(tunnels[0].hasToken).toBe(false);
    expect(tunnels[0].remote).toBe("manual.example.com:4433");
    expect(tunnels[0].sni).toBe("manual.example.com");
  });

  test("set qkey dialog does not overwrite endpoint when parser returns empty strings", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    seedOneTunnel(store, { qkey: "", hasToken: false, remote: "manual.example.com:4433", sni: "manual.example.com" });
    renderWithProviders(<TunnelDetail />, store);

    invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === "qkey_parse") return { remote: "", sni: "", hasToken: true, stealth: null, fec: null };
      throw `unexpected command: ${cmd}`;
    });

    fireEvent.click(screen.getAllByRole("button", { name: "Set QKey" })[0]!);
    const field = await screen.findByLabelText("QKey String");
    fireEvent.change(field, { target: { value: "QKey-ABC_def-123==" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => {
      const tunnels = store.get(tunnelsAtom);
      expect(tunnels[0].qkey).toBe("QKey-ABC_def-123==");
      expect(tunnels[0].hasToken).toBe(true);
      expect(tunnels[0].remote).toBe("manual.example.com:4433");
      expect(tunnels[0].sni).toBe("manual.example.com");
    });
  });

  test("shows QKey-provided stealth and fec modes when parser returns them", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    seedOneTunnel(store, { qkey: "QKey-ABC_def-123==", hasToken: true });
    renderWithProviders(<TunnelDetail />, store);

    invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === "qkey_parse") return { stealth: "max", fec: "on" };
      throw `unexpected command: ${cmd}`;
    });

    await expect(screen.findByText("AntiDPI")).resolves.toBeInTheDocument();
    await expect(screen.findByText("On")).resolves.toBeInTheDocument();

    const badges = screen.getAllByText("QKey");
    expect(badges.length).toBeGreaterThanOrEqual(2);
  });

  test("falls back to default modes when parser returns non-string values", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    seedOneTunnel(store, { qkey: "QKey-ABC_def-123==", hasToken: true });
    renderWithProviders(<TunnelDetail />, store);

    invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === "qkey_parse") return { stealth: 123, fec: { mode: "on" } };
      throw `unexpected command: ${cmd}`;
    });

    await expect(screen.findByText("Auto")).resolves.toBeInTheDocument();
    await expect(screen.findByText("On")).resolves.toBeInTheDocument();

    const defaultBadges = screen.getAllByText("Default");
    expect(defaultBadges.length).toBeGreaterThanOrEqual(2);
  });
});
