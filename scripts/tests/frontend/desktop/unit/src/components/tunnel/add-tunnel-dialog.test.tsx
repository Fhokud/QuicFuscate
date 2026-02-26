import { describe, expect, test, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { HeroUIProvider } from "@heroui/react";
import { Provider } from "jotai";
import { createStore } from "jotai/vanilla";
import { CreateTunnelDialog, ImportQKeyDialog } from "@/components/tunnel/add-tunnel-dialog";
import { tunnelsAtom } from "@/stores/atoms";

const readClipboardTextDirectMock = vi.fn<() => Promise<string>>();
vi.mock("@/lib/clipboard", () => ({
  readClipboardTextDirect: () => readClipboardTextDirectMock(),
}));

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

describe("CreateTunnelDialog", () => {
  const NAME_LABEL = "Name of the Connection";
  const REMOTE_LABEL = "Remote [IP-Address:Port]";

  beforeEach(() => {
    if (typeof Element.prototype.scrollIntoView !== "function") {
      Object.defineProperty(Element.prototype, "scrollIntoView", {
        value: vi.fn(),
        writable: true,
        configurable: true,
      });
    }
  });

  test("rejects invalid remote and does not create a tunnel", async () => {
    const store = createStore();
    const onOpenChange = vi.fn();
    renderWithProviders(<CreateTunnelDialog open onOpenChange={onOpenChange} />, store);

    fireEvent.change(screen.getByLabelText(NAME_LABEL, { exact: true }), { target: { value: "Test" } });
    fireEvent.change(screen.getByLabelText(REMOTE_LABEL, { exact: true }), { target: { value: "not a remote" } });
    fireEvent.click(screen.getByRole("button", { name: /Create/ }));

    await waitFor(() => {
      expect(store.get(tunnelsAtom)).toHaveLength(0);
    });
    expect(store.get(tunnelsAtom)).toHaveLength(0);
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
  });

  test("rejects unbracketed IPv6 remote and does not create a tunnel", async () => {
    const store = createStore();
    const onOpenChange = vi.fn();
    renderWithProviders(<CreateTunnelDialog open onOpenChange={onOpenChange} />, store);

    fireEvent.change(screen.getByLabelText(NAME_LABEL, { exact: true }), { target: { value: "IPv6 Test" } });
    fireEvent.change(screen.getByLabelText(REMOTE_LABEL, { exact: true }), { target: { value: "2001:db8::1:4433" } });
    fireEvent.click(screen.getByRole("button", { name: /Create/ }));

    await waitFor(() => {
      expect(store.get(tunnelsAtom)).toHaveLength(0);
    });
    expect(store.get(tunnelsAtom)).toHaveLength(0);
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
  });

  test("rejects URL-like remote value and does not create a tunnel", async () => {
    const store = createStore();
    const onOpenChange = vi.fn();
    renderWithProviders(<CreateTunnelDialog open onOpenChange={onOpenChange} />, store);

    fireEvent.change(screen.getByLabelText(NAME_LABEL, { exact: true }), { target: { value: "URL Test" } });
    fireEvent.change(screen.getByLabelText(REMOTE_LABEL, { exact: true }), { target: { value: "https://vpn.example.com:4433" } });
    fireEvent.click(screen.getByRole("button", { name: /Create/ }));

    await waitFor(() => {
      expect(store.get(tunnelsAtom)).toHaveLength(0);
    });
    expect(store.get(tunnelsAtom)).toHaveLength(0);
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
  });

  test("creates a tunnel with selected country and default SNI for IPv4 remotes", async () => {
    const store = createStore();
    const onOpenChange = vi.fn();
    renderWithProviders(<CreateTunnelDialog open onOpenChange={onOpenChange} />, store);

    fireEvent.change(screen.getByLabelText(NAME_LABEL, { exact: true }), { target: { value: "Berlin" } });
    fireEvent.change(screen.getByLabelText(REMOTE_LABEL, { exact: true }), { target: { value: "203.0.113.11:4433" } });
    const countryTrigger = document.querySelector<HTMLButtonElement>('[aria-haspopup="listbox"]');
    expect(countryTrigger).not.toBeNull();
    fireEvent.click(countryTrigger!);
    const listbox = await screen.findByRole("listbox");
    const listboxOptions = Array.from(listbox.querySelectorAll("[data-option]"));
    const germanyOption = listboxOptions.find((option) => option.textContent?.includes("Germany"));
    expect(germanyOption).toBeDefined();
    if (!germanyOption) throw new Error("Germany option not found");
    fireEvent.click(germanyOption);
    fireEvent.click(screen.getByRole("button", { name: /Create/ }));

    await waitFor(() => {
      expect(store.get(tunnelsAtom)).toHaveLength(1);
    });
    const t = store.get(tunnelsAtom)[0]!;
    expect(t.name).toBe("Berlin");
    expect(t.countryCode).toBe("DE");
    expect(t.remote).toBe("203.0.113.11:4433");
    expect(t.sni).toBe("cdn.cloudflare.com");
    expect(t.qkey).toBe("");
    expect(t.hasToken).toBe(false);
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  test("auto-selects built-in SNI for IPv6 and stores bracketed remote", async () => {
    const store = createStore();
    const onOpenChange = vi.fn();
    renderWithProviders(<CreateTunnelDialog open onOpenChange={onOpenChange} />, store);

    fireEvent.change(screen.getByLabelText(NAME_LABEL, { exact: true }), { target: { value: "Local" } });
    fireEvent.change(screen.getByLabelText(REMOTE_LABEL, { exact: true }), { target: { value: "[::1]" } });
    fireEvent.click(screen.getByRole("button", { name: /Create/ }));

    await waitFor(() => {
      expect(store.get(tunnelsAtom)).toHaveLength(1);
    });
    const t = store.get(tunnelsAtom)[0]!;
    expect(t.remote).toBe("[::1]:4433");
    expect(t.sni).toBe("cdn.cloudflare.com");
  });

  test("auto-selects built-in SNI for IPv4 remote endpoints", async () => {
    const store = createStore();
    const onOpenChange = vi.fn();
    renderWithProviders(<CreateTunnelDialog open onOpenChange={onOpenChange} />, store);

    fireEvent.change(screen.getByLabelText(NAME_LABEL, { exact: true }), { target: { value: "IPv4 Tunnel" } });
    fireEvent.change(screen.getByLabelText(REMOTE_LABEL, { exact: true }), { target: { value: "1.2.3.4:4433" } });
    fireEvent.click(screen.getByRole("button", { name: /Create/ }));

    await waitFor(() => {
      expect(store.get(tunnelsAtom)).toHaveLength(1);
    });
    const t = store.get(tunnelsAtom)[0]!;
    expect(t.sni).toBe("cdn.cloudflare.com");
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  test("creates a tunnel without country selection", async () => {
    const store = createStore();
    const onOpenChange = vi.fn();
    renderWithProviders(<CreateTunnelDialog open onOpenChange={onOpenChange} />, store);

    fireEvent.change(screen.getByLabelText(NAME_LABEL, { exact: true }), { target: { value: "Berlin No Flag" } });
    fireEvent.change(screen.getByLabelText(REMOTE_LABEL, { exact: true }), { target: { value: "198.51.100.13:4433" } });
    fireEvent.click(screen.getByRole("button", { name: /Create/ }));

    await waitFor(() => {
      expect(store.get(tunnelsAtom)).toHaveLength(1);
    });
    const t = store.get(tunnelsAtom)[0]!;
    expect(t.countryCode).toBeUndefined();
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });
});

describe("ImportQKeyDialog", () => {
  const prev = (globalThis as any).__TAURI_INTERNALS__;
  const invokeMock = vi.fn();

  beforeEach(() => {
    delete (globalThis as any).__TAURI_INTERNALS__;
    invokeMock.mockReset();
    readClipboardTextDirectMock.mockReset();
    readClipboardTextDirectMock.mockResolvedValue("");
  });

  afterEach(() => {
    if (prev) (globalThis as any).__TAURI_INTERNALS__ = prev;
    else delete (globalThis as any).__TAURI_INTERNALS__;
  });

  test("is disabled in browser mode without showing runtime error text", async () => {
    renderWithProviders(<ImportQKeyDialog open onOpenChange={() => {}} />);

    const textarea = screen.getByLabelText("QKey String", { exact: true });
    fireEvent.change(textarea, { target: { value: "QKey-TESTONLY" } });

    expect(screen.queryByText("Import requires the desktop app runtime")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Import" })).toBeDisabled();
  });

  test("pastes clipboard content into import textarea", async () => {
    readClipboardTextDirectMock.mockResolvedValue("QKey-PASTED-123");
    renderWithProviders(<ImportQKeyDialog open onOpenChange={() => {}} />);

    fireEvent.click(screen.getByRole("button", { name: "Paste" }));

    await waitFor(() => {
      const textarea = screen.getByLabelText("QKey String", { exact: true }) as HTMLTextAreaElement;
      expect(textarea.value).toBe("QKey-PASTED-123");
    });
  });

  test("enables import when runtime is present and a QKey is detected", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    renderWithProviders(<ImportQKeyDialog open onOpenChange={() => {}} />);

    const textarea = screen.getByLabelText("QKey String", { exact: true });
    fireEvent.change(textarea, { target: { value: "hello" } });
    expect(screen.getByRole("button", { name: "Import" })).toBeDisabled();

    fireEvent.change(textarea, { target: { value: "prefix QKey-ABC_def-123== suffix" } });
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Import" })).toBeEnabled();
    });
  });

  test("does not add a tunnel when qkey_parse fails", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    renderWithProviders(<ImportQKeyDialog open onOpenChange={() => {}} />, store);

    invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === "qkey_parse") throw "Invalid QKey";
      throw `unexpected command: ${cmd}`;
    });

    fireEvent.change(screen.getByLabelText("QKey String", { exact: true }), {
      target: { value: "QKey-ABC_def-123==" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Import" }));

    await waitFor(() => {
      expect(invokeMock).toHaveBeenCalled();
      expect(invokeMock.mock.calls[0]?.[0]).toBe("qkey_parse");
    });
    expect(store.get(tunnelsAtom)).toHaveLength(0);
  });

  test("adds a tunnel when qkey_parse succeeds", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    const onOpenChange = vi.fn();
    renderWithProviders(<ImportQKeyDialog open onOpenChange={onOpenChange} />, store);

    invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === "qkey_parse") {
        return { remote: "vpn.example.com:4433", sni: "cdn.example.com", hasToken: true };
      }
      throw new Error(`unexpected command: ${cmd}`);
    });

    fireEvent.change(screen.getByLabelText("QKey String", { exact: true }), {
      target: { value: "prefix qkey-ABC_def-123== suffix" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Import" }));

    await waitFor(() => expect(store.get(tunnelsAtom)).toHaveLength(1));
    const t = store.get(tunnelsAtom)[0]!;
    expect(t.remote).toBe("vpn.example.com:4433");
    expect(t.sni).toBe("cdn.example.com");
    expect(t.hasToken).toBe(true);
    expect(t.qkey.startsWith("QKey-")).toBe(true);
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  test("rejects parsed QKey payload with invalid remote endpoint", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    renderWithProviders(<ImportQKeyDialog open onOpenChange={() => {}} />, store);

    invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === "qkey_parse") {
        return { remote: "https://vpn.example.com:4433", sni: "cdn.example.com", hasToken: true };
      }
      throw new Error(`unexpected command: ${cmd}`);
    });

    fireEvent.change(screen.getByLabelText("QKey String", { exact: true }), {
      target: { value: "QKey-ABC_def-123==" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Import" }));

    await waitFor(() => {
      expect((screen.getByLabelText("QKey String", { exact: true }) as HTMLTextAreaElement).getAttribute("aria-invalid")).toBe("true");
    });
    expect(store.get(tunnelsAtom)).toHaveLength(0);
  });

  test("rejects parsed QKey payload with invalid SNI", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    renderWithProviders(<ImportQKeyDialog open onOpenChange={() => {}} />, store);

    invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === "qkey_parse") {
        return { remote: "vpn.example.com:4433", sni: "cdn.example.com:443", hasToken: true };
      }
      throw new Error(`unexpected command: ${cmd}`);
    });

    fireEvent.change(screen.getByLabelText("QKey String", { exact: true }), {
      target: { value: "QKey-ABC_def-123==" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Import" }));

    await waitFor(() => {
      expect((screen.getByLabelText("QKey String", { exact: true }) as HTMLTextAreaElement).getAttribute("aria-invalid")).toBe("true");
    });
    expect(store.get(tunnelsAtom)).toHaveLength(0);
  });

  test("derives a stable name from bracketed IPv6 remote on import", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    renderWithProviders(<ImportQKeyDialog open onOpenChange={() => {}} />, store);

    invokeMock.mockImplementation(async (cmd: string) => {
      if (cmd === "qkey_parse") {
        return { remote: "[2001:db8::1]:4433", sni: "cdn.example.com", hasToken: true };
      }
      throw new Error(`unexpected command: ${cmd}`);
    });

    fireEvent.change(screen.getByLabelText("QKey String", { exact: true }), {
      target: { value: "QKey-ABC_def-123==" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Import" }));

    await waitFor(() => expect(store.get(tunnelsAtom)).toHaveLength(1));
    const t = store.get(tunnelsAtom)[0]!;
    expect(t.name).toBe("2001:db8::1");
    expect(t.remote).toBe("[2001:db8::1]:4433");
  });

  test("qkey textarea input is capped at 16384 characters", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    renderWithProviders(<ImportQKeyDialog open onOpenChange={() => {}} />);

    const textarea = screen.getByLabelText("QKey String", { exact: true }) as HTMLTextAreaElement;
    fireEvent.change(textarea, { target: { value: "QKey-" + "A".repeat(20000) } });

    expect(textarea.value.length).toBe(16384);
  });
});
