import { describe, expect, test, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { HeroUIProvider } from "@heroui/react";
import { Provider } from "jotai";
import { createStore } from "jotai/vanilla";
import { EditQKeyDialog } from "@/components/tunnel/edit-qkey-dialog";
import { tunnelsAtom } from "@/stores/atoms";

const invokeMock = vi.fn();
const readClipboardTextDirectMock = vi.fn<() => Promise<string>>();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invokeMock(...args),
}));
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

function seedTunnels(store = createStore()) {
  const now = Date.now();
  store.set(tunnelsAtom, [
    {
      id: "t1",
      name: "One",
      remote: "manual1.example.com:4433",
      sni: "manual1.example.com",
      qkey: "",
      createdAt: now,
      hasToken: false,
    },
    {
      id: "t2",
      name: "Two",
      remote: "manual2.example.com:4433",
      sni: "manual2.example.com",
      qkey: "",
      createdAt: now,
      hasToken: false,
    },
  ]);
}

describe("EditQKeyDialog", () => {
  const previousTauriInternals = (globalThis as any).__TAURI_INTERNALS__;

  beforeEach(() => {
    invokeMock.mockReset();
    readClipboardTextDirectMock.mockReset();
    readClipboardTextDirectMock.mockResolvedValue("");
    delete (globalThis as any).__TAURI_INTERNALS__;
  });

  afterEach(() => {
    if (previousTauriInternals) (globalThis as any).__TAURI_INTERNALS__ = previousTauriInternals;
    else delete (globalThis as any).__TAURI_INTERNALS__;
  });

  test("is disabled in browser mode without showing runtime validation message", async () => {
    const store = createStore();
    seedTunnels(store);
    renderWithProviders(<EditQKeyDialog open onOpenChange={() => {}} tunnelId="t1" mode="set" />, store);

    const field = screen.getByLabelText("QKey String", { exact: true });
    fireEvent.change(field, { target: { value: "QKey-ABC_def-123==" } });

    expect(screen.queryByText("Validation requires the desktop app runtime")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
  });

  test("pastes clipboard content into edit textarea", async () => {
    const store = createStore();
    seedTunnels(store);
    readClipboardTextDirectMock.mockResolvedValue("QKey-PASTED-EDIT");
    renderWithProviders(<EditQKeyDialog open onOpenChange={() => {}} tunnelId="t1" mode="set" />, store);

    fireEvent.click(screen.getByRole("button", { name: "Paste" }));

    await waitFor(() => {
      const field = screen.getByLabelText("QKey String", { exact: true }) as HTMLTextAreaElement;
      expect(field.value).toBe("QKey-PASTED-EDIT");
    });
  });

  test("updates only the selected tunnel when qkey_parse succeeds", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    const onOpenChange = vi.fn();
    seedTunnels(store);

    invokeMock.mockResolvedValue({
      remote: "vpn.example.com:4433",
      sni: "cdn.example.com",
      hasToken: true,
    });

    renderWithProviders(<EditQKeyDialog open onOpenChange={onOpenChange} tunnelId="t1" mode="replace" />, store);

    fireEvent.change(screen.getByLabelText("QKey String", { exact: true }), {
      target: { value: "prefix qkey-ABC_def-123== suffix" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => {
      const tunnels = store.get(tunnelsAtom);
      expect(tunnels[0]!.qkey).toBe("QKey-ABC_def-123==");
      expect(tunnels[0]!.hasToken).toBe(true);
      expect(tunnels[0]!.remote).toBe("vpn.example.com:4433");
      expect(tunnels[0]!.sni).toBe("cdn.example.com");
      expect(tunnels[1]!.qkey).toBe("");
      expect(tunnels[1]!.remote).toBe("manual2.example.com:4433");
      expect(tunnels[1]!.sni).toBe("manual2.example.com");
    });

    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  test("keeps existing remote and sni when parser returns empty values", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    seedTunnels(store);
    invokeMock.mockResolvedValue({
      remote: "",
      sni: "",
      hasToken: true,
    });

    renderWithProviders(<EditQKeyDialog open onOpenChange={() => {}} tunnelId="t1" mode="set" />, store);

    fireEvent.change(screen.getByLabelText("QKey String", { exact: true }), {
      target: { value: "QKey-ABC_def-123==" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => {
      const t = store.get(tunnelsAtom)[0]!;
      expect(t.qkey).toBe("QKey-ABC_def-123==");
      expect(t.hasToken).toBe(true);
      expect(t.remote).toBe("manual1.example.com:4433");
      expect(t.sni).toBe("manual1.example.com");
    });
  });

  test("shows parse error and leaves tunnel unchanged when qkey_parse fails", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    seedTunnels(store);
    invokeMock.mockRejectedValue("Invalid QKey");

    renderWithProviders(<EditQKeyDialog open onOpenChange={() => {}} tunnelId="t1" mode="set" />, store);

    fireEvent.change(screen.getByLabelText("QKey String", { exact: true }), {
      target: { value: "QKey-ABC_def-123==" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    });
    const t = store.get(tunnelsAtom)[0]!;
    expect(t.qkey).toBe("");
    expect(t.hasToken).toBe(false);
    expect(t.remote).toBe("manual1.example.com:4433");
    expect(t.sni).toBe("manual1.example.com");
  });

  test("rejects parsed payload with invalid remote endpoint and keeps tunnel unchanged", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    seedTunnels(store);
    invokeMock.mockResolvedValue({
      remote: "https://vpn.example.com:4433",
      sni: "cdn.example.com",
      hasToken: true,
    });

    renderWithProviders(<EditQKeyDialog open onOpenChange={() => {}} tunnelId="t1" mode="replace" />, store);

    fireEvent.change(screen.getByLabelText("QKey String", { exact: true }), {
      target: { value: "QKey-ABC_def-123==" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    });
    const t = store.get(tunnelsAtom)[0]!;
    expect(t.qkey).toBe("");
    expect(t.remote).toBe("manual1.example.com:4433");
    expect(t.sni).toBe("manual1.example.com");
  });

  test("rejects parsed payload with invalid SNI and keeps tunnel unchanged", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    seedTunnels(store);
    invokeMock.mockResolvedValue({
      remote: "vpn.example.com:4433",
      sni: "cdn.example.com:443",
      hasToken: true,
    });

    renderWithProviders(<EditQKeyDialog open onOpenChange={() => {}} tunnelId="t1" mode="replace" />, store);

    fireEvent.change(screen.getByLabelText("QKey String", { exact: true }), {
      target: { value: "QKey-ABC_def-123==" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    });
    const t = store.get(tunnelsAtom)[0]!;
    expect(t.qkey).toBe("");
    expect(t.remote).toBe("manual1.example.com:4433");
    expect(t.sni).toBe("manual1.example.com");
  });

  test("keeps save disabled for text without a QKey", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    seedTunnels(store);

    renderWithProviders(<EditQKeyDialog open onOpenChange={() => {}} tunnelId="t1" mode="set" />, store);

    fireEvent.change(screen.getByLabelText("QKey String", { exact: true }), {
      target: { value: "hello-world-without-token" },
    });

    expect(screen.queryByText("No QKey found in pasted text")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
  });

  test("qkey textarea input is capped at 16384 characters", async () => {
    (globalThis as any).__TAURI_INTERNALS__ = { invoke: invokeMock };
    const store = createStore();
    seedTunnels(store);

    renderWithProviders(<EditQKeyDialog open onOpenChange={() => {}} tunnelId="t1" mode="set" />, store);
    const field = screen.getByLabelText("QKey String", { exact: true }) as HTMLTextAreaElement;
    fireEvent.change(field, { target: { value: "QKey-" + "A".repeat(20000) } });

    expect(field.value.length).toBe(16384);
  });
});
