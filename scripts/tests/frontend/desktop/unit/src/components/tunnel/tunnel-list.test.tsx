import { describe, expect, test } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { HeroUIProvider } from "@heroui/react";
import { Provider } from "jotai";
import { createStore } from "jotai/vanilla";
import { selectedTunnelIdAtom, tunnelStatesAtom, tunnelsAtom } from "@/stores/atoms";
import { TunnelList } from "@/components/tunnel/tunnel-list";

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
  store.set(tunnelsAtom, [
    {
      id: "t1",
      name: "Alpha",
      remote: "alpha.example.com:4433",
      countryCode: "US",
      createdAt: Date.now(),
      qkey: "",
      sni: "",
      hasToken: false,
    },
    {
      id: "t2",
      name: "Beta",
      remote: "beta.example.com:4433",
      countryCode: "DE",
      createdAt: Date.now(),
      qkey: "",
      sni: "",
      hasToken: false,
    },
  ]);
  store.set(tunnelStatesAtom, {});
  store.set(selectedTunnelIdAtom, null);
}

function getRowByName(name: string) {
  const labels = screen.getAllByText(name);
  const row = labels
    .map((label) => label.closest('[role="button"]'))
    .find((candidate): candidate is HTMLElement => Boolean(candidate));
  if (!row) throw new Error(`row not found for ${name}`);
  return row;
}

describe("TunnelList", () => {
  test("delete does not select a row due to stopPropagation", async () => {
    const store = createStore();
    seedTunnels(store);
    renderWithProviders(<TunnelList />, store);

    const alphaRow = getRowByName("Alpha");
    fireEvent.click(within(alphaRow).getByRole("button", { name: "Remove tunnel" }));
    const deleteDialog = await screen.findByRole("dialog", { name: "Delete Tunnel" });
    fireEvent.click(within(deleteDialog).getByRole("button", { name: "Delete" }));

    await waitFor(() => {
      expect(store.get(selectedTunnelIdAtom)).toBeNull();
      expect(store.get(tunnelsAtom).map((t) => t.id)).toEqual(["t2"]);
    });
  });

  test("deleting selected tunnel clears selection", async () => {
    const store = createStore();
    seedTunnels(store);
    store.set(selectedTunnelIdAtom, "t1");
    renderWithProviders(<TunnelList />, store);

    const alphaRow = getRowByName("Alpha");
    fireEvent.click(within(alphaRow).getByRole("button", { name: "Remove tunnel" }));
    const deleteDialog = await screen.findByRole("dialog", { name: "Delete Tunnel" });
    fireEvent.click(within(deleteDialog).getByRole("button", { name: "Delete" }));

    await waitFor(() => {
      expect(store.get(selectedTunnelIdAtom)).toBeNull();
      expect(store.get(tunnelsAtom).map((t) => t.id)).toEqual(["t2"]);
    });
  });

  test("deleting unselected tunnel keeps current selection", async () => {
    const store = createStore();
    seedTunnels(store);
    store.set(selectedTunnelIdAtom, "t1");
    renderWithProviders(<TunnelList />, store);

    const betaRow = getRowByName("Beta");
    fireEvent.click(within(betaRow).getByRole("button", { name: "Remove tunnel" }));
    const deleteDialog = await screen.findByRole("dialog", { name: "Delete Tunnel" });
    fireEvent.click(within(deleteDialog).getByRole("button", { name: "Delete" }));

    await waitFor(() => {
      expect(store.get(selectedTunnelIdAtom)).toBe("t1");
      expect(store.get(tunnelsAtom).map((t) => t.id)).toEqual(["t1"]);
    });
  });
});
