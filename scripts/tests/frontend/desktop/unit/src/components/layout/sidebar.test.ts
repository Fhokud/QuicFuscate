import { beforeEach, describe, expect, test, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "../../../testing-library";

import Sidebar from "../../../../../../../../apps/svelte-desktop/src/lib/components/layout/Sidebar.svelte";
import {
  getActiveTab,
  setActiveTab,
} from "../../../../../../../../apps/svelte-desktop/src/lib/stores/app.svelte";

describe("layout/Sidebar", () => {
  beforeEach(() => {
    setActiveTab("tunnels");
  });

  test("renders all four navigation tabs", async () => {
    render(Sidebar);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Tunnels" })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Configuration" })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Logs" })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "About" })).toBeInTheDocument();
    });
  });

  test("renders nav element with Primary aria-label", () => {
    const { container } = render(Sidebar);
    const nav = container.querySelector('nav[aria-label="Primary"]');
    expect(nav).not.toBeNull();
  });

  test("active tab text has font-semibold class", async () => {
    setActiveTab("tunnels");
    render(Sidebar);

    await waitFor(() => {
      const tunnelsBtn = screen.getByRole("button", { name: "Tunnels" });
      expect(tunnelsBtn.classList.contains("font-semibold")).toBe(true);
    });
  });

  test("inactive tab does not have font-semibold class", async () => {
    setActiveTab("tunnels");
    render(Sidebar);

    await waitFor(() => {
      const logsBtn = screen.getByRole("button", { name: "Logs" });
      expect(logsBtn.classList.contains("font-semibold")).toBe(false);
    });
  });

  test("clicking a tab updates the active tab", async () => {
    setActiveTab("tunnels");
    render(Sidebar);

    await fireEvent.click(screen.getByRole("button", { name: "Logs" }));

    await waitFor(() => {
      expect(getActiveTab()).toBe("logs");
    });
  });

  test("clicking Configuration tab sets active tab to settings", async () => {
    setActiveTab("tunnels");
    render(Sidebar);

    await fireEvent.click(screen.getByRole("button", { name: "Configuration" }));

    await waitFor(() => {
      expect(getActiveTab()).toBe("settings");
    });
  });

  test("clicking About tab sets active tab to about", async () => {
    setActiveTab("tunnels");
    render(Sidebar);

    await fireEvent.click(screen.getByRole("button", { name: "About" }));

    await waitFor(() => {
      expect(getActiveTab()).toBe("about");
    });
  });

  test("tab labels are correct", async () => {
    render(Sidebar);

    await waitFor(() => {
      expect(screen.getByText("Tunnels")).toBeInTheDocument();
      expect(screen.getByText("Configuration")).toBeInTheDocument();
      expect(screen.getByText("Logs")).toBeInTheDocument();
      expect(screen.getByText("About")).toBeInTheDocument();
    });
  });

  test("renders the QuicFuscate logo", () => {
    render(Sidebar);
    const img = screen.getByAltText("QuicFuscate logo");
    expect(img).toBeInTheDocument();
  });
});
