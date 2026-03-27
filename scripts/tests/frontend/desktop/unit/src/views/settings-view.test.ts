import { beforeEach, describe, expect, test, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "../../testing-library";

let tauriAvailable = false;

vi.mock("$lib/stores/tauri-bridge.svelte", async () => {
  const actual = await vi.importActual<typeof import("$lib/stores/tauri-bridge.svelte")>("$lib/stores/tauri-bridge.svelte");
  return {
    ...actual,
    isTauri: () => tauriAvailable,
  };
});

vi.mock("$lib/updater", async () => {
  return {
    checkForUpdates: vi.fn(),
    createTauriUpdaterDriver: vi.fn(),
    downloadAndInstallUpdate: vi.fn(),
    toTerminalUpdaterErrorState: vi.fn(() => ({ status: "error" as const, message: "mock" })),
    updaterEnabledByPolicy: (_rt: boolean, _setting: boolean, _runtime: boolean) => ({
      enabled: false,
      reason: "Updater disabled in test.",
    }),
  };
});

vi.mock("@quicfuscate/ui", async () => {
  const actual = await vi.importActual<typeof import("@quicfuscate/ui")>("@quicfuscate/ui");
  return {
    ...actual,
    ripple: () => {},
  };
});

import SettingsView from "../../../../../../../apps/svelte-desktop/src/lib/components/views/SettingsView.svelte";
import {
  getSettings,
  setSettings,
} from "../../../../../../../apps/svelte-desktop/src/lib/stores/app.svelte";

function seedDefaults(): void {
  setSettings({
    general: {
      logLevel: "info",
      autoConnectOnLaunch: false,
      startAtLogin: false,
      updaterEnabled: false,
      updaterChannel: "stable",
    },
    hardware: {
      detectedFeatures: [],
    },
  });
}

describe("views/SettingsView", () => {
  beforeEach(() => {
    tauriAvailable = false;
    seedDefaults();
  });

  test("renders the Configuration heading", async () => {
    render(SettingsView);

    await waitFor(() => {
      expect(screen.getByText("Configuration")).toBeInTheDocument();
    });
  });

  test("renders Logging section with Log Level label", async () => {
    render(SettingsView);

    await waitFor(() => {
      expect(screen.getByText("Logging")).toBeInTheDocument();
      expect(screen.getByText("Log Level")).toBeInTheDocument();
    });
  });

  test("renders Auto-connect toggle", async () => {
    render(SettingsView);

    await waitFor(() => {
      expect(screen.getByRole("switch", { name: "Auto-connect on launch" })).toBeInTheDocument();
    });
  });

  test("renders Start at login toggle", async () => {
    render(SettingsView);

    await waitFor(() => {
      expect(screen.getByRole("switch", { name: "Start at login" })).toBeInTheDocument();
    });
  });

  test("renders Startup section heading", async () => {
    render(SettingsView);

    await waitFor(() => {
      expect(screen.getByText("Startup")).toBeInTheDocument();
    });
  });

  test("renders Updates section", async () => {
    render(SettingsView);

    await waitFor(() => {
      expect(screen.getByText("Updates")).toBeInTheDocument();
      expect(screen.getByRole("switch", { name: "Updater enabled" })).toBeInTheDocument();
    });
  });

  test("updater switch is disabled when UI is locked", async () => {
    render(SettingsView);

    await waitFor(() => {
      const updaterSwitch = screen.getByRole("switch", { name: "Updater enabled" });
      expect(updaterSwitch).toBeDisabled();
    });
  });

  test("renders Check now and Install buttons", async () => {
    render(SettingsView);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Check now" })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Install" })).toBeInTheDocument();
    });
  });

  test("Check now button is disabled when updater is locked", async () => {
    render(SettingsView);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Check now" })).toBeDisabled();
    });
  });

  test("Install button is disabled when no pending update", async () => {
    render(SettingsView);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Install" })).toBeDisabled();
    });
  });

  test("auto-connect toggle fires settings update on click", async () => {
    render(SettingsView);

    await waitFor(() => {
      expect(screen.getByRole("switch", { name: "Auto-connect on launch" })).toBeInTheDocument();
    });

    await fireEvent.click(screen.getByRole("switch", { name: "Auto-connect on launch" }));

    await waitFor(() => {
      expect(getSettings().general.autoConnectOnLaunch).toBe(true);
    });
  });

  test("start at login toggle fires settings update on click", async () => {
    render(SettingsView);

    await waitFor(() => {
      expect(screen.getByRole("switch", { name: "Start at login" })).toBeInTheDocument();
    });

    await fireEvent.click(screen.getByRole("switch", { name: "Start at login" }));

    await waitFor(() => {
      expect(getSettings().general.startAtLogin).toBe(true);
    });
  });

  test("log level select shows current level", async () => {
    render(SettingsView);

    await waitFor(() => {
      expect(screen.getByText("Log Level")).toBeInTheDocument();
      // The Select trigger renders the current value as text
      expect(screen.getByText("info")).toBeInTheDocument();
    });
  });

  test("displays updater status text", async () => {
    render(SettingsView);

    await waitFor(() => {
      expect(screen.getByText("Updater status")).toBeInTheDocument();
    });
  });
});
