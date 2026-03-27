import { beforeEach, describe, expect, test, vi } from "vitest";
import { fireEvent, render, screen } from "../../../testing-library";

import ConnectButton from "../../../../../../../../apps/svelte-desktop/src/lib/components/ui/ConnectButton.svelte";

describe("ui/ConnectButton", () => {
  let clickFn: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    clickFn = vi.fn();
  });

  test("renders 'Connect' text in idle state", () => {
    render(ConnectButton, { state: "idle", onclick: clickFn });
    expect(screen.getByText("Connect")).toBeInTheDocument();
  });

  test("renders 'Disconnect' text in connected state", () => {
    render(ConnectButton, { state: "connected", onclick: clickFn });
    expect(screen.getByText("Disconnect")).toBeInTheDocument();
  });

  test("renders 'Connecting' text in connecting state", () => {
    render(ConnectButton, { state: "connecting", onclick: clickFn });
    expect(screen.getByText("Connecting")).toBeInTheDocument();
  });

  test("renders 'Stopping' text in disconnecting state", () => {
    render(ConnectButton, { state: "disconnecting", onclick: clickFn });
    expect(screen.getByText("Stopping")).toBeInTheDocument();
  });

  test("click triggers callback in idle state", async () => {
    render(ConnectButton, { state: "idle", onclick: clickFn });
    await fireEvent.click(screen.getByRole("button"));
    expect(clickFn).toHaveBeenCalledOnce();
  });

  test("click triggers callback in connected state", async () => {
    render(ConnectButton, { state: "connected", onclick: clickFn });
    await fireEvent.click(screen.getByRole("button"));
    expect(clickFn).toHaveBeenCalledOnce();
  });

  test("button is disabled during connecting state", () => {
    render(ConnectButton, { state: "connecting", onclick: clickFn });
    expect(screen.getByRole("button")).toBeDisabled();
  });

  test("button is disabled during disconnecting state", () => {
    render(ConnectButton, { state: "disconnecting", onclick: clickFn });
    expect(screen.getByRole("button")).toBeDisabled();
  });

  test("button is disabled when disabled prop is true", () => {
    render(ConnectButton, { state: "idle", onclick: clickFn, disabled: true });
    expect(screen.getByRole("button")).toBeDisabled();
  });

  test("click does not fire callback when disabled", async () => {
    render(ConnectButton, { state: "idle", onclick: clickFn, disabled: true });
    await fireEvent.click(screen.getByRole("button"));
    expect(clickFn).not.toHaveBeenCalled();
  });

  test("aria-label reflects connected state", () => {
    render(ConnectButton, { state: "connected", onclick: clickFn });
    expect(screen.getByRole("button")).toHaveAttribute("aria-label", "Disconnect");
  });

  test("aria-label reflects idle state with hasQKey", () => {
    render(ConnectButton, { state: "idle", onclick: clickFn, hasQKey: true });
    expect(screen.getByRole("button")).toHaveAttribute("aria-label", "Connect");
  });

  test("aria-label reflects idle state without hasQKey", () => {
    render(ConnectButton, { state: "idle", onclick: clickFn, hasQKey: false });
    expect(screen.getByRole("button")).toHaveAttribute("aria-label", "Set QKey");
  });

  test("renders hint text when provided", () => {
    render(ConnectButton, { state: "idle", onclick: clickFn, hint: "Select a tunnel first" });
    expect(screen.getByText("Select a tunnel first")).toBeInTheDocument();
  });
});
