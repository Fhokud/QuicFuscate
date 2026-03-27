import { beforeEach, describe, expect, test, vi } from "vitest";
import { fireEvent, render, screen } from "../../../testing-library";

import TextInput from "../../../../../../../../apps/svelte-admin/src/lib/components/ui/TextInput.svelte";

describe("TextInput", () => {
  let onchange: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    onchange = vi.fn();
  });

  test("renders an input element", () => {
    render(TextInput, { props: { onchange } });
    const input = screen.getByRole("textbox");
    expect(input).toBeInTheDocument();
  });

  test("renders with the given value", () => {
    render(TextInput, { props: { value: "hello", onchange } });
    expect(screen.getByRole("textbox")).toHaveValue("hello");
  });

  test("renders a label when provided", () => {
    render(TextInput, { props: { label: "Username", onchange } });
    expect(screen.getByText("Username")).toBeInTheDocument();
    expect(screen.getByLabelText("Username")).toBeInTheDocument();
  });

  test("does not render label element when label not provided", () => {
    const { container } = render(TextInput, { props: { onchange } });
    expect(container.querySelector("label")).toBeNull();
  });

  test("calls onchange when input value changes", async () => {
    render(TextInput, { props: { label: "Name", onchange } });
    const input = screen.getByLabelText("Name");
    await fireEvent.input(input, { target: { value: "world" } });
    expect(onchange).toHaveBeenCalledWith("world");
  });

  test("generates input id from label", () => {
    render(TextInput, { props: { label: "My Field", onchange } });
    const input = screen.getByLabelText("My Field");
    expect(input.id).toBe("input-my-field");
  });

  test("uses explicit id when provided", () => {
    render(TextInput, { props: { id: "custom-id", label: "Test", onchange } });
    const input = screen.getByLabelText("Test");
    expect(input.id).toBe("custom-id");
  });

  test("is disabled when disabled prop is true", () => {
    render(TextInput, { props: { label: "Disabled", disabled: true, onchange } });
    expect(screen.getByLabelText("Disabled")).toBeDisabled();
  });

  test("is not disabled by default", () => {
    render(TextInput, { props: { label: "Active", onchange } });
    expect(screen.getByLabelText("Active")).not.toBeDisabled();
  });

  test("renders with password type", () => {
    render(TextInput, { props: { label: "Password", type: "password", onchange } });
    const input = screen.getByLabelText("Password");
    expect(input.getAttribute("type")).toBe("password");
  });

  test("applies maxLength attribute", () => {
    render(TextInput, { props: { label: "Code", maxLength: 6, onchange } });
    const input = screen.getByLabelText("Code");
    expect(input.getAttribute("maxlength")).toBe("6");
  });
});
