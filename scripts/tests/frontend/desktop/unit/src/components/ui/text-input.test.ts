import { beforeEach, describe, expect, test, vi } from "vitest";
import { fireEvent, render, screen } from "../../../testing-library";

import TextInput from "../../../../../../../../apps/svelte-desktop/src/lib/components/ui/TextInput.svelte";

describe("ui/TextInput", () => {
  let inputFn: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    inputFn = vi.fn();
  });

  test("renders an input element with the given value", () => {
    render(TextInput, { value: "hello", oninput: inputFn });
    const input = screen.getByDisplayValue("hello") as HTMLInputElement;
    expect(input).toBeInTheDocument();
    expect(input.tagName).toBe("INPUT");
  });

  test("renders with placeholder text", () => {
    render(TextInput, { value: "", oninput: inputFn, placeholder: "Enter name" });
    expect(screen.getByPlaceholderText("Enter name")).toBeInTheDocument();
  });

  test("fires oninput callback on input event", async () => {
    render(TextInput, { value: "", oninput: inputFn });
    const input = screen.getByRole("textbox") as HTMLInputElement;
    await fireEvent.input(input, { target: { value: "new value" } });
    expect(inputFn).toHaveBeenCalledWith("new value");
  });

  test("respects maxlength by slicing the value", async () => {
    render(TextInput, { value: "", oninput: inputFn, maxlength: 5 });
    const input = screen.getByRole("textbox") as HTMLInputElement;
    await fireEvent.input(input, { target: { value: "abcdefghij" } });
    expect(inputFn).toHaveBeenCalledWith("abcde");
  });

  test("sets the id attribute when provided", () => {
    render(TextInput, { value: "", oninput: inputFn, id: "my-input" });
    const input = document.getElementById("my-input");
    expect(input).not.toBeNull();
    expect(input?.tagName).toBe("INPUT");
  });

  test("input type is text", () => {
    render(TextInput, { value: "", oninput: inputFn });
    const input = screen.getByRole("textbox") as HTMLInputElement;
    expect(input.type).toBe("text");
  });

  test("sets maxlength attribute on the input element", () => {
    render(TextInput, { value: "", oninput: inputFn, maxlength: 10 });
    const input = screen.getByRole("textbox") as HTMLInputElement;
    expect(input.maxLength).toBe(10);
  });
});
