import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "../../testing-library";

const getJsonMock = vi.hoisted(() => vi.fn());
const postJsonMock = vi.hoisted(() => vi.fn());

vi.mock("$lib/api", async () => {
  const actual = await vi.importActual<typeof import("$lib/api")>("$lib/api");
  return {
    ...actual,
    getJson: (...args: unknown[]) => getJsonMock(...args),
    postJson: (...args: unknown[]) => postJsonMock(...args),
  };
});

import LoginModal from "../../../../../../../apps/svelte-admin/src/lib/components/LoginModal.svelte";
import {
  setAuthRequired,
  setAuthError,
  getAuthRequired,
  getAuthError,
} from "../../../../../../../apps/svelte-admin/src/lib/stores/app.svelte";

describe("LoginModal", () => {
  let clearErrorMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    getJsonMock.mockReset();
    postJsonMock.mockReset();
    clearErrorMock = vi.fn();
    setAuthRequired(false);
    setAuthError(null);
    // shouldAdvanceTime: real clock still ticks so waitFor/findBy* don't hang;
    // vi.advanceTimersByTimeAsync() still works for explicit animation control.
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test("renders login dialog when open is true", async () => {
    render(LoginModal, {
      props: { open: true, error: null, onClearError: clearErrorMock },
    });
    await vi.advanceTimersByTimeAsync(90);

    expect(screen.getByText("Admin Login")).toBeInTheDocument();
  });

  test("shows username and password fields", async () => {
    render(LoginModal, {
      props: { open: true, error: null, onClearError: clearErrorMock },
    });
    await vi.advanceTimersByTimeAsync(90);

    expect(screen.getByLabelText("Username")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
  });

  test("shows Login submit button", async () => {
    render(LoginModal, {
      props: { open: true, error: null, onClearError: clearErrorMock },
    });
    await vi.advanceTimersByTimeAsync(90);

    expect(screen.getByRole("button", { name: "Login" })).toBeInTheDocument();
  });

  test("username field defaults to admin", async () => {
    render(LoginModal, {
      props: { open: true, error: null, onClearError: clearErrorMock },
    });
    await vi.advanceTimersByTimeAsync(90);

    const usernameInput = screen.getByLabelText("Username") as HTMLInputElement;
    expect(usernameInput.value).toBe("admin");
  });

  test("Login button is disabled when password is empty", async () => {
    render(LoginModal, {
      props: { open: true, error: null, onClearError: clearErrorMock },
    });
    await vi.advanceTimersByTimeAsync(90);

    expect(screen.getByRole("button", { name: "Login" })).toBeDisabled();
  });

  test("Login button enables when password is entered", async () => {
    render(LoginModal, {
      props: { open: true, error: null, onClearError: clearErrorMock },
    });
    await vi.advanceTimersByTimeAsync(90);

    const passwordInput = screen.getByLabelText("Password");
    await fireEvent.input(passwordInput, { target: { value: "secret123" } });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Login" })).not.toBeDisabled();
    });
  });

  test("submitting calls postJson with credentials", async () => {
    postJsonMock.mockResolvedValue({
      success: true,
      data: { user: "admin", requires_password_change: false },
    });

    render(LoginModal, {
      props: { open: true, error: null, onClearError: clearErrorMock },
    });
    await vi.advanceTimersByTimeAsync(90);

    const passwordInput = screen.getByLabelText("Password");
    await fireEvent.input(passwordInput, { target: { value: "mypassword" } });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Login" })).not.toBeDisabled();
    });

    await fireEvent.click(screen.getByRole("button", { name: "Login" }));
    await vi.advanceTimersByTimeAsync(100);

    await waitFor(() => {
      expect(postJsonMock).toHaveBeenCalledWith("/api/login", {
        username: "admin",
        password: "mypassword",
      });
    });
  });

  test("successful login sets authRequired to false", async () => {
    setAuthRequired(true);
    postJsonMock.mockResolvedValue({
      success: true,
      data: { user: "admin", requires_password_change: false },
    });

    render(LoginModal, {
      props: { open: true, error: null, onClearError: clearErrorMock },
    });
    await vi.advanceTimersByTimeAsync(90);

    const passwordInput = screen.getByLabelText("Password");
    await fireEvent.input(passwordInput, { target: { value: "correct" } });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Login" })).not.toBeDisabled();
    });

    await fireEvent.click(screen.getByRole("button", { name: "Login" }));
    await vi.advanceTimersByTimeAsync(100);

    await waitFor(() => {
      expect(getAuthRequired()).toBe(false);
    });
  });

  test("shows description text for admin access", async () => {
    render(LoginModal, {
      props: { open: true, error: null, onClearError: clearErrorMock },
    });
    await vi.advanceTimersByTimeAsync(90);

    expect(screen.getByText(/Enter admin credentials/)).toBeInTheDocument();
  });

  test("Login button is disabled when username is empty", async () => {
    render(LoginModal, {
      props: { open: true, error: null, onClearError: clearErrorMock },
    });
    await vi.advanceTimersByTimeAsync(90);

    // Clear the username field
    const usernameInput = screen.getByLabelText("Username");
    await fireEvent.input(usernameInput, { target: { value: "" } });

    const passwordInput = screen.getByLabelText("Password");
    await fireEvent.input(passwordInput, { target: { value: "somepass" } });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Login" })).toBeDisabled();
    });
  });

  test("does not render dialog content when open is false", async () => {
    render(LoginModal, {
      props: { open: false, error: null, onClearError: clearErrorMock },
    });
    await vi.advanceTimersByTimeAsync(90);

    expect(screen.queryByText("Admin Login")).not.toBeInTheDocument();
  });

  test("calls onClearError when password field receives input", async () => {
    render(LoginModal, {
      props: { open: true, error: "Bad password", onClearError: clearErrorMock },
    });
    await vi.advanceTimersByTimeAsync(90);

    const passwordInput = screen.getByLabelText("Password");
    await fireEvent.input(passwordInput, { target: { value: "new" } });

    expect(clearErrorMock).toHaveBeenCalled();
  });
});
