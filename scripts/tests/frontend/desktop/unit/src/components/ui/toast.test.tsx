import { describe, expect, test } from "vitest";
import { render, screen } from "@testing-library/react";
import { Provider, createStore } from "jotai";
import { ToastContainer } from "@/components/ui/toast";
import { addToastAtom } from "@/stores/toastAtom";

describe("ToastContainer", () => {
  test("renders toast when added via atom", async () => {
    const store = createStore();
    store.set(addToastAtom, { type: "success", message: "Hello", duration: 10_000 });

    render(
      <Provider store={store}>
        <ToastContainer />
      </Provider>,
    );

    expect(screen.getByTestId("toast-container")).toBeInTheDocument();
    expect(await screen.findByText("Hello")).toBeInTheDocument();
  });
});
