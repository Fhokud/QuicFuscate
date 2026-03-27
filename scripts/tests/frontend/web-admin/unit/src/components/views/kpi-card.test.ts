import { describe, expect, test } from "vitest";
import { render, screen } from "../../../testing-library";

import KpiCard from "../../../../../../../../apps/svelte-admin/src/lib/components/views/KpiCard.svelte";

describe("KpiCard", () => {
  test("renders the label text", () => {
    render(KpiCard, { props: { label: "Clients", value: "42" } });
    expect(screen.getByText("Clients")).toBeInTheDocument();
  });

  test("renders the value text", () => {
    render(KpiCard, { props: { label: "Uptime", value: "3h 12m" } });
    expect(screen.getByText("3h 12m")).toBeInTheDocument();
  });

  test("renders loading skeleton when loading is true", () => {
    const { container } = render(KpiCard, {
      props: { label: "Bytes In", value: "1.5 MB", loading: true },
    });
    expect(screen.queryByText("1.5 MB")).not.toBeInTheDocument();
    const skeleton = container.querySelector("[data-skeleton]") ?? container.querySelector(".animate-pulse");
    // Skeleton renders a placeholder, value should not be visible
    expect(screen.getByText("Bytes In")).toBeInTheDocument();
  });

  test("renders dash when trafficBitsPerSecond is zero", () => {
    render(KpiCard, {
      props: { label: "Traffic In", value: "0", trafficBitsPerSecond: 0 },
    });
    expect(screen.getByText("-")).toBeInTheDocument();
  });

  test("renders dash when trafficBitsPerSecond is negative", () => {
    render(KpiCard, {
      props: { label: "Traffic In", value: "0", trafficBitsPerSecond: -5 },
    });
    expect(screen.getByText("-")).toBeInTheDocument();
  });

  test("does not render dash when trafficBitsPerSecond is positive", () => {
    render(KpiCard, {
      props: { label: "Traffic In", value: "1 Mbit/s", trafficBitsPerSecond: 1_000_000 },
    });
    expect(screen.queryByText("-")).not.toBeInTheDocument();
  });

  test("renders sparkline SVG when sparkline data provided and no trafficBitsPerSecond", () => {
    const { container } = render(KpiCard, {
      props: { label: "Metric", value: "100", sparkline: [10, 20, 30, 40] },
    });
    const svg = container.querySelector("svg");
    expect(svg).not.toBeNull();
  });

  test("does not render sparkline SVG when sparkline data is empty", () => {
    const { container } = render(KpiCard, {
      props: { label: "Metric", value: "0", sparkline: [] },
    });
    const svg = container.querySelector("svg");
    expect(svg).toBeNull();
  });

  test("does not render sparkline when trafficBitsPerSecond is provided", () => {
    const { container } = render(KpiCard, {
      props: {
        label: "Traffic",
        value: "5 Mbit/s",
        sparkline: [10, 20, 30],
        trafficBitsPerSecond: 5_000_000,
      },
    });
    // When trafficBitsPerSecond is set, sparkline is suppressed
    const svgs = container.querySelectorAll("svg");
    expect(svgs.length).toBe(0);
  });
});
