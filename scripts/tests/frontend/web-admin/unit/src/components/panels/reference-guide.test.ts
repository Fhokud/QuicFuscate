import { describe, expect, test } from "vitest";
import { render, screen } from "../../../testing-library";

import ReferenceGuide from "../../../../../../../../apps/svelte-admin/src/lib/components/panels/ReferenceGuide.svelte";

describe("ReferenceGuide", () => {
  test("renders the Reference Guide heading", () => {
    render(ReferenceGuide);
    expect(screen.getByText("Reference Guide")).toBeInTheDocument();
  });

  test("renders the Stealth section heading", () => {
    render(ReferenceGuide);
    // "Stealth" appears as both section heading and as a stealth mode label
    expect(screen.getAllByText("Stealth").length).toBeGreaterThanOrEqual(1);
  });

  test("renders the Congestion Control section heading", () => {
    render(ReferenceGuide);
    expect(screen.getByText("Congestion Control")).toBeInTheDocument();
  });

  test("renders the FEC section heading", () => {
    render(ReferenceGuide);
    expect(screen.getByText("FEC")).toBeInTheDocument();
  });

  test("renders all stealth mode labels", () => {
    render(ReferenceGuide);
    // "Auto" and "Off" appear in both Stealth and FEC sections
    expect(screen.getAllByText("Auto").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText("Performance")).toBeInTheDocument();
    // "Stealth" already checked as section heading
    expect(screen.getByText("AntiDPI")).toBeInTheDocument();
    expect(screen.getByText("Manual")).toBeInTheDocument();
  });

  test("renders stealth mode descriptions", () => {
    render(ReferenceGuide);
    expect(screen.getByText("Intelligent adaptive behavior.")).toBeInTheDocument();
    expect(screen.getByText("Maximum anti-censorship & detection resistance.")).toBeInTheDocument();
    expect(screen.getByText("Feature flags controlled explicitly.")).toBeInTheDocument();
  });

  test("renders congestion control algorithm labels", () => {
    render(ReferenceGuide);
    expect(screen.getByText("Reno")).toBeInTheDocument();
    expect(screen.getByText("BBR2")).toBeInTheDocument();
    expect(screen.getByText("BBR3")).toBeInTheDocument();
  });

  test("renders congestion control descriptions", () => {
    render(ReferenceGuide);
    expect(screen.getByText(/conservative AIMD baseline/i)).toBeInTheDocument();
    expect(screen.getByText(/loss-aware model-based CC/i)).toBeInTheDocument();
  });

  test("renders FEC mode descriptions", () => {
    render(ReferenceGuide);
    expect(screen.getByText("Adaptive FEC tunes redundancy.")).toBeInTheDocument();
    expect(screen.getByText("FEC fully deactivated.")).toBeInTheDocument();
  });
});
