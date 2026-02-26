import { describe, expect, test } from "vitest";
import { displayCcMode, displayFecMode, displayMtu, displayStealthMode } from "@/lib/policy-display";

describe("policy-display", () => {
  test("normalizes stealth modes to supported UI set", () => {
    expect(displayStealthMode("auto")).toBe("Auto");
    expect(displayStealthMode("intelligent")).toBe("Auto");
    expect(displayStealthMode("performance")).toBe("Performance");
    expect(displayStealthMode("base")).toBe("Performance");
    expect(displayStealthMode("stealth")).toBe("Stealth");
    expect(displayStealthMode("anti-dpi")).toBe("AntiDPI");
    expect(displayStealthMode("max")).toBe("AntiDPI");
    expect(displayStealthMode("manual")).toBe("Manual");
    expect(displayStealthMode("off")).toBe("Off");
    expect(displayStealthMode("unknown-mode")).toBe("Auto");
  });

  test("normalizes fec modes to on/off only", () => {
    expect(displayFecMode("off")).toBe("Off");
    expect(displayFecMode("zero")).toBe("Off");
    expect(displayFecMode("on")).toBe("On");
    expect(displayFecMode("manual")).toBe("On");
    expect(displayFecMode("auto")).toBe("On");
    expect(displayFecMode("")).toBe("On");
  });

  test("normalizes cc modes to known algorithms", () => {
    expect(displayCcMode("reno")).toBe("RENO");
    expect(displayCcMode("cubic")).toBe("CUBIC");
    expect(displayCcMode("bbr")).toBe("BBR");
    expect(displayCcMode("bbr2")).toBe("BBR2");
    expect(displayCcMode("bbr2_gcongestion")).toBe("BBR2 GC");
    expect(displayCcMode("server")).toBe("Server");
    expect(displayCcMode("unknown")).toBe("Custom");
  });

  test("normalizes mtu display", () => {
    expect(displayMtu("1400")).toBe("1400");
    expect(displayMtu("server")).toBe("Server");
    expect(displayMtu("")).toBe("Server");
    expect(displayMtu("not-a-number")).toBe("Server");
  });
});
