import { describe, expect, test } from "vitest";
import { isValidSniHost, normalizeRemoteForStorage, parseRemote } from "@/lib/tunnel-validators";

describe("tunnel-validators", () => {
  describe("parseRemote", () => {
    test("parses host:port", () => {
      expect(parseRemote("vpn.example.com:4433")).toEqual({ server: "vpn.example.com", port: 4433 });
    });

    test("parses host without port using default 4433", () => {
      expect(parseRemote("vpn.example.com")).toEqual({ server: "vpn.example.com", port: 4433 });
    });

    test("parses bracketed IPv6 with port", () => {
      expect(parseRemote("[2001:db8::1]:8443")).toEqual({ server: "2001:db8::1", port: 8443 });
    });

    test("rejects unbracketed IPv6", () => {
      expect(parseRemote("2001:db8::1:8443")).toBeNull();
    });

    test("rejects URL-like input", () => {
      expect(parseRemote("https://vpn.example.com:4433")).toBeNull();
    });

    test("rejects out-of-range port", () => {
      expect(parseRemote("vpn.example.com:70000")).toBeNull();
    });
  });

  describe("normalizeRemoteForStorage", () => {
    test("keeps dns endpoint format", () => {
      expect(normalizeRemoteForStorage("vpn.example.com:4433")).toBe("vpn.example.com:4433");
    });

    test("normalizes bracketed IPv6 endpoint", () => {
      expect(normalizeRemoteForStorage("[2001:db8::1]:4433")).toBe("[2001:db8::1]:4433");
    });

    test("normalizes host without port to default", () => {
      expect(normalizeRemoteForStorage("vpn.example.com")).toBe("vpn.example.com:4433");
    });

    test("returns null for invalid input", () => {
      expect(normalizeRemoteForStorage("https://vpn.example.com:4433")).toBeNull();
    });
  });

  describe("isValidSniHost", () => {
    test("accepts a normal host", () => {
      expect(isValidSniHost("cdn.example.com")).toBe(true);
    });

    test("rejects host with port", () => {
      expect(isValidSniHost("cdn.example.com:443")).toBe(false);
    });

    test("rejects whitespace", () => {
      expect(isValidSniHost("cdn example.com")).toBe(false);
    });

    test("rejects URL-like content", () => {
      expect(isValidSniHost("https://cdn.example.com")).toBe(false);
    });
  });
});
