import { describe, expect, test } from "vitest";
import { resolveDomainFrontingSniDisplay } from "@/lib/domain-fronting-policy";

describe("domain-fronting-policy", () => {
  test("shows Auto [Rotating] for rotating policy", () => {
    const extra = JSON.stringify({
      df_sni_mode: "auto_rotating",
      df_sni_pool: ["cdn.cloudflare.com", "cloudflare-dns.com"],
    });
    expect(resolveDomainFrontingSniDisplay(extra, "placeholder.example")).toBe("Auto [Rotating]");
  });

  test("shows fixed domain for fixed policy", () => {
    const extra = JSON.stringify({
      df_sni_mode: "fixed",
      df_sni_domain: "cloudfront.net",
    });
    expect(resolveDomainFrontingSniDisplay(extra, "placeholder.example")).toBe("cloudfront.net");
  });

  test("falls back to qkey sni for malformed or missing policy", () => {
    expect(resolveDomainFrontingSniDisplay("", "cdn.cloudflare.com")).toBe("cdn.cloudflare.com");
    expect(resolveDomainFrontingSniDisplay("{broken-json", "cloudflare-dns.com")).toBe("cloudflare-dns.com");
    expect(resolveDomainFrontingSniDisplay(JSON.stringify({ df_sni_mode: "unknown" }), "akamai.net")).toBe("akamai.net");
  });
});
