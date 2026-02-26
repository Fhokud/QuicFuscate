import { test, expect } from "@playwright/test";

test("app shell renders", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("QuicFuscate")).toBeVisible();
  const nav = page.getByRole("navigation", { name: "Primary" });

  await expect(nav.getByRole("button", { name: "Tunnels", exact: true })).toBeVisible();
  await expect(nav.getByRole("button", { name: "Configuration", exact: true })).toBeVisible();
  await expect(nav.getByRole("button", { name: "Logs", exact: true })).toBeVisible();
  await expect(nav.getByRole("button", { name: "About", exact: true })).toBeVisible();
});

test("navigation switches views", async ({ page }) => {
  await page.goto("/");
  const nav = page.getByRole("navigation", { name: "Primary" });

  await nav.getByRole("button", { name: "Configuration", exact: true }).click();
  await expect(page.getByRole("main").getByText("Configuration", { exact: true })).toBeVisible();

  await nav.getByRole("button", { name: "Logs", exact: true }).click();
  await expect(page.getByText("Live Output", { exact: true })).toBeVisible();

  await nav.getByRole("button", { name: "About", exact: true }).click();
  await expect(page.getByText("Open-source obfuscated QUIC tunnel")).toBeVisible();

  await nav.getByRole("button", { name: "Tunnels", exact: true }).click();
  await expect(page.getByRole("button", { name: "Create" }).first()).toBeVisible();
});

test("create tunnel manually (browser mode)", async ({ page }) => {
  await page.goto("/");

  await page.getByRole("button", { name: "Create" }).first().click();
  await expect(page.getByRole("dialog", { name: "Create Tunnel" })).toBeVisible();

  await page.getByLabel("Name of the Connection", { exact: true }).fill("Frankfurt DE");
  await page.getByLabel("Remote [IP-Address:Port]", { exact: true }).fill("203.0.113.11:4433");
  await page.getByRole("button", { name: "Create" }).click();

  await expect(page.getByText("Frankfurt DE", { exact: true }).first()).toBeVisible();
});

test("import qkey requires desktop runtime in browser mode", async ({ page }) => {
  await page.goto("/");

  await page.getByRole("button", { name: "Import QKey" }).click();
  await expect(page.getByLabel("QKey String", { exact: true })).toBeVisible();

  await page.getByRole("textbox", { name: "QKey String" }).fill("QKey-TESTONLY");
  const importBtn = page.getByRole("button", { name: "Import" });
  await expect(importBtn).toBeDisabled();
});
