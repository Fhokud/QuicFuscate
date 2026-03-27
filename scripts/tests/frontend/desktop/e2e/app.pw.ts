import { test, expect } from "@playwright/test";

async function waitForHydration(page: any) {
  await expect(page.locator('#qf-app-stage[data-hydrated="true"]')).toBeVisible();
}

function createButton(page: any) {
  return page.getByRole("button", { name: "Open tunnel composer", exact: true });
}

function importQkeyButton(page: any) {
  return page.getByRole("button", { name: "Open QKey vault", exact: true });
}

test("app shell renders", async ({ page }) => {
  await page.goto("/");
  await waitForHydration(page);
  const nav = page.getByRole("navigation", { name: "Primary" });

  await expect(page.getByAltText("QuicFuscate logo")).toBeVisible();
  await expect(nav.getByRole("button", { name: "Tunnels", exact: true })).toBeVisible();
  await expect(nav.getByRole("button", { name: "Configuration", exact: true })).toBeVisible();
  await expect(nav.getByRole("button", { name: "Logs", exact: true })).toBeVisible();
  await expect(nav.getByRole("button", { name: "About", exact: true })).toBeVisible();
});

test("navigation switches views", async ({ page }) => {
  await page.goto("/");
  await waitForHydration(page);
  const nav = page.getByRole("navigation", { name: "Primary" });

  await nav.getByRole("button", { name: "Configuration", exact: true }).click();
  await expect(page.getByRole("main").getByText("Configuration", { exact: true })).toBeVisible();

  await nav.getByRole("button", { name: "Logs", exact: true }).click();
  await expect(page.getByText("Live Output", { exact: true })).toBeVisible();

  await nav.getByRole("button", { name: "About", exact: true }).click({ force: true });
  await expect(page.getByText("Open-source obfuscated QUIC tunnel")).toBeVisible();

  await nav.getByRole("button", { name: "Tunnels", exact: true }).click();
  await expect(createButton(page)).toBeVisible();
});

test("create tunnel manually (browser mode)", async ({ page }) => {
  await page.goto("/");
  await waitForHydration(page);

  await createButton(page).click();
  await expect(page.getByRole("dialog", { name: "Create Tunnel" })).toBeVisible();

  const dialog = page.getByRole("dialog", { name: "Create Tunnel" });
  await dialog.getByLabel("Name of the Connection", { exact: true }).fill("Frankfurt DE");
  await dialog.getByLabel("Remote [IP-Address:Port]", { exact: true }).fill("[::1]");
  await dialog.getByRole("button", { name: "Create Tunnel", exact: true }).click();

  await expect(page.getByText("Frankfurt DE", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("[::1]:4433", { exact: true }).first()).toBeVisible();
});

test("import qkey requires desktop runtime in browser mode", async ({ page }) => {
  await page.goto("/");
  await waitForHydration(page);

  await importQkeyButton(page).click();
  await expect(page.getByLabel("QKey String", { exact: true })).toBeVisible();

  await page.getByRole("textbox", { name: "QKey String" }).fill("QKey-TESTONLY");
  const importBtn = page.getByRole("button", { name: "Import", exact: true });
  await expect(importBtn).toBeDisabled();
});
