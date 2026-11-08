// Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
// Akeju Secure SaaS Starter, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
import { createHmac } from "node:crypto";
import { expect, test } from "@playwright/test";

function totp(secret: string, offsetSteps = 0) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secret) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + offsetSteps));
  const hash = createHmac("sha1", key).update(counter).digest();
  const at = hash[19] & 15;
  return String((hash.readUInt32BE(at) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

test("signup, data, MFA, sign out and two-step sign-in", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Create a company account" }).click();
  await page.getByLabel("Company name").fill("Acme");
  await page.getByLabel("Email").fill("owner@example.com");
  await page.getByLabel(/Password/).fill("correct-horse-battery");
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByText("Signed in as")).toBeVisible();

  await page.getByLabel("Project name").fill("<b>Launch</b>");
  await page.getByRole("button", { name: "Add project" }).click();
  await expect(page.getByText("<b>Launch</b>")).toBeVisible();
  await expect(page.getByTestId("audit")).toContainText("project.created");

  await page.getByRole("button", { name: "Set up two-step sign-in" }).click();
  const secret = (await page.getByTestId("mfa-secret").textContent())!;
  await page.getByLabel("Code from your app").fill(totp(secret, -1));
  await page.getByRole("button", { name: "Turn on two-step sign-in" }).click();
  await expect(page.getByText("Two-step sign-in is on.")).toBeVisible();

  await page.getByRole("button", { name: "Sign out" }).click();
  await page.getByLabel("Email").fill("owner@example.com");
  await page.getByLabel("Password").fill("wrong-password-123");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.locator("p.error")).toContainText("incorrect");

  await page.getByLabel("Password").fill("correct-horse-battery");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByLabel("Code from your authenticator app").fill(totp(secret));
  await page.getByRole("button", { name: "Verify code" }).click();
  await expect(page.getByText("Signed in as")).toBeVisible();
  await expect(page.getByText("<b>Launch</b>")).toBeVisible();
});

test("production pages send security headers", async ({ request }) => {
  const r = await request.get("/");
  expect(r.headers()["content-security-policy"]).toContain("frame-ancestors 'none'");
  expect(r.headers()["x-powered-by"]).toBeUndefined();
});
