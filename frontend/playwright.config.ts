// Copyright (c) 2026 Adekunle Akeju. All rights reserved except as licensed.
// Akeju Secure SaaS Starter, created by Adekunle Akeju. SPDX-License-Identifier: AGPL-3.0-or-later
import { defineConfig } from "@playwright/test";

const python = process.env.PYTHON ?? "python";

export default defineConfig({
  testDir: "./tests",
  workers: 1,
  timeout: 60_000,
  use: { baseURL: "http://localhost:3000", channel: process.env.CI ? undefined : "msedge" },
  webServer: [
    {
      command: `${python} -m uvicorn app.asgi:app --port 8000`,
      cwd: "../backend",
      url: "http://127.0.0.1:8000/health",
      reuseExistingServer: false,
      env: { APP_SECRET: "e2e-only-secret-e2e-only-secret-e2e", DATABASE_URL: "sqlite:///:memory:", COOKIE_SECURE: "false" },
    },
    { command: "npm run start", url: "http://localhost:3000", reuseExistingServer: false },
  ],
});
