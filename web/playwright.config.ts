import { defineConfig, devices } from '@playwright/test';

/**
 * The dashboard is tested against the fixture payloads captured from a real agent session
 * (`scripts/dashboard-fixtures.ps1`), served as static files by `vite preview`. No agent and no
 * elevation are needed, so the whole suite runs anywhere — but the shapes are the agent's own.
 */
export default defineConfig({
  testDir: './e2e',
  // The screenshot spec writes images for review; it asserts nothing and is run by `npm run shots`.
  testIgnore: ['**/shots.spec.ts'],
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: [['list']],
  use: {
    baseURL: 'http://localhost:4173',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'desktop-1280',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1280, height: 900 } },
    },
  ],
  webServer: {
    command: 'npm run preview -- --port 4173 --strictPort',
    url: 'http://localhost:4173',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
