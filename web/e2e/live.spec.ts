import { expect, test } from '@playwright/test';

/**
 * Live mode against a running agent. Skipped unless ARGUS_LIVE_TOKEN is set, because it needs an
 * elevated agent on Windows — the fixture suite is the gate that runs everywhere, this is the extra
 * check that the real wire (bearer fetches, the SSE ticket, stream frames) works end to end.
 *
 *   ARGUS_LIVE_TOKEN=<token from the agent's ready file> npm test -- e2e/live.spec.ts
 */
const token = process.env.ARGUS_LIVE_TOKEN;

test.skip(!token, 'needs a live agent: set ARGUS_LIVE_TOKEN');

test('live agent: sessions load and the stream delivers a snapshot', async ({ page }) => {
  const streamFrames: string[] = [];
  page.on('request', (request) => {
    if (request.url().includes('/stream?ticket=')) streamFrames.push('stream-open');
  });

  await page.goto(`http://localhost:5173/?token=${token}`);
  // The header names the target the agent is actually monitoring.
  await expect(page.getByText(/notepad\.exe/).first()).toBeVisible();

  await page.goto(`http://localhost:5173/live?token=${token}`);
  await expect(page.getByText('live', { exact: true })).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText(/Risk over time/i).first()).toBeVisible();
  // The ticket is fetched, then used: a stream URL carrying a ticket must have been opened.
  expect(streamFrames, 'the live screen opened the ticket-authenticated stream').toContain('stream-open');
});

test('live agent: threats screen reads detections over the bearer token', async ({ page }) => {
  await page.goto(`http://localhost:5173/threats?token=${token}`);
  await expect(page.getByRole('heading', { name: /Detections/ })).toBeVisible();
  await expect(page.getByText(/No rule fired in this session|severity \d+/).first()).toBeVisible();
});
