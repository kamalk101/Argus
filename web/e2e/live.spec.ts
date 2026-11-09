import { expect, test } from '@playwright/test';

/**
 * Live mode: the dashboard in front of a running agent.
 *
 *   # terminal 1 (elevated)
 *   dotnet run --project src/Argus.Agent -- --port 5195 --ready-file %TEMP%\ready.json
 *   # terminal 2
 *   ARGUS_LIVE_URL=http://127.0.0.1:5195 ARGUS_LIVE_TOKEN=<token from ready.json> npm test -- e2e/live.spec.ts
 *
 * Skipped without ARGUS_LIVE_TOKEN: the fixture suite is the gate that runs everywhere, this is the
 * extra check that the real wire — bearer fetches, the SSE ticket, the launch flow — works.
 */
const token = process.env.ARGUS_LIVE_TOKEN;
const baseUrl = process.env.ARGUS_LIVE_URL ?? 'http://127.0.0.1:5195';

test.skip(!token, 'needs a live agent: set ARGUS_LIVE_TOKEN (and ARGUS_LIVE_URL)');

// Serial: the stream check is only meaningful once the launch check has produced a session.
test.describe.configure({ mode: 'serial' });

function url(path: string): string {
  return `${baseUrl}${path}${path.includes('?') ? '&' : '?'}token=${token}`;
}

test('the agent serves the dashboard and the session list', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));

  await page.goto(url('/'));
  await expect(page.getByRole('navigation', { name: 'sections' })).toBeVisible();
  // Either an existing session or the empty state is a correct answer; a blank screen is not.
  await expect(page.getByText(/No sessions yet|Sessions/).first()).toBeVisible();
  expect(errors).toEqual([]);
});

test('a client-side route survives a reload (SPA fallback)', async ({ page }) => {
  await page.goto(url('/timeline'));
  await page.reload();
  // The heading only renders once a session exists; the empty state is equally proof that the shell
  // was served for /timeline instead of the static-file 404.
  await expect(page.getByText(/Timeline|No session — the timeline fills/).first()).toBeVisible();
  await expect(page.getByRole('link', { name: 'Timeline' })).toHaveAttribute('aria-current', 'page');
});

test('launching a target goes through the preview, and the session then exists', async ({ page }) => {
  // One session at a time is the agent's rule; a re-run of this suite must not inherit the last one.
  const headers = { Authorization: `Bearer ${token}` };
  const existing = await page.request.get(`${baseUrl}/api/sessions`, { headers });
  // A fresh agent answers 204/bare-null rather than `[]`, so `for ... of await json()` threw
  // "not iterable" instead of running the check. Normalise before iterating.
  const listed = await existing.json().catch(() => null);
  for (const session of Array.isArray(listed) ? listed : []) {
    if (session.status === 'running') {
      await page.request.post(`${baseUrl}/api/sessions/${session.id}/stop`, { headers });
    }
  }

  await page.goto(url('/'));
  await page.getByRole('button', { name: 'Monitor an application' }).first().click();

  const dialog = page.getByRole('dialog', { name: 'Monitor an application' });
  await expect(dialog).toBeVisible();

  await page.getByLabel('executable path').fill('C:\\Windows\\System32\\notepad.exe');
  await page.getByRole('button', { name: 'Check this file' }).click();

  // The preview is the whole point: the operator sees what will run before it runs.
  await expect(dialog.getByText('notepad.exe', { exact: true })).toBeVisible();
  await expect(dialog.getByText(/^[a-f0-9]{64}$/)).toBeVisible();
  await expect(dialog.getByText('valid', { exact: true })).toBeVisible();

  await page.getByRole('button', { name: 'Start monitoring' }).click();
  await expect(page).toHaveURL(/\/live/);
  await expect(page.getByText(/notepad\.exe/).first()).toBeVisible({ timeout: 20_000 });
});

test('the live screen opens the ticket-authenticated stream', async ({ page }) => {
  let opened = false;
  page.on('request', (request) => {
    if (request.url().includes('/stream?ticket=')) opened = true;
  });

  await page.goto(url('/live'));
  // A session may not exist yet; the stream only opens once one does.
  const empty = page.getByText(/No session to watch/i);
  if (await empty.isVisible({ timeout: 2000 }).catch(() => false)) {
    test.skip(true, 'no active session on this agent');
  }
  await expect(page.getByText('live', { exact: true })).toBeVisible({ timeout: 15_000 });
  expect(opened, 'the live screen opened the ticket-authenticated stream').toBe(true);
});


test('a path that does not exist is refused before anything launches', async ({ page }) => {
  await page.goto(url('/'));
  await page.getByRole('button', { name: 'Monitor an application' }).first().click();
  await page.getByLabel('executable path').fill('C:\\nope\\nothing.exe');
  await page.getByRole('button', { name: 'Check this file' }).click();

  await expect(page.getByText(/no such file on the agent's machine/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Start monitoring' })).toBeDisabled();
});
