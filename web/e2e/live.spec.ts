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


test('collection health reports the sensor counters, not blanks', async ({ page }) => {
  // Regression: the periodic `stats` frame published the counters flat while the frame sent on connect
  // nested them under `monitor`. After the first tick the screen showed "events seen 0 / forwarded 0"
  // beside a running capture — a broken contract that looked like an idle sensor.
  const headers = { Authorization: `Bearer ${token}` };
  const listed = await (await page.request.get(`${baseUrl}/api/sessions`, { headers })).json().catch(() => null);
  const running = (Array.isArray(listed) ? listed : []).find((session) => session.status === 'running');
  test.skip(!running, 'no running session: the launch test did not produce one');

  await page.goto(url('/live'));
  const health = page.getByText('events seen').locator('..');
  await expect(health).toBeVisible({ timeout: 15_000 });

  // Wait for at least one stats frame, then require a real number.
  await expect(async () => {
    const seen = await health.locator('dd').innerText();
    expect(seen).toMatch(/^[\d,]+$/);
    expect(Number(seen.replace(/,/g, ''))).toBeGreaterThan(0);
  }).toPass({ timeout: 20_000 });
});

test('a path that does not exist is refused before anything launches', async ({ page }) => {
  await page.goto(url('/'));
  await page.getByRole('button', { name: 'Monitor an application' }).first().click();
  await page.getByLabel('executable path').fill('C:\\nope\\nothing.exe');
  await page.getByRole('button', { name: 'Check this file' }).click();

  await expect(page.getByText(/no such file on the agent's machine/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Start monitoring' })).toBeDisabled();
});

test('the exported report is fetched with the bearer token and is self-contained', async ({ page }) => {
  // The download path cannot be a link: `/api/...` rejects an unauthenticated request, and a token in
  // a URL is exactly what the stream tickets exist to avoid. So assert both halves — the browser gets
  // a file, and the report itself carries no external asset that would 404 once the file is moved.
  const headers = { Authorization: `Bearer ${token}` };
  const listed = await (await page.request.get(`${baseUrl}/api/sessions`, { headers })).json().catch(() => null);
  const session = (Array.isArray(listed) ? listed : [])[0];
  test.skip(!session, 'no session on this agent to export');

  await page.goto(url('/threats'));
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'HTML' }).click();
  const saved = await download;
  expect(saved.suggestedFilename()).toMatch(/^argus-report-.*\.html$/);

  const file = await saved.path();
  const html = await (await import('node:fs/promises')).readFile(file!, 'utf8');
  expect(html).toContain('Argus behaviour report');
  expect(html).toContain('What this tool can and cannot see');
  expect(html).toContain('config');
  // No external asset may be referenced: a report that needs the agent or the internet to render is
  // not an export.
  expect(html).not.toMatch(/<(script|img|link)\b/i);
  expect(html).not.toMatch(/https?:\/\/(?!127\.0\.0\.1)/);
});

test('settings shows the port the agent actually bound and its configuration digest', async ({ page }) => {
  await page.goto(url('/settings'));
  await expect(page.getByRole('heading', { name: 'This agent' })).toBeVisible();

  // Read from the agent, not invented: the same values `/api/settings` answers.
  const settings = await (await page.request.get(`${baseUrl}/api/settings`, {
    headers: { Authorization: `Bearer ${token}` },
  })).json();
  await expect(page.getByText(`127.0.0.1:${settings.port}`)).toBeVisible();
  await expect(page.getByText(settings.configHash)).toBeVisible();
  await expect(page.getByText(settings.agent, { exact: true }).first()).toBeVisible();
});
