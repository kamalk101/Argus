import { expect, test } from '@playwright/test';

/**
 * Nine routes, each asserted on the things the phase's definition of done names: the route renders
 * its own content (not the previous screen's), and an event row carries its observability badge.
 *
 * Two fixture sets are used: `flagged` (cmd → powershell -enc, a Run-key write, a dropped copy of
 * cmd.exe — five detections, Malicious) and `benign` (notepad, zero detections, complete coverage).
 */
const ROUTES = [
  { path: '/', heading: 'Sessions' },
  { path: '/live', heading: 'Risk over time' },
  { path: '/processes', heading: 'Process tree' },
  { path: '/files', heading: 'File activity' },
  { path: '/network', heading: 'Network activity' },
  { path: '/threats', heading: 'Detections' },
  { path: '/timeline', heading: 'Timeline' },
  { path: '/search', heading: 'Search' },
  { path: '/settings', heading: 'This agent' },
] as const;

/** `/threats?fixtures=flagged` — the query carries the fixture set, the path stays a real route. */
function url(path: string, fixture: 'flagged' | 'benign' = 'flagged'): string {
  return `${path === '/' ? '/' : path}?fixtures=${fixture}`;
}

for (const route of ROUTES) {
  test(`${route.path} renders its own screen`, async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));

    await page.goto(url(route.path));

    await expect(page.getByRole('heading', { name: route.heading, exact: false }).first()).toBeVisible();
    await expect(page.getByRole('navigation', { name: 'sections' })).toBeVisible();
    expect(errors, `uncaught page errors on ${route.path}`).toEqual([]);
  });
}

test('every event row carries an observability badge', async ({ page }) => {
  await page.goto(url('/files'));
  const rows = page.getByRole('row');
  await expect(rows.first()).toBeVisible();

  const count = await rows.count();
  // The header row is row 0; check every rendered data row.
  const visible = Math.min(count, 40);
  expect(visible).toBeGreaterThan(3);
  for (let index = 1; index < visible; index += 1) {
    const text = await rows.nth(index).innerText();
    expect(text.toLowerCase(), `row ${index}: ${text}`).toMatch(/observed|inferred|partial|unobserved/);
  }
});

test('threats expand into the evidence chain the agent reported', async ({ page }) => {
  await page.goto(url('/threats'));
  const first = page.locator('button[aria-expanded]').first();
  await expect(first).toBeVisible();
  await first.click();

  await expect(page.getByText('Why', { exact: true })).toBeVisible();
  await expect(page.getByText('Counterfactual', { exact: true })).toBeVisible();
  await expect(page.getByText(/^(F-002|P-003|F-007|P-004)$/).first()).toBeVisible();
});

test('a benign session says so, and does not invent detections', async ({ page }) => {
  await page.goto(url('/threats', 'benign'));
  await expect(page.getByText(/No rule fired in this session/i)).toBeVisible();
});

test('a complete session says its coverage is complete', async ({ page }) => {
  await page.goto(url('/', 'benign'));
  await expect(page.getByText(/Collection complete/i)).toBeVisible();
});

test('Ctrl+K reaches search from another screen', async ({ page }) => {
  await page.goto(url('/timeline'));
  // The shortcut listener is attached after React mounts. Pressing before that is a test bug, not an
  // app bug — measured: 1 of 3 repeats failed until the shell was awaited.
  await expect(page.getByRole('navigation', { name: 'sections' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Timeline' })).toHaveAttribute('aria-current', 'page');

  await page.keyboard.press('Control+k');
  const search = page.getByRole('textbox', { name: 'search' });
  await expect(search).toBeFocused();
  await search.fill('powershell');
  await expect(page.getByText(/\d+ events · \d+ detections/)).toBeVisible();
});

test('keyboard navigation reaches the list and opens the detail panel', async ({ page }) => {
  await page.goto(url('/processes'));
  const firstRow = page.getByRole('row').nth(1);
  await firstRow.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: /PID \d+/ })).toBeVisible();
});

test('a large event list scrolls without rendering every row', async ({ page }) => {
  // The flagged session holds hundreds of events; the virtualiser must keep the DOM small regardless.
  await page.goto(url('/files'));
  await page.getByLabel('event list').waitFor();

  const rendered = await page.getByRole('row').count();
  expect(rendered, 'virtualised rows stay bounded').toBeLessThan(120);

  const list = page.getByLabel('event list');
  const before = await list.evaluate((element) => element.scrollTop);
  await list.evaluate((element) => element.scrollBy(0, 4000));
  await page.waitForTimeout(150);
  const after = await list.evaluate((element) => element.scrollTop);
  expect(after, 'the list scrolls').toBeGreaterThan(before);
});

test('100k rows scroll without jank and without rendering them all', async ({ page }) => {
  // The specification's number is 100k rows in the view model. The payload is generated here rather
  // than committed: a 30 MB fixture in git would be indistinguishable from dead weight, and the
  // virtualiser's job is to render the same handful of rows either way.
  const ROWS = 100_000;
  const events = Array.from({ length: ROWS }, (_, index) => ({
    seq: index + 1,
    timestampUtc: new Date(Date.UTC(2026, 10, 9, 5, 0, 0) + index * 40).toISOString(),
    kind: index % 7 === 0 ? 'fileCreate' : index % 7 === 1 ? 'fileDelete' : 'fileWrite',
    category: 'File',
    pid: 4000 + (index % 40),
    parentPid: 6320,
    imageName: ['cmd.exe', 'powershell.exe', 'notepad.exe'][index % 3],
    imagePath: String.raw`C:\Windows\System32` + '\\' + ['cmd.exe', String.raw`WindowsPowerShell\v1.0\powershell.exe`, 'notepad.exe'][index % 3],
    target: String.raw`C:\Users\kamal\AppData\Local\Temp` + '\\' + `stage-${index % 500}.bin`,
    remoteIp: null,
    remotePort: null,
    protocol: null,
    hostName: null,
    scope: 'InScope',
    scopeReason: 'child of the monitored process',
    observability: index % 11 === 0 ? 'Partial' : index % 5 === 0 ? 'Inferred' : 'Direct',
    confidence: 1,
    source: 'live',
  }));

  await page.route('**/fixtures/large/**', async (route) => {
    const name = new URL(route.request().url()).pathname.split('/').pop()!;
    if (name === 'events.json') {
      await route.fulfill({ json: events });
      return;
    }
    await route.fulfill({ path: `public/fixtures/flagged/${name}` });
  });

  await page.goto('/files?fixtures=large');
  const list = page.getByLabel('event list');
  await list.waitFor({ timeout: 30_000 });

  await expect(page.getByText(/100,000 of 100,000 file events/)).toBeVisible({ timeout: 30_000 });

  const rendered = await page.getByRole('row').count();
  expect(rendered, '100k rows must not become 100k DOM nodes').toBeLessThan(120);

  const started = Date.now();
  await list.evaluate((element) => element.scrollTo({ top: element.scrollHeight }));
  await page.waitForTimeout(200);
  const elapsed = Date.now() - started;

  // The Files screen caps the table at the newest 20,000 file rows (the filter and paging beyond
  // that are the timeline's job), so "the end" means the end of what this screen renders.
  const position = await list.evaluate((element) => ({
    top: element.scrollTop,
    max: element.scrollHeight - element.clientHeight,
  }));
  expect(position.top, 'the list reached the end').toBeGreaterThan(position.max * 0.9);
  expect(elapsed, `scroll to the end took ${elapsed} ms`).toBeLessThan(2_000);
  expect(await page.getByRole('row').count(), 'still bounded after scrolling').toBeLessThan(120);
});

test('the launch dialog says it cannot launch when there is no agent', async ({ page }) => {
  await page.goto('/?fixtures=benign');
  await page.getByRole('button', { name: 'Monitor an application' }).first().click();

  const dialog = page.getByRole('dialog', { name: 'Monitor an application' });
  await expect(dialog).toBeVisible();
  // Fixture mode must not pretend a launch is possible: a button that silently does nothing would be
  // read as a broken agent.
  await expect(dialog.getByText(/This is fixture data/)).toBeVisible();
  await expect(dialog.getByLabel('executable path')).toBeEditable();
  await expect(dialog.getByRole('button', { name: 'Check this file' })).toBeDisabled();
  await expect(dialog.getByRole('button', { name: 'Start monitoring' })).toBeDisabled();

  await dialog.getByRole('button', { name: 'Close' }).click();
  await expect(dialog).toBeHidden();
});

test('settings reports the configuration in force, not a set of toggles', async ({ page }) => {
  await page.goto(url('/settings'));

  // The three sections that make the screen honest: the process, the thresholds it loaded, and the
  // observability table every report also prints.
  await expect(page.getByRole('heading', { name: 'This agent' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Rule thresholds in force' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'What this tool can and cannot see' })).toBeVisible();

  // A threshold is shown by its human label *and* its key, so a new threshold cannot hide.
  await expect(page.getByText('Files created before F-004 reports a rate')).toBeVisible();
  await expect(page.getByRole('cell', { name: 'massFileCreationCount' })).toBeVisible();

  await expect(page.getByText('Not observable', { exact: false }).first()).toBeVisible();

  // Nothing on this screen may offer to change the running agent: its options are fixed at launch.
  await expect(page.getByRole('checkbox')).toHaveCount(0);
  await expect(page.locator('input[type=range]')).toHaveCount(0);
});

test('the export control downloads the captured report and never puts the token in a URL', async ({ page }) => {
  await page.goto(url('/threats'));

  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'HTML' }).click();
  const saved = await download;

  expect(saved.suggestedFilename()).toMatch(/report.*\.html$/);
  // The bearer token must not appear in the page's own URL: the fetch carries it in a header.
  expect(page.url()).not.toContain('token=');
});
