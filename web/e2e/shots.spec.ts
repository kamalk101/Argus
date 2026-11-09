import { test } from '@playwright/test';

/** Not an assertion suite: writes the screenshots used to review the layout by eye. */
const SHOTS = [
  ['/', 'sessions'],
  ['/live', 'live'],
  ['/threats', 'threats'],
  ['/timeline', 'timeline'],
  ['/processes', 'processes'],
  ['/network', 'network'],
  ['/files', 'files'],
] as const;

for (const [path, name] of SHOTS) {
  test(`shot ${name}`, async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto(`${path}?fixtures=flagged`);
    await page.waitForTimeout(900);
    await page.screenshot({ path: `../.shots/${name}.png` });
  });
}

test('shot threat expanded', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/threats?fixtures=flagged');
  await page.locator('button[aria-expanded]').first().click();
  await page.waitForTimeout(800);
  await page.screenshot({ path: '../.shots/threat-expanded.png' });
});
