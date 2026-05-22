// Playwright capture template for D-2 desktop snapshots.
//
// Usage (from CI or a developer machine):
//   cd client-ui && npm run dev &
//   playwright test test-rigs/snapshots-d2/capture/playwright-template.spec.ts
//
// The template visits each primary D-2 surface, switches theme +
// locale, and writes the four PNGs per flow under
// test-rigs/snapshots-d2/desktop/<flow>/.

import { test, expect } from '@playwright/test';
import { writeFileSync } from 'node:fs';
import { mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';

const FLOWS: Array<{ id: string; setup: (page: any) => Promise<void> }> = [
    { id: 'connection', setup: async () => {} },
    {
        id: 'routes-empty',
        setup: async (page) => page.click('text=Routes'),
    },
    {
        id: 'sources-empty',
        setup: async (page) => page.click('text=Sources'),
    },
    {
        id: 'status',
        setup: async (page) => page.click('text=Status'),
    },
    {
        id: 'settings',
        setup: async (page) => page.click('text=Settings'),
    },
];

const VARIANTS: Array<{ id: string; lang: 'EN' | 'FA'; theme: 'light' | 'dark' }> = [
    { id: 'EN-light', lang: 'EN', theme: 'light' },
    { id: 'EN-dark', lang: 'EN', theme: 'dark' },
    { id: 'FA-light', lang: 'FA', theme: 'light' },
    { id: 'FA-dark', lang: 'FA', theme: 'dark' },
];

for (const flow of FLOWS) {
    for (const variant of VARIANTS) {
        test(`${flow.id} ${variant.id}`, async ({ page }) => {
            await page.goto('http://localhost:1420/');
            await page.evaluate(([lang, theme]) => {
                if (theme === 'dark' || theme === 'light') {
                    document.documentElement.setAttribute('data-theme', theme);
                }
                if (lang === 'FA') {
                    document.documentElement.setAttribute('dir', 'rtl');
                    document.documentElement.setAttribute('lang', 'fa');
                } else {
                    document.documentElement.setAttribute('dir', 'ltr');
                    document.documentElement.setAttribute('lang', 'en');
                }
            }, [variant.lang, variant.theme]);
            await flow.setup(page);

            const out = resolve(
                __dirname,
                `../desktop/${flow.id}/${variant.id}.png`,
            );
            mkdirSync(dirname(out), { recursive: true });
            const buf = await page.screenshot({ fullPage: true });
            writeFileSync(out, buf);

            // Visual regression assertion is added in CI mode; the
            // template just captures.
            expect(buf.length).toBeGreaterThan(0);
        });
    }
}
