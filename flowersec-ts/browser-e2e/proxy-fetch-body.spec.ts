import { expect, test } from '@playwright/test';
import { startBrowserModuleSite } from './browser-module-site.js';

test('Portable browsers run proxy request body serialization', async ({ page }) => {
  const site = await startBrowserModuleSite();
  try {
    await page.goto(site.origin);
    const result = await page.evaluate(async () => {
      const moduleURL = '/dist/proxy/fetch.js';
      const { prepareProxyFetch } = await import(moduleURL);
      const empty = await prepareProxyFetch('/api');
      const post = await prepareProxyFetch('/api', { method: 'POST', body: '{"value":42}', headers: { 'Content-Type': 'application/json' } });
      let limited = false;
      try { await prepareProxyFetch('/api', { method: 'POST', body: 'too large' }, undefined, 4); }
      catch (error) { limited = (error as {code?: string}).code === 'resource_exhausted'; }
      return { empty: empty.request.body === undefined, value: new TextDecoder().decode(post.request.body), limited };
    });
    expect(result).toEqual({ empty: true, value: '{"value":42}', limited: true });
  } finally { await site.close(); }
});
