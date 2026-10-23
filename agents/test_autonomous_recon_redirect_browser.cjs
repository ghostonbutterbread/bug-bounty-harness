// Local browser transport regression: node --test agents/test_autonomous_recon_redirect_browser.cjs
// Requires Node Playwright and a local Chrome/Chromium executable; no external target.
const assert = require('node:assert/strict');
const http = require('node:http');
const test = require('node:test');
const {chromium} = require('playwright');

const chrome = process.env.CHROME_BIN || '/usr/bin/google-chrome';

test('one-response routing never transfers an excluded redirect hop', async () => {
  const hits = [];
  const server = http.createServer((req, res) => {
    hits.push(req.url);
    if (req.url === '/out-redirect') {
      res.writeHead(302, {Location: '/private-redirect'});
      res.end();
    } else if (req.url === '/in-redirect') {
      res.writeHead(302, {Location: '/allowed'});
      res.end();
    } else {
      res.writeHead(200, {'Content-Type': 'text/html'});
      res.end('<html>allowed</html>');
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    const origin = `http://127.0.0.1:${server.address().port}`;
    const permitted = url => new URL(url).origin === origin && !new URL(url).pathname.startsWith('/private');
    let waits = 0;
    const failures = [];
    const allowedNavigation = [];
    browser = await chromium.launch({headless: true, executablePath: chrome});
    const context = await browser.newContext({serviceWorkers: 'block'});
    await context.route('**/*', async route => {
      const url = route.request().url();
      if (!permitted(url)) return route.abort();
      try {
        waits++;
        const response = await route.fetch({maxRedirects: 0});
        if ([301, 302, 303, 307, 308].includes(response.status())) {
          const location = response.headers()['location'];
          const destination = location && new URL(location, url).href;
          await route.abort();
          if (destination && permitted(destination) && route.request().isNavigationRequest()) {
            allowedNavigation.push(url);
          } else {
            failures.push(`Browser redirect not followed: ${url} -> ${destination || 'missing Location'}`);
          }
        } else {
          await route.fulfill({response});
        }
      } catch (err) {
        failures.push(`Browser route failed: ${url}: ${err.name}`);
        await route.abort();
      }
    });
    const page = await context.newPage();
    await assert.rejects(page.goto(`${origin}/out-redirect`));
    assert.deepEqual(hits, ['/out-redirect']);
    assert.equal(hits.includes('/private-redirect'), false);
    assert.match(failures.join('\n'), /private-redirect/);
    assert.equal(waits, 1);

    failures.length = 0;
    await assert.rejects(page.goto(`${origin}/in-redirect`));
    assert.deepEqual(allowedNavigation, [`${origin}/in-redirect`]);
    assert.equal(hits.includes('/allowed'), false); // browser did not follow it unguarded
    // Python's _ScopedRedirect is the fallback; its focused test verifies the
    // allow/rate decision on every hop. Exercise the same local HTTP redirect.
    const response = await fetch(`${origin}/in-redirect`);
    assert.equal(response.status, 200);
    assert.equal(await response.text(), '<html>allowed</html>');
    assert.deepEqual(hits, ['/out-redirect', '/in-redirect', '/in-redirect', '/allowed']);
    assert.equal(failures.length, 0);
    assert.equal(waits, 2);
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
});
