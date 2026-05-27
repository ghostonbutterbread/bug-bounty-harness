#!/usr/bin/env node
const http = require('http');
const { URL } = require('url');

const CDP_URL = process.env.CDP_URL || 'http://127.0.0.1:9224';
const LISTEN_HOST = process.env.LISTEN_HOST || '127.0.0.1';
const LISTEN_PORT = Number(process.env.LISTEN_PORT || '9230');
const PLAYWRIGHT_MODULE = process.env.PLAYWRIGHT_MODULE || 'playwright';

let chromium;
try {
  ({ chromium } = require(PLAYWRIGHT_MODULE));
} catch (error) {
  ({ chromium } = require('/home/ryushe/.local/playwright/node_modules/playwright'));
}

let browserPromise;
let pagePromise;

async function getPage() {
  if (!browserPromise) {
    browserPromise = chromium.connectOverCDP(CDP_URL);
  }
  if (!pagePromise) {
    pagePromise = browserPromise.then(async (browser) => {
      const context = browser.contexts()[0] || await browser.newContext();
      return context.pages().find((page) => !page.url().startsWith('chrome-extension://')) ||
        context.pages()[0] ||
        await context.newPage();
    });
  }
  return pagePromise;
}

function html() {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>CDP Handoff</title>
  <style>
    body { margin: 0; font-family: sans-serif; background: #111; color: #eee; }
    header { padding: 8px 12px; background: #222; position: sticky; top: 0; z-index: 2; }
    button, input { font: inherit; margin-right: 6px; }
    #shot { display: block; max-width: 100vw; height: auto; cursor: crosshair; }
    #status { opacity: .8; margin-left: 8px; }
  </style>
</head>
<body>
  <header>
    <button id="refresh">refresh</button>
    <button id="back">back</button>
    <button id="reload">reload</button>
    <input id="text" placeholder="type text then Enter" size="32">
    <span id="status"></span>
  </header>
  <img id="shot" alt="browser screenshot">
  <script>
    const img = document.getElementById('shot');
    const status = document.getElementById('status');
    function setStatus(value) { status.textContent = value; }
    function load() { img.src = '/screenshot.jpg?t=' + Date.now(); }
    img.addEventListener('load', () => setStatus('ready ' + new Date().toLocaleTimeString()));
    img.addEventListener('error', () => setStatus('screenshot failed'));
    img.addEventListener('click', async (event) => {
      const rect = img.getBoundingClientRect();
      const x = Math.round((event.clientX - rect.left) * img.naturalWidth / rect.width);
      const y = Math.round((event.clientY - rect.top) * img.naturalHeight / rect.height);
      setStatus('click ' + x + ',' + y);
      await fetch('/click?x=' + x + '&y=' + y, { method: 'POST' });
      setTimeout(load, 400);
    });
    document.getElementById('refresh').onclick = load;
    document.getElementById('reload').onclick = async () => {
      await fetch('/reload', { method: 'POST' });
      setTimeout(load, 1000);
    };
    document.getElementById('back').onclick = async () => {
      await fetch('/back', { method: 'POST' });
      setTimeout(load, 1000);
    };
    document.getElementById('text').addEventListener('keydown', async (event) => {
      if (event.key !== 'Enter') return;
      const value = event.currentTarget.value;
      event.currentTarget.value = '';
      await fetch('/type', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ text: value })
      });
      setTimeout(load, 400);
    });
    setInterval(load, 2000);
    load();
  </script>
</body>
</html>`;
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const page = await getPage();

    if (url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end(html());
      return;
    }
    if (url.pathname === '/screenshot.jpg') {
      const buffer = await page.screenshot({ type: 'jpeg', quality: 75, fullPage: false });
      res.writeHead(200, { 'content-type': 'image/jpeg', 'cache-control': 'no-store' });
      res.end(buffer);
      return;
    }
    if (url.pathname === '/click' && req.method === 'POST') {
      await page.mouse.click(Number(url.searchParams.get('x')), Number(url.searchParams.get('y')));
      res.writeHead(204).end();
      return;
    }
    if (url.pathname === '/type' && req.method === 'POST') {
      const body = JSON.parse(await readBody(req) || '{}');
      await page.keyboard.type(String(body.text || ''), { delay: 25 });
      res.writeHead(204).end();
      return;
    }
    if (url.pathname === '/reload' && req.method === 'POST') {
      await page.reload({ waitUntil: 'domcontentloaded', timeout: 30000 }).catch(() => {});
      res.writeHead(204).end();
      return;
    }
    if (url.pathname === '/back' && req.method === 'POST') {
      await page.goBack({ waitUntil: 'domcontentloaded', timeout: 30000 }).catch(() => {});
      res.writeHead(204).end();
      return;
    }

    res.writeHead(404).end('not found');
  } catch (error) {
    res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(error && error.stack || String(error));
  }
});

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
  console.log(`CDP handoff listening on http://${LISTEN_HOST}:${LISTEN_PORT} for ${CDP_URL}`);
});
