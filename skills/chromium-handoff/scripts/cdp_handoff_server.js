#!/usr/bin/env node
const http = require('http');
const fs = require('fs');
const { URL } = require('url');

const CDP_URL = process.env.CDP_URL || 'http://127.0.0.1:9224';
const LISTEN_HOST = process.env.LISTEN_HOST || '127.0.0.1';
const LISTEN_PORT = process.env.LISTEN_PORT || 'auto';
const HANDOFF_PORT_MIN = Number(process.env.HANDOFF_PORT_MIN || '9501');
const HANDOFF_PORT_MAX = Number(process.env.HANDOFF_PORT_MAX || '9599');
const PLAYWRIGHT_MODULE = process.env.PLAYWRIGHT_MODULE || 'playwright';
const BROWSER_LAUNCH_RECEIPT = process.env.BROWSER_LAUNCH_RECEIPT;

function validateLiveBrowser(receipt) {
  if (!Number.isInteger(receipt.pid) || receipt.pid <= 1) {
    throw new Error('BROWSER_LAUNCH_RECEIPT must record a live browser pid');
  }
  if (typeof receipt.profile_dir !== 'string' || !receipt.profile_dir.startsWith('/')) {
    throw new Error('BROWSER_LAUNCH_RECEIPT must record an absolute profile_dir');
  }

  const cdp = new URL(CDP_URL);
  if (cdp.protocol !== 'http:' || cdp.hostname !== '127.0.0.1' || !/^\d+$/.test(cdp.port)) {
    throw new Error('CDP_URL must be a loopback HTTP endpoint with an explicit port');
  }

  let proc;
  try {
    const procStat = fs.statSync(`/proc/${receipt.pid}`);
    if (procStat.uid !== process.getuid()) {
      throw new Error('browser pid is not owned by the handoff user');
    }
    proc = fs.readFileSync(`/proc/${receipt.pid}/cmdline`, 'utf8').split('\0');
  } catch (error) {
    throw new Error(`could not verify live browser pid: ${error.message}`);
  }

  if (!proc.includes(`--remote-debugging-port=${cdp.port}`) ||
      !proc.includes('--remote-debugging-address=127.0.0.1') ||
      !proc.includes(`--user-data-dir=${receipt.profile_dir}`)) {
    throw new Error('live browser pid does not match the receipt CDP endpoint and profile');
  }
}

function validateLaunchReceipt() {
  if (!BROWSER_LAUNCH_RECEIPT) {
    throw new Error('BROWSER_LAUNCH_RECEIPT is required for a CDP screenshot handoff');
  }

  let receipt;
  try {
    receipt = JSON.parse(fs.readFileSync(BROWSER_LAUNCH_RECEIPT, 'utf8'));
  } catch (error) {
    throw new Error(`could not read BROWSER_LAUNCH_RECEIPT: ${error.message}`);
  }

  const fallback = receipt.display_fallback;
  if (!fallback || fallback.from !== 'kasmvnc' || typeof fallback.reason !== 'string' || !fallback.reason.trim()) {
    throw new Error('BROWSER_LAUNCH_RECEIPT must record a KasmVNC display_fallback reason');
  }
  if (receipt.proxy_cert_mode !== 'import') {
    throw new Error('BROWSER_LAUNCH_RECEIPT must record proxy_cert_mode: import');
  }
  if (!receipt.proxy_cert_status || receipt.proxy_cert_status.status !== 'trusted') {
    throw new Error('BROWSER_LAUNCH_RECEIPT must record proxy_cert_status.status: trusted');
  }
  if (receipt.cdp_url !== CDP_URL) {
    throw new Error('BROWSER_LAUNCH_RECEIPT cdp_url does not match CDP_URL');
  }
  validateLiveBrowser(receipt);
  return receipt;
}

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

function listen(port) {
  return new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off('listening', onListening);
      reject(error);
    };
    const onListening = () => {
      server.off('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(port, LISTEN_HOST);
  });
}

async function startServer() {
  validateLaunchReceipt();
  if (LISTEN_PORT === 'auto') {
    if (!Number.isInteger(HANDOFF_PORT_MIN) || !Number.isInteger(HANDOFF_PORT_MAX) ||
        HANDOFF_PORT_MIN < 1024 || HANDOFF_PORT_MAX > 65535 || HANDOFF_PORT_MIN > HANDOFF_PORT_MAX) {
      throw new Error(`invalid handoff port range: ${HANDOFF_PORT_MIN}-${HANDOFF_PORT_MAX}`);
    }
    let lastError;
    for (let port = HANDOFF_PORT_MIN; port <= HANDOFF_PORT_MAX; port += 1) {
      try {
        await listen(port);
        break;
      } catch (error) {
        if (error && error.code !== 'EADDRINUSE') throw error;
        lastError = error;
      }
    }
    if (!server.listening) {
      throw lastError || new Error('no free handoff port');
    }
  } else {
    const port = Number(LISTEN_PORT);
    if (!Number.isInteger(port) || port < 1024 || port > 65535) {
      throw new Error(`invalid LISTEN_PORT: ${LISTEN_PORT}`);
    }
    await listen(port);
  }

  const address = server.address();
  console.log(JSON.stringify({
    event: 'cdp_handoff_ready',
    listen_host: LISTEN_HOST,
    listen_port: address.port,
    cdp_url: CDP_URL,
  }));
}

startServer().catch((error) => {
  console.error(error && error.stack || String(error));
  process.exitCode = 1;
});
