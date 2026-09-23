#!/usr/bin/env node
const http = require('http');
const fs = require('fs');
const os = require('os');
const { URL } = require('url');

const CDP_URL = process.env.CDP_URL || 'http://127.0.0.1:9224';
const LISTEN_HOST = process.env.LISTEN_HOST || '127.0.0.1';
const LISTEN_PORT = process.env.LISTEN_PORT || 'auto';
const HANDOFF_PORT_MIN = Number(process.env.HANDOFF_PORT_MIN || '9501');
const HANDOFF_PORT_MAX = Number(process.env.HANDOFF_PORT_MAX || '9599');
const PLAYWRIGHT_MODULE = process.env.PLAYWRIGHT_MODULE || 'playwright';
const BROWSER_LAUNCH_RECEIPT = process.env.BROWSER_LAUNCH_RECEIPT;
const PAGE_ID = process.env.HANDOFF_PAGE_ID;
let launchReceipt;
let unavailable = false;

function sameIdentity(a, b) {
  return a && b && ['pid', 'start', 'boot', 'node'].every((key) => a[key] === b[key]);
}

function liveIdentity(pid) {
  const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
  const fields = stat.slice(stat.lastIndexOf(')') + 2).trim().split(/\s+/);
  if (fields[0] === 'Z') throw new Error('browser process is a zombie');
  return { pid, start: fields[19],
    boot: fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(), node: os.hostname() };
}

function controlIdentity(receipt) {
  return new Promise((resolve, reject) => {
    const req = http.get({ socketPath: receipt.control_socket, path: '/identity' }, (res) => {
      let body = '';
      res.on('data', (chunk) => {
        body += chunk;
        if (body.length > 8192) req.destroy(new Error('control identity too large'));
      });
      res.on('error', reject);
      res.on('end', () => {
        try {
          if (res.statusCode !== 200) throw new Error('control identity unavailable');
          resolve(JSON.parse(body));
        } catch (error) { reject(error); }
      });
    });
    const timer = setTimeout(() => req.destroy(new Error('control identity deadline')), 3000);
    req.on('close', () => clearTimeout(timer));
    req.on('error', reject);
  });
}

async function verifyControl(receipt) {
  validateLiveBrowser(receipt);
  if (receipt.control_mode === 'pipe-fenced') {
    const current = await controlIdentity(receipt);
    if (!current.available || current.cdp_url !== CDP_URL ||
        !sameIdentity(current.process_identity, receipt.process_identity)) {
      throw new Error('exact browser control revoked or unavailable');
    }
  }
}

function paneIdentity() {
  // Deliberately exclude endpoint capabilities, profile, account and page content.
  return { instance_id: launchReceipt.instance_id || null,
    pane_id: launchReceipt.pane_id || null, page_id: selectedPageId || null,
    control_mode: launchReceipt.control_mode || 'legacy' };
}

function validateLiveBrowser(receipt) {
  if (!Number.isInteger(receipt.pid) || receipt.pid <= 1) {
    throw new Error('BROWSER_LAUNCH_RECEIPT must record a live browser pid');
  }
  if (typeof receipt.profile_dir !== 'string' || !receipt.profile_dir.startsWith('/')) {
    throw new Error('BROWSER_LAUNCH_RECEIPT must record an absolute profile_dir');
  }

  const cdp = new URL(CDP_URL);
  if (cdp.protocol !== 'http:' || cdp.hostname !== '127.0.0.1' || !/^\d+$/.test(cdp.port) ||
      cdp.username || cdp.password || cdp.search || cdp.hash) {
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

  if (receipt.control_mode === 'pipe-fenced') {
    if (!sameIdentity(receipt.process_identity, liveIdentity(receipt.pid))) {
      throw new Error('receipt process_identity does not match live PID/start/boot/node');
    }
    if (!proc.includes('--remote-debugging-pipe') ||
        proc.some((arg) => arg.startsWith('--remote-debugging-port=')) ||
        !proc.includes(`--user-data-dir=${receipt.profile_dir}`)) {
      throw new Error('live pipe browser does not match receipt profile/control mode');
    }
    if (!/^\/[A-Za-z0-9_-]{43}$/.test(cdp.pathname)) {
      throw new Error('pipe CDP_URL must retain the exact generation path');
    }
    const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    if (!uuid.test(receipt.instance_id) || receipt.pane_id !== receipt.instance_id) {
      throw new Error('pipe receipt requires matching stable instance_id and pane_id');
    }
    if (typeof receipt.control_socket !== 'string' || !receipt.control_socket.startsWith('/')) {
      throw new Error('pipe receipt requires absolute control_socket');
    }
    const socket = fs.lstatSync(receipt.control_socket);
    if (!socket.isSocket() || socket.uid !== process.getuid() || (socket.mode & 0o077)) {
      throw new Error('control_socket must be a private owned Unix socket');
    }
  } else if (!proc.includes(`--remote-debugging-port=${cdp.port}`) ||
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
let selectedPageId;

async function getPage() {
  if (unavailable) throw new Error('handoff unavailable');
  try {
    await verifyControl(launchReceipt);
    if (!browserPromise) {
      browserPromise = chromium.connectOverCDP(CDP_URL, { timeout: 10000 }).then((browser) => {
        browser.on('disconnected', () => { unavailable = true; });
        return browser;
      });
    }
    if (!pagePromise) {
      pagePromise = browserPromise.then(async (browser) => {
        const candidates = [];
        for (const context of browser.contexts()) {
          for (const page of context.pages()) {
            if (page.url().startsWith('chrome-extension://')) continue;
            const session = await context.newCDPSession(page);
            let info;
            try { info = await session.send('Target.getTargetInfo'); }
            finally { await session.detach(); }
            const id = info.targetInfo.targetId;
            if (!PAGE_ID || PAGE_ID === id) candidates.push({ page, id });
          }
        }
        if (candidates.length !== 1) {
          throw new Error('select exactly one existing page with HANDOFF_PAGE_ID');
        }
        selectedPageId = candidates[0].id;
        candidates[0].page.on('close', () => { unavailable = true; });
        return candidates[0].page;
      });
    }
    const page = await pagePromise;
    if (unavailable || page.isClosed()) throw new Error('selected page closed');
    return page;
  } catch (error) {
    unavailable = true;
    throw error;
  }
}

function html() {
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Browser Handoff</title>
<style>body { margin:0; font-family:sans-serif; background:#111; color:#eee }
header { padding:10px; background:#222 } #shot { max-width:100vw; height:auto }
button,input { font:inherit; margin-right:6px }</style></head><body>
<header><span id="pane"></span>
<button id="refresh">refresh</button><button id="back">back</button>
<button id="reload">reload</button><input id="text" placeholder="type text then Enter">
<span id="status">Click refresh to view; no automatic screenshots.</span></header>
<img id="shot" alt="browser screenshot"><script>
const img = document.getElementById('shot');
const status = document.getElementById('status');
let stopped = false;
let imageURL;
function stop() {
  stopped = true;
  status.textContent = 'Handoff unavailable: control revoked, browser stopped, or selected page closed. Start a new handoff with the current receipt.';
  document.querySelectorAll('button,input').forEach(el => el.disabled = true);
  img.removeAttribute('src');
  if (imageURL) URL.revokeObjectURL(imageURL);
}
async function request(path, options) {
  if (stopped) return null;
  try {
    const res = await fetch(path, options);
    if (!res.ok) { stop(); return null; }
    return res;
  } catch (error) { stop(); return null; }
}
async function load() {
  const res = await request('screenshot.jpg');
  if (!res) return;
  const blob = await res.blob();
  if (stopped) return;
  if (imageURL) URL.revokeObjectURL(imageURL);
  imageURL = URL.createObjectURL(blob); img.src = imageURL;
  status.textContent = 'Snapshot; refresh explicitly to update.';
}
async function action(path, options = {}) {
  if (await request(path, { ...options, method:'POST' })) await load();
}
img.onclick = async event => {
  if (stopped || !img.naturalWidth) return;
  const rect = img.getBoundingClientRect();
  const x = Math.round((event.clientX-rect.left)*img.naturalWidth/rect.width);
  const y = Math.round((event.clientY-rect.top)*img.naturalHeight/rect.height);
  await action('click?x='+x+'&y='+y);
};
document.getElementById('refresh').onclick = load;
document.getElementById('back').onclick = () => action('back');
document.getElementById('reload').onclick = () => action('reload');
document.getElementById('text').onkeydown = async event => {
  if (event.key !== 'Enter') return;
  const text = event.currentTarget.value; event.currentTarget.value = '';
  await action('type', {headers:{'content-type':'application/json'}, body:JSON.stringify({text})});
};
async function identity() {
  const res = await request('identity');
  if (res) {
    const value = await res.json();
    document.getElementById('pane').textContent = 'Pane '+(value.pane_id || 'legacy')+' / page '+value.page_id;
  }
}
// Status only: never issue screenshot/evaluation or renew a reservation on a timer.
setInterval(identity, 5000);
identity();
</script></body></html>`;
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (unavailable) throw new Error('handoff unavailable');
    if (url.pathname === '/identity') {
      await verifyControl(launchReceipt);
      if (unavailable) throw new Error('handoff unavailable');
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(paneIdentity()));
      return;
    }

    if (url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end(html());
      return;
    }
    const page = await getPage();
    if (url.pathname === '/screenshot.jpg') {
      const buffer = await page.screenshot({ type: 'jpeg', quality: 75, fullPage: false, timeout: 10000 });
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
      await page.reload({ waitUntil: 'domcontentloaded', timeout: 30000 });
      res.writeHead(204).end();
      return;
    }
    if (url.pathname === '/back' && req.method === 'POST') {
      await page.goBack({ waitUntil: 'domcontentloaded', timeout: 30000 });
      res.writeHead(204).end();
      return;
    }

    res.writeHead(404).end('not found');
  } catch (error) {
    unavailable = true;
    res.writeHead(410, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
    res.end('Handoff unavailable: control revoked, browser stopped, or selected page unavailable. Start a new handoff with the current receipt and intended page.');
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
  if (LISTEN_HOST !== '127.0.0.1') throw new Error('LISTEN_HOST must be 127.0.0.1');
  launchReceipt = validateLaunchReceipt();
  await getPage();
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
    ...paneIdentity(),
  }));
}

startServer().catch((error) => {
  console.error(String(error.message || error).split(CDP_URL).join('[CDP endpoint]'));
  // A failed page selection may already have a Playwright transport open.
  process.exit(1);
});
