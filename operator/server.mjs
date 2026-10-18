// Local observation only. This process never opens custody, accepts work or signs payments.
import http from 'node:http';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const files = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/console.css', ['console.css', 'text/css; charset=utf-8']],
  ['/console.js', ['console.js', 'text/javascript; charset=utf-8']],
  ['/compute-engine.webp', ['../web/assets/editorial/compute-engine-small.webp', 'image/webp']]
]);
const assets = new Map([...files].map(([route, [name, type]]) => [route, { type, body: fs.readFileSync(path.join(here, name)) }]));

export async function localInventory() {
  let graphics = [], graphicsStatus = 'unavailable';
  if (process.platform === 'win32') {
    try {
      const shell = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32/WindowsPowerShell/v1.0/powershell.exe');
      const { stdout } = await run(shell, ['-NoProfile', '-NonInteractive', '-Command',
        'Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress'],
      { timeout: 10000, maxBuffer: 16384, windowsHide: true });
      const names = JSON.parse(stdout.replace(/^\uFEFF/, ''));
      graphics = (Array.isArray(names) ? names : [names]).filter(x => typeof x === 'string').map(x => x.slice(0, 160));
      graphicsStatus = 'observed';
    } catch { /* An inventory failure must never become an admission success. */ }
  }
  return { os: os.platform(), architecture: os.arch(), cpu: os.cpus()[0]?.model ?? 'Unavailable',
    logicalCpus: os.cpus().length, totalMemoryBytes: os.totalmem(), graphics, graphicsStatus,
    observedAt: new Date().toISOString() };
}

export function createObserver(inventory) {
  let previous = os.cpus(), cpuPercent = null;
  const sample = () => {
    const current = os.cpus();
    let total = 0, idle = 0;
    if (current.length === previous.length) for (let i = 0; i < current.length; i++) {
      for (const key of Object.keys(current[i].times)) total += current[i].times[key] - previous[i].times[key];
      idle += current[i].times.idle - previous[i].times.idle;
    }
    cpuPercent = total > 0 ? Math.round(Math.max(0, Math.min(100, 100 * (1 - idle / total)))) : null;
    previous = current;
  };
  const timer = setInterval(sample, 1000);
  timer.unref();
  return {
    close: () => clearInterval(timer),
    status: () => ({
      schema: 'cannabis.worker-console.v1', observedAt: new Date().toISOString(), mode: 'local-observation',
      inventory, resources: { cpuPercent, totalMemoryBytes: os.totalmem(), freeMemoryBytes: os.freemem(),
        consoleUptimeSeconds: Math.floor(process.uptime()) },
      worker: { admitted: false, acceptingJobs: false, completedJobsThisSession: 0, earningsThisSession: '0',
        reason: 'This console has no admitted confidential runtime. Customer work and payment intake are unavailable.' },
      requirements: [
        { name: 'Protected hardware', detail: 'A fresh, verified SNP or TDX report bound to the approved guest and assignment is required.' },
        { name: 'Isolated execution', detail: 'The measured launcher must enforce runtime, storage, network and device isolation, cleanup and key retirement.' },
        { name: 'Reviewed settlement', detail: 'Canonical contracts, provider terms, requester signing and accepted-result verification are required.' },
        { name: 'End-to-end acceptance', detail: 'A real paid job must prove protected execution, requester decryption and the exact worker/service fee split.' }
      ],
      limits: ['Machine inventory and utilization are observations, not attestation or billable work.',
        'This console does not infer current global launch status from local settings.',
        'No custody, job content, remote access, payment, mining or token issuance is available here.']
    })
  };
}

export function createConsoleServer(observer) {
  return http.createServer({ requestTimeout: 5000, headersTimeout: 5000, maxHeaderSize: 8192 }, (req, res) => {
    const origin = `http://127.0.0.1:${res.socket.localPort}`;
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    if (req.headers.host !== origin.slice(7) || (req.headers.origin && req.headers.origin !== origin) ||
        (req.headers['sec-fetch-site'] && !['same-origin', 'none'].includes(req.headers['sec-fetch-site']))) {
      res.writeHead(403).end(); return;
    }
    if (!['GET', 'HEAD'].includes(req.method)) { res.writeHead(405, { Allow: 'GET, HEAD' }).end(); return; }
    // Exact routing: no user-selected paths, shell commands, RPC URLs or filenames.
    if (req.url === '/api/status') {
      try {
        const body = JSON.stringify(observer.status());
        res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
        res.end(req.method === 'HEAD' ? undefined : body);
      } catch { res.writeHead(503).end(); }
      return;
    }
    const asset = assets.get(req.url);
    if (!asset) { res.writeHead(404).end(); return; }
    res.writeHead(200, { 'Content-Type': asset.type, 'Content-Length': asset.body.length });
    res.end(req.method === 'HEAD' ? undefined : asset.body);
  });
}

function openConsole(url) {
  if (process.platform !== 'win32') return;
  const chrome = [process.env.ProgramFiles, process.env['ProgramFiles(x86)'], process.env.LOCALAPPDATA]
    .filter(Boolean).map(base => path.join(base, 'Google/Chrome/Application/chrome.exe')).find(file => fs.existsSync(file));
  const executable = chrome ?? path.join(process.env.SystemRoot || 'C:\\Windows', 'explorer.exe');
  const child = spawn(executable, chrome ? [`--app=${url}`] : [url], { detached: true, stdio: 'ignore', windowsHide: false });
  child.on('error', () => console.error(`Open ${url} in your browser.`));
  child.unref();
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.slice(2).some(arg => arg !== '--open')) throw Error('Usage: node operator/server.mjs [--open]');
  const observer = createObserver(await localInventory());
  const server = createConsoleServer(observer);
  server.on('error', error => { observer.close(); console.error(error.code === 'EADDRINUSE' ? 'Port 4201 is already in use. No existing process was replaced.' : 'Console could not start.'); process.exitCode = 1; });
  server.listen(4201, '127.0.0.1', () => {
    const url = 'http://127.0.0.1:4201/';
    console.log(`Cannabis worker console: ${url}\nLocal observation only; paid execution is not admitted.`);
    if (process.argv.includes('--open')) openConsole(url);
  });
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => { observer.close(); server.close(); server.closeAllConnections(); });
}
