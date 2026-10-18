import http from 'node:http';
import { isIP } from 'node:net';
import { pathToFileURL } from 'node:url';
import { WorkStore, WorkError, exact, founderRecipient } from './work-store.mjs';

const cookie = (req, name) => (req.headers.cookie ?? '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='))?.slice(name.length + 1);
export function createWorkServer({ file, origin, trustedProxy = false, now = Date.now }) {
  const url = new URL(origin);
  if (url.origin !== origin || url.username || url.password || url.protocol !== 'https:' && !(url.protocol === 'http:' && url.hostname === '127.0.0.1')) throw Error('Use a fixed HTTPS public origin or loopback');
  const secure = url.protocol === 'https:', prefix = secure ? '__Host-cannabis-' : 'cannabis-';
  const store = new WorkStore(file, origin, { now }), limits = new Map();
  const setCookie = (name, value, seconds) => `${prefix}${name}=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${seconds}${secure ? '; Secure' : ''}`;
  let globalWindow = 0, globalCount = 0;
  const server = http.createServer({ maxHeaderSize: 8192, requestTimeout: 10_000, headersTimeout: 10_000 }, async (req, res) => {
    const json = (status, value) => { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(value)); };
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    try {
      if (req.headers.host !== url.host) throw new WorkError(403, 'Unexpected host');
      const route = new URL(req.url, origin);
      if (route.search) throw new WorkError(400, 'Credentials and order data do not belong in URLs');
      if (!['GET', 'POST', 'DELETE'].includes(req.method)) throw new WorkError(405, 'Method not allowed');
      if (req.headers.origin && req.headers.origin !== origin || req.headers['sec-fetch-site'] === 'cross-site' || req.method !== 'GET' && req.headers.origin !== origin) throw new WorkError(403, 'Same-origin request required');
      const tick = Math.floor(now() / 60_000);
      if (tick !== globalWindow) { globalWindow = tick; globalCount = 0; limits.clear(); }
      if (++globalCount > 1200) throw new WorkError(429, 'Please try again shortly');
      // Caddy overwrites this header; never trust it on an exposed listener.
      const ip = trustedProxy ? req.headers['x-cannabis-client-ip'] : req.socket.remoteAddress;
      if (!ip || !isIP(ip)) throw new WorkError(403, 'Verified proxy address required');
      const used = (limits.get(ip) ?? 0) + 1; limits.set(ip, used);
      if (used > 60) throw new WorkError(429, 'Please try again shortly');
      const session = cookie(req, prefix + 'session'), account = store.account(session);
      let body;
      if (req.method === 'POST') {
        if (req.headers['content-type'] !== 'application/json' || req.headers['content-encoding']) throw new WorkError(415, 'Use uncompressed JSON');
        if (Number(req.headers['content-length'] ?? 0) > 8192) throw new WorkError(413, 'Request exceeds limit');
        const chunks = []; let size = 0;
        for await (const chunk of req) { size += chunk.length; if (size > 8192) throw new WorkError(413, 'Request exceeds limit'); chunks.push(chunk); }
        try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new WorkError(400, 'Invalid JSON'); }
      }
      const method = req.method, pathname = route.pathname;
      if (method === 'GET' && pathname === '/api/work/status') return json(200, {
        status: 'preparing-service', preparationsAvailable: true, paymentsAvailable: false, executionAvailable: false,
        assets: ['Cannabis', 'ETH'], conversionAvailable: false, feeBasisPoints: 100, founderRecipient, retentionDays: 30,
        message: 'Prepare and recover orders now. Payment opens after reviewed settlement and protected worker admission.'
      });
      if (method === 'POST' && pathname === '/api/work/auth/challenge') {
        exact(body, ['address', 'chainId']); const c = store.challenge(body.address, body.chainId);
        res.setHeader('Set-Cookie', setCookie('challenge', c.binding, 300)); return json(200, { id: c.id, message: c.message });
      }
      if (method === 'POST' && pathname === '/api/work/auth/verify') {
        exact(body, ['id', 'signature']);
        const result = store.signIn(body.id, cookie(req, prefix + 'challenge'), body.signature);
        store.signOut(session);
        res.setHeader('Set-Cookie', [setCookie('session', result.token, 43200), setCookie('challenge', '', 0)]);
        return json(200, { address: result.address, expires: result.expires });
      }
      if (method === 'POST' && pathname === '/api/work/auth/logout') {
        exact(body, []); store.signOut(session); res.setHeader('Set-Cookie', setCookie('session', '', 0)); return json(200, { signedOut: true });
      }
      if (method === 'GET' && pathname === '/api/work/account') return json(200, { address: account });
      if (method === 'GET' && pathname === '/api/work/orders') return json(200, { orders: store.list(account) });
      if (method === 'POST' && pathname === '/api/work/orders') return json(201, store.create(body, account));
      const match = /^\/api\/work\/orders\/([^/]+)(\/quote)?$/.exec(pathname);
      if (match) {
        const bearer = /^Bearer ([0-9a-f]{64})$/.exec(req.headers.authorization ?? '')?.[1];
        const order = store.get(match[1], bearer, account);
        if (method === 'POST' && match[2]) {
          exact(body, []);
          return json(503, { error: 'No admitted confidential capacity or reviewed live settlement is available. No payment requested.', code: 'PAYMENT_NOT_OPEN' });
        }
        if (!match[2] && method === 'GET') return json(200, order);
        if (!match[2] && method === 'DELETE') { store.remove(match[1], bearer, account); return json(200, { deleted: true }); }
      }
      return json(404, { error: 'Not found' });
    } catch (error) {
      // Never log request bodies, credentials, wallet addresses or private data.
      if (!res.headersSent && !res.destroyed) json(error instanceof WorkError ? error.status : 500, { error: error instanceof WorkError ? error.message : 'Service unavailable; retain your recovery file' });
    }
  });
  server.keepAliveTimeout = 5000; server.maxConnections = 64;
  const cleanup = setInterval(() => store.cleanup(), 60_000); cleanup.unref();
  server.on('close', () => { clearInterval(cleanup); store.close(); });
  return { server, store };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (!process.env.CANNABIS_WORK_DB || !process.env.CANNABIS_WORK_ORIGIN) throw Error('Set the database path and canonical origin');
  const { server } = createWorkServer({ file: process.env.CANNABIS_WORK_DB, origin: process.env.CANNABIS_WORK_ORIGIN, trustedProxy: process.env.CANNABIS_WORK_PROXY === 'caddy' });
  const port = Number(process.env.CANNABIS_WORK_PORT ?? 4210);
  if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) throw Error('Invalid API port');
  server.listen(port, '127.0.0.1', () => console.log('Cannabis work API listening on loopback'));
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => server.close());
}
