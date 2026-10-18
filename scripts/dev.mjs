// Preview exactly the public release website. No wallet, RPC or claim API.
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import './build-site.mjs';
const root = fs.realpathSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../dist-site'));
const port = 4200;
const mime = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.png': 'image/png', '.webp': 'image/webp', '.svg': 'image/svg+xml', '.md': 'text/plain; charset=utf-8', '.txt': 'text/plain; charset=utf-8', '.srt': 'text/plain; charset=utf-8', '.vtt': 'text/vtt', '.mp4': 'video/mp4' };
const server = http.createServer((req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self'; media-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'");
  if (req.headers.host !== '127.0.0.1:' + port) { res.writeHead(403).end(); return; }
  if (!['GET', 'HEAD'].includes(req.method)) { res.writeHead(405).end(); return; }
  let file;
  try {
    const url = new URL(req.url, 'http://127.0.0.1');
    const name = decodeURIComponent(url.pathname);
    file = fs.realpathSync(path.resolve(root, '.' + (name === '/' ? '/index.html' : name)));
    if (!file.startsWith(root + path.sep) || !fs.statSync(file).isFile()) throw Error();
  } catch { res.writeHead(404).end(); return; }
  const size = fs.statSync(file).size;
  let start = 0, end = size - 1, status = 200;
  res.setHeader('Accept-Ranges', 'bytes');
  if (req.headers.range) {
    const match = /^bytes=(\d+)-(\d*)$/.exec(req.headers.range);
    if (!match) { res.writeHead(416, { 'Content-Range': 'bytes */' + size }).end(); return; }
    start = Number(match[1]); end = match[2] ? Math.min(Number(match[2]), end) : end;
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start > end || start >= size) {
      res.writeHead(416, { 'Content-Range': 'bytes */' + size }).end(); return;
    }
    status = 206; res.setHeader('Content-Range', 'bytes ' + start + '-' + end + '/' + size);
  }
  res.writeHead(status, { 'Content-Type': mime[path.extname(file)] || 'application/octet-stream', 'Content-Length': Math.max(0, end - start + 1) });
  if (req.method === 'HEAD' || !size) { res.end(); return; }
  const stream = fs.createReadStream(file, { start, end });
  stream.on('error', () => res.destroy()); res.on('close', () => stream.destroy()); stream.pipe(res);
});
server.listen(port, '127.0.0.1', () => console.log('Cannabis website: http://127.0.0.1:' + port));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close());
