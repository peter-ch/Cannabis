import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { Contract, formatEther } from 'ethers';
import { root } from './compile.mjs';
import { localProof } from './lib.mjs';

const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.png': 'image/png', '.svg': 'image/svg+xml', '.json': 'application/json', '.md': 'text/plain; charset=utf-8', '.mp4': 'video/mp4', '.mp3': 'audio/mpeg' };
export function createServer({ provider, token, state, vestingAbi, port = 4200 }) {
  let busy = false;
  const vesting = new Contract(state.vesting, vestingAbi, provider);
  const origin = `http://127.0.0.1:${port}`;
  const server = http.createServer(async (req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
    const json = (status, data) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(data)); };
    if (req.headers.host !== `127.0.0.1:${port}`) return json(403, { error: 'Loopback host required' });
    try {
      const url = new URL(req.url, origin);
      if (req.method === 'GET' && url.pathname === '/api/status') {
        const recipient = await (await provider.getSigner(1)).getAddress();
        const [supply, issued, start, balance, released, claimed, founderAllocation] = await Promise.all([
          token.totalSupply(), token.communityIssued(), token.claimsStartAt(), token.balanceOf(recipient), vesting.released(), token.walletClaimed(recipient), token.FOUNDER_ALLOCATION()]);
        return json(200, { network: 'Local devnet', chainId: 31337, address: state.address, recipient, founder: state.founder,
          totalSupply: formatEther(supply), communityIssued: formatEther(issued), claims: String(issued / await token.CLAIM_AMOUNT()), claimsStartAt: Number(start),
          balance: formatEther(balance), founderReleased: formatEther(released), founderAllocation: formatEther(founderAllocation), claimed,
          vestingStart: state.start, vestingEnd: state.end, verification: 'LOCAL_MOCK_ONLY', busy });
      }
      if (req.method === 'POST' && url.pathname === '/api/claim') {
        if (req.headers.origin !== origin || req.headers['content-type'] !== 'application/json') return json(403, { error: 'Same-origin request required' });
        if (busy) return json(409, { error: 'A local proof is already being prepared' });
        if (Number(req.headers['content-length'] ?? 0) > 2 || req.headers['transfer-encoding']) return json(413, { error: 'Request body must be empty or {}' });
        busy = true;
        try {
          const signer = await provider.getSigner(1);
          const address = await signer.getAddress();
          if (await token.walletClaimed(address)) return json(409, { error: 'This local identity has already claimed' });
          const proof = await localProof(provider, token, address);
          const next = await token.claimsStartAt();
          const head = await provider.getBlock('latest');
          if (Number(next) > head.timestamp) await provider.send('evm_setNextBlockTimestamp', [Math.max(Number(next), Math.floor(Date.now() / 1000))]);
          const tx = await token.connect(signer).claim(address, proof, { gasLimit: 600000 });
          const receipt = await tx.wait();
          return json(200, { transaction: receipt.hash, reward: '420', gasUsed: receipt.gasUsed.toString(), verification: 'LOCAL_MOCK_ONLY' });
        } finally { busy = false; }
      }
      if (req.method !== 'GET') return json(405, { error: 'Method not allowed' });
      let filename;
      if (url.pathname === '/') filename = path.join(root, 'web/index.html');
      else if (/^\/docs\/[a-z-]+\.md$/.test(url.pathname)) filename = path.join(root, url.pathname.slice(1));
      else if (/^\/media\/(cannabis-(landscape|portrait)\.mp4|narration\.txt|captions\.srt)$/.test(url.pathname)) filename = path.join(root, url.pathname.slice(1));
      else if (/^\/(style\.css|app\.js|assets\/[a-z-]+\.png)$/.test(url.pathname)) filename = path.join(root, 'web', url.pathname.slice(1));
      else return json(404, { error: 'Not found' });
      if (!fs.existsSync(filename)) return json(404, { error: 'Not found' });
      const size = fs.statSync(filename).size;
      const headers = { 'Content-Type': types[path.extname(filename)] ?? 'text/plain; charset=utf-8', 'Accept-Ranges': 'bytes' };
      if (req.headers.range) {
        const match = /^bytes=(\d+)-(\d*)$/.exec(req.headers.range);
        const start = match ? Number(match[1]) : NaN;
        const end = match?.[2] ? Math.min(Number(match[2]), size - 1) : size - 1;
        if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start > end || start >= size) {
          res.writeHead(416, { 'Content-Range': `bytes */${size}` }); return res.end();
        }
        res.writeHead(206, { ...headers, 'Content-Length': end - start + 1, 'Content-Range': `bytes ${start}-${end}/${size}` });
        fs.createReadStream(filename, { start, end }).on('error', () => res.destroy()).pipe(res);
      } else {
        res.writeHead(200, { ...headers, 'Content-Length': size });
        fs.createReadStream(filename).on('error', () => res.destroy()).pipe(res);
      }
    } catch (error) { json(500, { error: error.shortMessage ?? 'Local node unavailable; check the server log' }); }
  });
  return server;
}
