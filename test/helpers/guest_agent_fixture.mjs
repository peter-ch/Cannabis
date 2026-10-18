// HTTP protocol fixture only: these bytes are not a hardware attestation report.
import http from 'node:http';
import { GUEST_AGENT_VERSION } from '../../compute/guest_session.mjs';

export async function guestAgentFixture(options = {}) {
  const calls = [], reports = [];
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1'); calls.push(url.pathname);
    if (url.pathname === '/info') {
      if (options.redirect) { res.writeHead(302, { Location: options.redirect }); res.end(); return; }
      res.end(JSON.stringify({ version: GUEST_AGENT_VERSION, tee: options.tee || 'snp', feature: 'attestation', ...options.info })); return;
    }
    if (url.pathname === '/aa/evidence') {
      reports.push({ encoding: url.searchParams.get('encoding'), bytes: Buffer.from(url.searchParams.get('runtime_data'), 'base64url') });
      if (options.hang) return;
      options.onEvidence?.();
      res.end(options.raw ?? JSON.stringify({ protocolFixtureOnly: true, attestation_report: { report_data: [...reports.at(-1).bytes] }, cert_chain: null })); return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, calls, reports,
    close: () => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }) };
}
