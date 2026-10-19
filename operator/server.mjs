// Loopback controls for observation, recovery, provider signing and the optional
// retained operator service. No wallet-key custody or settlement authority.
import http from 'node:http';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes,timingSafeEqual } from 'node:crypto';

const run = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const files = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/console.css', ['console.css', 'text/css; charset=utf-8']],
  ['/console.js', ['console.js', 'text/javascript; charset=utf-8']],
  ['/results.js', ['results.js', 'text/javascript; charset=utf-8']],
  ['/results.css', ['results.css', 'text/css; charset=utf-8']],
  ['/provider.js', ['provider.js', 'text/javascript; charset=utf-8']],
  ['/provider-wallet.js', ['provider-wallet.js', 'text/javascript; charset=utf-8']],
  ['/provider.css', ['provider.css', 'text/css; charset=utf-8']],
  ['/service.js', ['service.js', 'text/javascript; charset=utf-8']],
  ['/service.css', ['service.css', 'text/css; charset=utf-8']],
  ['/market.js', ['market.js', 'text/javascript; charset=utf-8']],
  ['/market-wallet.js', ['market-wallet.js', 'text/javascript; charset=utf-8']],
  ['/market-wallet.js.LEGAL.txt', ['market-wallet.js.LEGAL.txt', 'text/plain; charset=utf-8']],
  ['/market.css', ['market.css', 'text/css; charset=utf-8']],
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
        'No custody, plaintext customer content, job intake, payment or token issuance is available here.']
    })
  };
}

export function createConsoleServer(observer,{results=null,provider=null,service=null,market=null}={}) {
  const actionToken=randomBytes(32).toString('hex');
  const actions=new Map([
    ['/api/results/recover',['id',body=>results.recover(body.id)]],
    ['/api/results/prepare-retry',['grants,id',body=>results.prepareRetry(body.id,body.grants)]],
    ['/api/results/start-retry',['reviewId',body=>results.startRetry(body.reviewId)]],
    ['/api/results/discard-review',['reviewId',body=>results.discardReview(body.reviewId)]],
    ['/api/results/cancel-retry',['operationId',body=>results.cancelRetry(body.operationId)]],
    ['/api/provider/begin',['assignmentId',body=>provider.beginLaunch(body.assignmentId)]],
    ['/api/provider/review',['requestId',body=>provider.detail(body.requestId)]],
    ['/api/provider/submit',['requestId,signature',body=>provider.submit(body.requestId,body.signature)]],
    ['/api/provider/decline',['requestId',body=>provider.decline(body.requestId)]],
    ['/api/service/start',['',()=>service.start()]],
    ['/api/service/stop',['',()=>service.stop()]],
    ['/api/market/network',['',()=>market.network()]],
    ['/api/market/offers',['fromBlock,toBlock',body=>market.discover(body)]],
    ['/api/market/bookings',['bookingIds',body=>market.bookings(body.bookingIds)]],
    ['/api/market/import',['plan',body=>market.importPlan(body.plan)]],
    ['/api/market/plan',['planId',body=>market.plan(body.planId)]],
    ['/api/market/export',['planId',body=>market.exportPlan(body.planId)]],
    ['/api/market/inspect',['planId',body=>market.inspect(body.planId)]],
    ['/api/market/begin',['bookingId,method,planId,signer',body=>market.begin(body.planId,{method:body.method,actor:body.signer,bookingId:body.bookingId})]],
    ['/api/market/detail',['requestId',body=>market.detail(body.requestId)]],
    ['/api/market/handoff',['requestId',body=>market.handoff(body.requestId)]],
    ['/api/market/signature',['requestId,signature',body=>market.submitSignature(body.requestId,body.signature)]],
    ['/api/market/import-signature',['bookingId,planId,signature,signer',body=>market.importSignature(body.planId,body.bookingId,body.signer,body.signature)]],
    ['/api/market/report-hash',['actionId,transactionHash',body=>market.reportHash(body.actionId,body.transactionHash)]],
    ['/api/market/action',['actionId',body=>market.action(body.actionId)]],
    ['/api/market/observe',['actionId',body=>market.observe(body.actionId)]],
    ['/api/market/wallet-refused',['actionId',body=>market.walletRefused(body.actionId)]],
    ['/api/market/cancel',['requestId',body=>market.cancel(body.requestId)]]
  ]);
  const server=http.createServer({ requestTimeout: 5000, headersTimeout: 5000, maxHeaderSize: 8192 }, async (req, res) => {
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
    const json=(value,status=200)=>{
      const body=JSON.stringify(value);res.writeHead(status,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)});
      res.end(req.method==='HEAD'?undefined:body);
    };
    if(actions.has(req.url)&&req.method==='POST') {
      const provided=req.headers['x-cannabis-console'];
      if(req.headers.origin!==origin||req.headers['content-type']!=='application/json'||typeof provided!=='string'||
        !/^[0-9a-f]{64}$/.test(provided)||!timingSafeEqual(Buffer.from(provided),Buffer.from(actionToken))) {
        req.resume();res.writeHead(403).end();return;
      }
      const signing=req.url.startsWith('/api/provider/'),operating=req.url.startsWith('/api/service/'),trading=req.url.startsWith('/api/market/');
      if(!(trading?market:operating?service:signing?provider:results)){req.resume();json({error:trading?'No reviewed market is configured.':operating?'No operator service is configured.':signing?'No provider catalog is configured.':'No result store is configured.'},503);return;}
      const timer=setTimeout(()=>req.destroy(),5000);let body;
      try {
        const chunks=[];let size=0;
        for await(const chunk of req){size+=chunk.length;if(size>(trading?262144:operating?64:signing?20480:8192))throw Error('Body limit');chunks.push(chunk);}
        body=JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if(!body||Array.isArray(body)||Object.keys(body).sort().join()!==actions.get(req.url)[0])throw Error('Body shape');
      }catch{if(!res.destroyed)json({error:'Use the selected item and a bounded console request.'},400);return;}
      finally{clearTimeout(timer);}
      try{json(await actions.get(req.url)[1](body),operating||req.url==='/api/results/start-retry'?202:200);}
      catch{json({error:trading?'Market action unavailable. Refresh the selected plan and retain uncertain transaction records.':operating?'Service action unavailable. Refresh lifecycle status and retain recovery state.':signing?'Provider approval unavailable. Refresh and review the retained assignment.':'Recovery action unavailable. Keep the retained result, refresh its state and review the selected relay.'},409);}
      return;
    }
    if (!['GET', 'HEAD'].includes(req.method)) { res.writeHead(405, { Allow: 'GET, HEAD' }).end(); return; }
    // Exact routing: no user-selected paths, shell commands, RPC URLs or filenames.
    if (req.url === '/api/status') {
      try {
        const value=observer.status();
        value.resultStorage=results?results.snapshot():{state:'not-configured',reason:'No retained result store is selected for this console.'};
        value.providerApprovals=provider?provider.snapshot():{state:'not-configured',reason:'No retained provider assignments are selected for this console.'};
        value.operatorService=service?service.snapshot():{state:'not-configured',reason:'No operator service is selected. This window shows machine observations only.'};
        value.market=market?market.snapshot():{state:'not-configured',reason:'No reviewed network and market deployment are selected. No offers or payments are available here.'};
        if(market){value.mode='market-controls';value.worker.reason='Market activity does not establish an admitted worker or verified session earnings.';
          value.limits[value.limits.length-1]='Market controls prepare explicit wallet approvals. A transaction, offer or reservation does not establish confidential execution or accepted work.';}
        if(service){value.mode='operator-controls';value.worker.reason='Paid acceptance and earnings are not verified by local service or transport status.';
          value.limits[value.limits.length-1]='The selected booked service has separate controls. Local sessions do not establish payment, token issuance or requester attestation.';}
        json(value);
      } catch { res.writeHead(503).end(); }
      return;
    }
    if(req.url==='/api/control'){json({schema:'cannabis.console-control.v1',configured:Boolean(results||provider||service||market),
      resultStorage:Boolean(results),providerApprovals:Boolean(provider),operatorService:Boolean(service),market:Boolean(market),actionToken:results||provider||service||market?actionToken:null});return;}
    const asset = assets.get(req.url);
    if (!asset) { res.writeHead(404).end(); return; }
    res.writeHead(200, { 'Content-Type': asset.type, 'Content-Length': asset.body.length });
    res.end(req.method === 'HEAD' ? undefined : asset.body);
  });
  server.maxConnections=16;return server;
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
  let directory,catalog,approvalDirectory,serviceFile,marketFile,marketState,port=4201,open=false;const relayOrigins=[];
  const args=process.argv.slice(2);
  for(let i=0;i<args.length;i++) {
    if(args[i]==='--open'&&!open)open=true;
    else if(args[i]==='--result-store'&&!directory&&args[i+1])directory=args[++i];
    else if(args[i]==='--relay-origin'&&args[i+1])relayOrigins.push(args[++i]);
    else if(args[i]==='--provider-catalog'&&!catalog&&args[i+1])catalog=args[++i];
    else if(args[i]==='--provider-approvals'&&!approvalDirectory&&args[i+1])approvalDirectory=args[++i];
    else if(args[i]==='--operator-config'&&!serviceFile&&args[i+1])serviceFile=args[++i];
    else if(args[i]==='--market-config'&&!marketFile&&args[i+1])marketFile=args[++i];
    else if(args[i]==='--market-state'&&!marketState&&args[i+1])marketState=args[++i];
    else if(args[i]==='--port'&&/^[0-9]{1,5}$/.test(args[i+1]??''))port=Number(args[++i]);
    else throw Error('Usage: node operator/server.mjs [--open] [--port PORT] [--operator-config ABSOLUTE_FILE | --result-store ABSOLUTE_PATH --relay-origin ORIGIN --provider-catalog ABSOLUTE_FILE --provider-approvals ABSOLUTE_DIRECTORY --market-config ABSOLUTE_FILE --market-state ABSOLUTE_JOURNAL]');
  }
  if(!Number.isSafeInteger(port)||port<1024||port>65535||relayOrigins.length&&!directory||Boolean(catalog)!==Boolean(approvalDirectory)||
    Boolean(marketFile)!==Boolean(marketState)||serviceFile&&(directory||catalog||approvalDirectory||relayOrigins.length||marketFile||marketState))throw Error('Invalid local console configuration');
  let results=null,provider=null,service=null,market=null;
  if(serviceFile){const {openOperatorService}=await import('./service.mjs');({service,results,provider,market}=await openOperatorService(serviceFile));}
  if(directory){const {ResultConsole}=await import('./storage-console.mjs');results=new ResultConsole(directory,{relayOrigins});}
  if(catalog){const {ProviderApprovals,readProviderCatalog}=await import('./provider-approvals.mjs');
    provider=new ProviderApprovals(readProviderCatalog(catalog),approvalDirectory);}
  if(marketFile){const {MarketConsole,readMarketConfiguration}=await import('./market-console.mjs');market=new MarketConsole(readMarketConfiguration(marketFile),marketState);}
  const observer = createObserver(await localInventory());
  const server = createConsoleServer(observer,{results,provider,service,market});
  let closing;
  const close=()=>closing??=(async()=>{observer.close();server.close();server.closeAllConnections();
    if(service)await service.close();else{await market?.close();await results?.close();await provider?.close();}})().catch(()=>{
      console.error('Operator shutdown is unverified. Preserve recovery state and inspect owned processes.');process.exitCode=1;});
  server.on('error', async error => { await close(); console.error(error.code === 'EADDRINUSE' ? 'The selected port is already in use. No existing process was replaced.' : 'Console could not start.'); process.exitCode = 1; });
  server.listen(port, '127.0.0.1', () => {
    const url = `http://127.0.0.1:${port}/`;
    console.log(`Cannabis worker console: ${url}\nLocal observations${results?', encrypted-result recovery':''}${provider?', provider approvals':''}${service?', explicit booked-service controls':''}; paid acceptance is not verified.`);
    if (open) openConsole(url);
  });
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, close);
}
