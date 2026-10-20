// Loopback capability interface for explicit requester wallet review. Holds no
// wallet keys and exposes no signing, file paths or transactions from HTTP input.
import http from 'node:http';
import fs from 'node:fs';
import {randomBytes} from 'node:crypto';
import {TypedDataEncoder,verifyTypedData} from 'ethers';
import {validateWorkflowReview,workflowSigningSchema} from './workflow-wallet-schema.mjs';
import {canonical,workflowCheck as check} from './workflow-store.mjs';
const assets=new Map([['/','workflow.html'],['/workflow-ui.js','workflow-ui.js'],['/workflow-wallet.js','workflow-wallet.js'],
  ['/workflow-wallet-schema.mjs','workflow-wallet-schema.mjs'],['/workflow.css','workflow.css']]);
export async function createWorkflowApprovalServer({snapshot,start,clock=Date.now,mode='run'}={}) {
  check(typeof snapshot==='function'&&typeof start==='function'&&typeof clock==='function'&&['run','recover'].includes(mode));
  const capability=randomBytes(32).toString('hex'),requests=new Map();let origin,closed=false,running=false,state='ready',outcome;
  function finish(r,signature,error) {
    if(!requests.has(r.review.id))return;requests.delete(r.review.id);clearTimeout(r.timer);r.signal?.removeEventListener('abort',r.abort);
    error?r.reject(Error('Workflow approval ended')):r.resolve(signature);
  }
  const signApproval=(input,signal)=>new Promise((resolve,reject)=>{
    try {
      check(!closed&&!signal?.aborted&&requests.size<64);const p=input.payload,s=workflowSigningSchema(input.kind,p.domain.version);
      check(p.domain.name===s.name&&canonical(p.types)===canonical(s.types)&&p.digest===TypedDataEncoder.hash(p.domain,p.types,p.value));
      const review=validateWorkflowReview({id:randomBytes(32).toString('hex'),kind:input.kind,reservationId:input.reservationId,
        requester:input.requester,genesisHash:input.genesisHash,expiresAt:input.expiresAt*1000,digest:p.digest,
        typedData:TypedDataEncoder.getPayload(p.domain,p.types,p.value)},clock());
      const r={review,p:structuredClone(p),resolve,reject,signal};r.abort=()=>finish(r,null,true);
      r.timer=setTimeout(r.abort,Math.max(1,review.expiresAt-clock()));requests.set(review.id,r);signal?.addEventListener('abort',r.abort,{once:true});
      if(signal?.aborted)r.abort();
    }catch{reject(Error('Workflow approval unavailable'));}
  });
  const server=http.createServer(async(req,res)=>{
    const reply=(status,value,type='application/json')=>{res.writeHead(status,{'Content-Type':type,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
      'Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"});
      res.end(typeof value==='string'||Buffer.isBuffer(value)?value:JSON.stringify(value));};
    try {
      check(!closed&&req.headers.host===new URL(origin).host&&(!req.headers.origin||req.headers.origin===origin));
      if(req.method==='GET'&&assets.has(req.url)) {
        const name=assets.get(req.url),type=name.endsWith('.html')?'text/html; charset=utf-8':name.endsWith('.css')?'text/css; charset=utf-8':'text/javascript; charset=utf-8';
        return reply(200,fs.readFileSync(new URL(name,import.meta.url)),type);
      }
      check(req.headers.authorization==='Bearer '+capability&&(!req.headers['sec-fetch-site']||req.headers['sec-fetch-site']==='same-origin'));
      if(req.method==='GET'&&req.url==='/api/state')return reply(200,{state,mode,outcome,workflow:snapshot(),requests:[...requests.values()].map(r=>r.review)});
      check(req.method==='POST'&&req.headers.origin===origin&&req.headers['content-type']==='application/json');
      let bytes=0;const chunks=[];for await(const chunk of req){bytes+=chunk.length;check(bytes<=4096);chunks.push(chunk);}
      const body=JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if(req.url==='/api/start') {
        check(!running&&state==='ready'&&Object.keys(body).length===0);running=true;state='running';
        Promise.resolve().then(()=>start(signApproval)).then(result=>{outcome=result;state='finished';},()=>{state='recovery-required';})
          .finally(()=>{running=false;});return reply(202,{started:true});
      }
      check(req.url==='/api/approve'&&Object.keys(body).sort().join()==='id,signature');const r=requests.get(body.id);
      check(r&&!r.signal?.aborted&&clock()<r.review.expiresAt&&typeof body.signature==='string'&&body.signature.length<=16386&&
        verifyTypedData(r.p.domain,r.p.types,r.p.value,body.signature)===r.review.requester);
      finish(r,body.signature,false);return reply(200,{approved:true});
    }catch{if(!res.headersSent)reply(400,{error:'Local workflow request refused'});else res.destroy();}
  });
  server.headersTimeout=10000;server.requestTimeout=10000;server.maxConnections=16;
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  origin='http://127.0.0.1:'+server.address().port;
  return {origin,url:origin+'/#'+capability,signApproval,close:async()=>{closed=true;for(const r of requests.values())finish(r,null,true);
    server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}};
}
