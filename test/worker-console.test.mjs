import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createConsoleServer, createObserver } from '../operator/server.mjs';

async function fixture(t, observer = createObserver({ cpu: 'fixture', graphics: [] }),options={}) {
  const server = createConsoleServer(observer,options);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  t.after(async () => { observer.close?.(); await new Promise(resolve => server.close(resolve)); });
  const request=(route, { method = 'GET', headers = {},body } = {}) => new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, path: route, method, headers }, res => {
      const buffers = []; res.on('data', data => buffers.push(data));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(buffers).toString() }));
    });
    req.on('error', reject); req.end(body);
  });
  request.origin='http://127.0.0.1:'+port;return request;
}

test('worker observation cannot authorize jobs, issue currency or expose custody paths', async t => {
  const request = await fixture(t);
  const response = await request('/api/status');
  assert.equal(response.status, 200);
  const value = JSON.parse(response.body);
  assert.equal(value.worker.admitted, false);
  assert.equal(value.worker.acceptingJobs, false);
  assert.equal(value.worker.completedJobsThisSession, 0);
  assert.equal(value.worker.earningsThisSession, '0');
  assert.ok(Date.now() - Date.parse(value.observedAt) < 5000);
  assert.ok(value.resources.totalMemoryBytes > 0);
  for (const route of ['/api/start', '/api/sign', '/api/stop', '/api/status?command=run', '/../private/wallets/founder-wallet.dpapi.json', '/%2e%2e/package.json', '/server.mjs']) {
    assert.equal((await request(route)).status, 404, route);
  }
  for (const method of ['POST', 'PUT', 'DELETE', 'OPTIONS']) assert.equal((await request('/api/status', { method })).status, 405);
});

test('worker console refuses cross-site requests and DNS rebinding', async t => {
  const request = await fixture(t);
  for (const headers of [{ host: 'attacker.invalid' }, { origin: 'https://attacker.invalid' },
    { origin: 'null' }, { 'sec-fetch-site': 'cross-site' }, { 'sec-fetch-site': 'same-site' }]) {
    assert.equal((await request('/api/status', { headers })).status, 403);
    assert.equal((await request('/', { headers })).status, 403);
  }
  const response = await request('/');
  assert.equal(response.status, 200);
  assert.match(response.headers['content-security-policy'], /frame-ancestors 'none'/);
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.equal(response.headers['access-control-allow-origin'], undefined);
  assert.equal((await request('/', { method: 'HEAD' })).body, '');
});

test('observation failures return unavailable without disclosing diagnostics or success', async t => {
  const request = await fixture(t, { status() { throw Error('private diagnostic'); } });
  const response = await request('/api/status');
  assert.equal(response.status, 503);
  assert.equal(response.body, '');
  assert.equal((await request('/')).status, 200);
});

test('result mutations require the local session, exact origin, bounded JSON and a fixed action',async t=>{
  let calls=0;
  const request=await fixture(t,undefined,{results:{snapshot:()=>({state:'available'}),recover:id=>{calls++;return {id};}}});
  const control=JSON.parse((await request('/api/control')).body),id='a'.repeat(64);
  const headers={origin:request.origin,'content-type':'application/json','x-cannabis-console':control.actionToken};
  for(const change of [h=>delete h.origin,h=>h.origin='null',h=>delete h['x-cannabis-console'],
    h=>h['x-cannabis-console']='0'.repeat(64),h=>h['content-type']='text/plain',h=>h['sec-fetch-site']='cross-site']) {
    const altered={...headers};change(altered);
    assert.equal((await request('/api/results/recover',{method:'POST',headers:altered,body:JSON.stringify({id})})).status,403);
  }
  for(const body of ['null','[]','{','{"id":"x","path":"/private"}'])
    assert.equal((await request('/api/results/recover',{method:'POST',headers,body})).status,400);
  assert.equal(calls,0);
  assert.equal((await request('/api/results/recover',{method:'POST',headers,body:JSON.stringify({id})})).status,200);
  assert.equal(calls,1);
  for(const route of ['/api/results/recover','/api/results/delete','/api/results/start','/api/results/recover?path=/private'])
    assert.equal((await request(route)).status,404);
  assert.ok(!(await request('/api/status')).body.includes(control.actionToken));
});

test('missing storage and changed process tokens never trigger recovery',async t=>{
  const absent=await fixture(t);assert.equal(JSON.parse((await absent('/api/control')).body).configured,false);
  const first=await fixture(t,undefined,{results:{snapshot:()=>({state:'available'})}});
  let calls=0;const second=await fixture(t,undefined,{results:{snapshot:()=>({state:'available'}),recover:()=>calls++}});
  const old=JSON.parse((await first('/api/control')).body).actionToken;
  assert.equal((await second('/api/results/recover',{method:'POST',headers:{origin:second.origin,
    'content-type':'application/json','x-cannabis-console':old},body:JSON.stringify({id:'a'.repeat(64)})})).status,403);
  assert.equal(calls,0);
});
