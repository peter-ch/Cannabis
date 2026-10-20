// Actual isolated-chain discovery checks; no live provider or funds.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { AbiCoder, ContractFactory, ZeroAddress, keccak256, toUtf8Bytes } from 'ethers';
import { compile } from '../scripts/compile.mjs';
import { startNode } from '../scripts/lib.mjs';
import { readMarketOffers } from '../compute/market_reader.mjs';

let node, provider, artifacts, market, native, tokenEscrow, asset, requester, founder, first, second, judge, outsider, initial, now;
let sequence = 0;
const hash = text => keccak256(toUtf8Bytes(text));
const nonce = () => hash('market-fixture-' + ++sequence);
const coder = AbiCoder.defaultAbiCoder();
const sorted = records => records.map(r => r.id).sort();
const freePort = () => new Promise(resolve => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); });
async function deploy(name, args = []) {
  const c = await new ContractFactory(artifacts[name].abi, artifacts[name].bytecode, requester).deploy(...args);
  await c.waitForDeployment(); return c;
}
before(async () => {
  artifacts = compile({ 'MarketFixtures.sol': { content: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
contract MarketAsset is ERC20 {
    constructor() ERC20("Isolated market fixture", "FIX") { _mint(msg.sender, 1000000 ether); }
}
contract ProviderWallet {
    address public immutable owner;
    constructor(address owner_) { owner = owner_; }
    function invoke(address target, bytes calldata data) external {
        require(msg.sender == owner);
        (bool ok,) = target.call(data); require(ok);
    }
    function isValidSignature(bytes32 digest, bytes calldata signature) external view returns (bytes4) {
        return ECDSA.recover(digest, signature) == owner ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}` } });
  node = await startNode(await freePort(), 'provider-manifest-test-node.log'); provider = node.provider;
  [requester, founder, first, second, judge, outsider] = await Promise.all(Array.from({ length: 6 }, (_, i) => provider.getSigner(i)));
  asset = await deploy('MarketAsset');
  native = await deploy('ComputeEscrow', [ZeroAddress, await founder.getAddress()]);
  tokenEscrow = await deploy('ComputeEscrow', [await asset.getAddress(), await founder.getAddress()]);
  market = await deploy('ComputeMarket', [await native.getAddress(), await tokenEscrow.getAddress()]);
  await (await asset.approve(await tokenEscrow.getAddress(), 10n ** 30n)).wait();
  initial = await provider.send('evm_snapshot', []);
});
after(() => { provider?.destroy(); node?.child.kill(); });
async function reset() {
  await provider.send('evm_revert', [initial]); initial = await provider.send('evm_snapshot', []);
  now = (await provider.getBlock('latest')).timestamp;
}
import { encodeProviderManifest, inspectProviderManifest, readProviderManifest } from '../compute/provider_manifest.mjs';

async function manifestOffer(alter=m=>m) {
  await reset();
  const account=await first.getAddress(),resourceId=nonce(),id=await market.resourceKey(account,resourceId),serviceHash=hash('manifest-service');
  await (await market.connect(first).publishResource(resourceId,serviceHash,2)).wait();
  const salt=nonce(),offerId=keccak256(coder.encode(['address','bytes32'],[account,salt]));
  const terms={resource:id,escrow:await native.getAddress(),policyHash:hash('private-policy'),start:String(now+1000),end:String(now+3000),
    expiresAt:String(now+900),units:'1',grossPerUnitSecond:'100'};
  const network={rpc:node.rpc,chainId:31337,market:await market.getAddress(),marketCodeHash:keccak256(await provider.getCode(await market.getAddress())),
    genesisHash:(await provider.getBlock(0)).hash,finality:'rpc-finalized',maxFinalizedAgeSeconds:3600};
  const manifest=alter({schema:'cannabis.provider-manifest.v1',chainId:'31337',genesisHash:network.genesisHash,market:network.market,offerId,
    resource:{id,provider:account,serviceHash,units:'2'},offer:terms,
    endpoints:[{role:'booking',origin:'https://provider.invalid'},{role:'session',origin:'https://provider.invalid'}],
    runtimes:[{adapter:'native-linux-x86_64-v1',architecture:'x86_64',os:'linux',digestSHA256:hash('runtime'),tee:'snp',acceleratorClass:'cpu'}],
    terms:'Public verification fixture. No live provider, capacity or payment.'});
  const encoded=encodeProviderManifest(manifest);
  const receipt=await (await market.connect(first).publishOffer(salt,{...terms,manifestHash:encoded.manifestHash})).wait();
  const clock=()=>now;
  const query={offerId,fromBlock:receipt.blockNumber,toBlock:receipt.blockNumber,mirrors:[]};
  return {network,query,clock,...encoded};
}
async function mirror(t,handler) {
  const requests=[];
  const server=http.createServer((req,res)=>{
    requests.push({url:req.url,headers:req.headers});
    Promise.resolve(handler(req,res)).catch(()=>{res.destroy();});
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
  return {origin:'http://127.0.0.1:'+server.address().port,requests};
}
const serve=(res,bytes,headers={})=>{res.writeHead(200,{'content-type':'application/json','content-length':bytes.length,...headers});res.end(bytes);};

test('exact public manifests match independently observed offer terms and reject ambiguous bytes or secret fields',async()=>{
  const f=await manifestOffer(),snapshot=await readMarketOffers(f.network,f.query,f.clock);
  const inspected=inspectProviderManifest(f.bytes,snapshot,f.query.offerId,now);
  assert.equal(inspected.matchesSuppliedObservation,true);assert.equal(inspected.chainVerified,false);
  assert.equal(inspected.endpointAuthenticated,false);assert.equal(inspected.hardwareValidated,false);
  for(const alter of [m=>m.privateKey='forbidden',m=>m.resource.units='01',m=>m.offer.grossPerUnitSecond='101',
    m=>m.endpoints[0].origin='https://name:password@example.invalid',m=>m.endpoints[0].origin+='/',
    m=>m.endpoints[0].origin='http://127.0.0.1',m=>m.runtimes[0].arguments=['private'],m=>m.terms='\0',
    m=>m.endpoints=m.endpoints.slice(0,1),m=>m.runtimes.push(m.runtimes[0])]) {
    const changed=structuredClone(f.manifest);alter(changed);assert.throws(()=>encodeProviderManifest(changed));
  }
  for(const bytes of [Buffer.from(JSON.stringify(f.manifest)),Buffer.from(JSON.stringify(f.manifest,null,2)+'\n'),
    Buffer.from(f.bytes.toString().replace('"schema":','"schema":"duplicate","schema":')),Buffer.from([0xff]),Buffer.alloc(65537)])
    assert.throws(()=>inspectProviderManifest(bytes,snapshot,f.query.offerId,now));
  for(const alter of [s=>s.genesisHash=hash('different chain'),s=>s.offers[0].resource.provider=requester.address,
    s=>s.offers[0].offer.units='2',s=>s.offers[0].withdrawn=true]) {
    const s=structuredClone(snapshot);alter(s);assert.throws(()=>inspectProviderManifest(f.bytes,s,f.query.offerId,now));
  }
});

test('two interchangeable mirrors retrieve only the on-chain hash without a founder site or credentials',async t=>{
  const f=await manifestOffer();
  const bad=await mirror(t,(req,res)=>serve(res,Buffer.from('{}\n')));
  const good=await mirror(t,(req,res)=>serve(res,f.bytes));
  f.query.mirrors=[bad.origin,good.origin];
  const result=await readProviderManifest(f.network,f.query,{clock:f.clock});
  assert.equal(result.chainVerified,true);assert.equal(result.manifestHash,f.manifestHash);assert.equal(result.mirror,good.origin);
  assert.equal(result.bookingGuaranteed,false);assert.equal(result.endpointAuthenticated,false);assert.equal(result.keyReleaseAuthorized,false);
  for(const m of [bad,good]) {
    assert.equal(m.requests.length,1);assert.equal(m.requests[0].url,'/.well-known/cannabis/manifests/sha256/'+f.manifestHash.slice(2)+'.json');
    assert.equal(m.requests[0].headers.authorization,undefined);assert.equal(m.requests[0].headers.cookie,undefined);
  }
});

test('withdrawal during download is reobserved before returning provider contact data',async t=>{
  const f=await manifestOffer(),m=await mirror(t,async(req,res)=>{
    await (await market.connect(first).withdrawOffer(f.query.offerId)).wait();serve(res,f.bytes);
  });
  f.query.mirrors=[m.origin];await assert.rejects(readProviderManifest(f.network,f.query,{clock:f.clock}));
  assert.equal(m.requests.length,1);
});

test('a provider cannot commit metadata naming another provider or a different offer',async t=>{
  for(const change of [m=>({...m,resource:{...m.resource,provider:requester.address}}),m=>({...m,offerId:hash('other offer')})]) {
    const f=await manifestOffer(change),m=await mirror(t,(req,res)=>serve(res,f.bytes));f.query.mirrors=[m.origin];
    await assert.rejects(readProviderManifest(f.network,f.query,{clock:f.clock}));assert.equal(m.requests.length,1);
  }
});

test('network pins fail before HTTP and caller mutations do not replace retained selections',async t=>{
  const f=await manifestOffer(),m=await mirror(t,(req,res)=>{
    f.query.mirrors=['https://unselected.invalid'];f.network.rpc='https://unselected.invalid';serve(res,f.bytes);
  });
  f.query.mirrors=[m.origin];
  await assert.rejects(readProviderManifest({...f.network,genesisHash:hash('wrong')},f.query,{clock:f.clock}));assert.equal(m.requests.length,0);
  const result=await readProviderManifest(f.network,f.query,{clock:f.clock});assert.equal(result.mirror,m.origin);assert.equal(m.requests.length,1);
});

test('redirects, compression, oversized responses and wrong bytes cannot select a provider',async t=>{
  const f=await manifestOffer();
  const handlers=[(req,res)=>{res.writeHead(302,{Location:'https://unselected.invalid'});res.end();},
    (req,res)=>serve(res,f.bytes,{'content-encoding':'gzip'}),
    (req,res)=>{res.writeHead(200,{'content-type':'application/json','content-length':65537});res.end('x');},
    (req,res)=>serve(res,Buffer.from('{}\n'))];
  const servers=[];for(const h of handlers)servers.push(await mirror(t,h));f.query.mirrors=servers.map(m=>m.origin);
  await assert.rejects(readProviderManifest(f.network,f.query,{clock:f.clock}));
  servers.forEach(m=>assert.equal(m.requests.length,1));
});

test('cancellation and clock rollback prevent a mirror fallback or late result',async t=>{
  for(const mode of ['cancel','clock']) {
    const f=await manifestOffer(),controller=new AbortController();let time=now;
    const first=await mirror(t,(req,res)=>{if(mode==='cancel')controller.abort();else time--;serve(res,f.bytes);});
    const second=await mirror(t,(req,res)=>serve(res,f.bytes));f.query.mirrors=[first.origin,second.origin];
    await assert.rejects(readProviderManifest(f.network,f.query,{clock:()=>time,signal:controller.signal}));
    assert.equal(first.requests.length,1);assert.equal(second.requests.length,0);
  }
});

test('a stalled mirror cannot extend the retained retrieval budget',async t=>{
  const f=await manifestOffer(),m=await mirror(t,()=>{});f.query.mirrors=[m.origin];
  const started=Date.now();
  await assert.rejects(readProviderManifest(f.network,f.query,{clock:f.clock,timeoutMs:4000}));
  assert.equal(m.requests.length,1);assert.ok(Date.now()-started<10000);
});

test('a stalled RPC is cancelled under the same budget before any mirror is contacted',async t=>{
  const f=await manifestOffer(),held=[];
  const rpc=await mirror(t,(req,res)=>{const state={closed:false};held.push(state);res.on('close',()=>{state.closed=true;});});
  const content=await mirror(t,(req,res)=>serve(res,f.bytes));f.query.mirrors=[content.origin];
  const started=Date.now();
  await assert.rejects(readProviderManifest({...f.network,rpc:rpc.origin},f.query,{clock:f.clock,timeoutMs:1000}));
  assert.ok(Date.now()-started<5000);assert.ok(held.length>0);assert.equal(content.requests.length,0);
  await new Promise(resolve=>setTimeout(resolve,50));assert.ok(held.every(r=>r.closed));
});

test('oversized or redirected RPC replies are refused before fetching public contacts',async t=>{
  const f=await manifestOffer(),content=await mirror(t,(req,res)=>serve(res,f.bytes));f.query.mirrors=[content.origin];
  for(const mode of ['oversized','redirect']) {
    const rpc=await mirror(t,(req,res)=>{
      if(mode==='redirect'){res.writeHead(302,{Location:content.origin});res.end();}
      else {res.writeHead(200,{'content-type':'application/json','content-length':'1048577'});res.end('x');}
    });
    await assert.rejects(readProviderManifest({...f.network,rpc:rpc.origin},f.query,{clock:f.clock}));
    assert.equal(content.requests.length,0);
  }
});

test('direct manifest CLI prepares exact bytes, fetches independently and preserves existing files',async t=>{
  const f=await manifestOffer(),directory=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-provider-cli-'));
  t.after(()=>{assert.equal(path.dirname(fs.realpathSync(directory)),fs.realpathSync(os.tmpdir()));
    assert.ok(path.basename(directory).startsWith('cannabis-provider-cli-'));fs.rmSync(directory,{recursive:true});});
  const write=(name,value)=>{const p=path.join(directory,name+'.json');fs.writeFileSync(p,JSON.stringify(value));return p;};
  const run=async(...args)=>JSON.parse((await promisify(execFile)(process.execPath,['scripts/compute-provider-manifest.mjs',...args],
    {encoding:'utf8',windowsHide:true,timeout:30000})).stdout);
  const input=write('input',f.manifest),preparedFile=path.join(directory,'prepared.json');
  const prepared=await run('encode',input,preparedFile);
  assert.equal(prepared.chainVerified,false);assert.equal(prepared.transactionSubmitted,false);
  assert.equal(prepared.manifestHash,f.manifestHash);assert.deepEqual(fs.readFileSync(preparedFile),f.bytes);
  await assert.rejects(run('encode',input,preparedFile));assert.deepEqual(fs.readFileSync(preparedFile),f.bytes);
  const snapshot=await readMarketOffers(f.network,f.query,f.clock);
  const inspected=await run('inspect',preparedFile,write('observed',snapshot),f.query.offerId);
  assert.equal(inspected.chainVerified,false);assert.equal(inspected.matchesSuppliedObservation,true);
  const m=await mirror(t,(req,res)=>serve(res,f.bytes));f.query.mirrors=[m.origin];
  const output=path.join(directory,'downloaded.json');
  const fetched=await run('fetch',write('network',f.network),write('selection',f.query),output);
  assert.equal(fetched.chainVerified,true);assert.equal(fetched.endpointAuthenticated,false);
  assert.deepEqual(fs.readFileSync(output),f.bytes);assert.equal(m.requests.length,1);
});
