// Isolated loopback chain and public-metadata journals. No owner custody or live RPC.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';
import {ContractFactory,ZeroAddress,keccak256,toUtf8Bytes,AbiCoder,formatUnits} from 'ethers';
import {compile} from '../../scripts/compile.mjs';
import {startNode} from '../../scripts/lib.mjs';
import {MarketJournal} from '../../operator/market-journal.mjs';
import {MarketConsole} from '../../operator/market-console.mjs';
import {prepareMarketPlan} from '../../operator/market-plan.mjs';
import {createConsoleServer,createObserver} from '../../operator/server.mjs';

export const founder='0xe02Ad92413aD0a3Aac8263eE3C2Bd9410955F89b';
const coder=AbiCoder.defaultAbiCoder(),utc=t=>new Date(t*1000).toISOString().replace('.000Z','Z');
let sequence=0;
export const nonce=()=>keccak256(toUtf8Bytes('isolated-market-console-'+ ++sequence));
const freePort=()=>new Promise(resolve=>{const s=net.createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
export async function waitRequest(console,started,expected) {
  const until=Date.now()+65000;
  while(Date.now()<until) {
    const r=console.detail(started.requestId);
    if(!['running','rechecking','checking-signature'].includes(r.state)) {
      if(expected&&r.state!==expected)throw Error(`Expected ${expected}, got ${r.state}: ${r.error}`);
      return r;
    }
    await new Promise(resolve=>setTimeout(resolve,15));
  }
  throw Error('Market operation exceeded its deadline');
}
export async function marketConsoleFixture() {
  const artifacts=compile({'ConsoleAsset.sol':{content:`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
contract ConsoleAsset is ERC20 { constructor() ERC20("Isolated console fixture", "FIX") {_mint(msg.sender, 1000000 ether);} }
`}});
  const node=await startNode(await freePort(),'market-console-node.log'),provider=node.provider;
  const [requester,worker,judge]=await Promise.all([0,1,2].map(i=>provider.getSigner(i)));
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'cannabis-market-console-')),journals=[],servers=[];
  const deploy=async(name,args=[])=>{const c=await new ContractFactory(artifacts[name].abi,artifacts[name].bytecode,requester).deploy(...args);await c.waitForDeployment();return c;};
  let proxy;
  try {
    const token=await deploy('ConsoleAsset'),native=await deploy('ComputeEscrow',[ZeroAddress,founder]);
    const cannabis=await deploy('ComputeEscrow',[await token.getAddress(),founder]);
    const market=await deploy('ComputeMarket',[await native.getAddress(),await cannabis.getAddress()]);
    const options={finalized:null,transform:null,holdReceipt:false};
    proxy=http.createServer(async(req,res)=>{
      try {
        const chunks=[];for await(const part of req)chunks.push(part);
        const message=JSON.parse(Buffer.concat(chunks));
        const one=async input=>{
          const query=structuredClone(input);
          if(query.method==='eth_getBlockByNumber'&&query.params[0]==='finalized'&&options.finalized!==null)query.params[0]='0x'+options.finalized.toString(16);
          const upstream=await fetch(node.rpc,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(query)});
          let response=await upstream.json();
          if(options.holdReceipt&&input.method==='eth_getTransactionReceipt')response={jsonrpc:'2.0',id:input.id,result:null};
          if(options.transform)response=await options.transform(input,response);
          return response;
        };
        const result=Array.isArray(message)?await Promise.all(message.map(one)):await one(message);
        res.setHeader('content-type','application/json');res.end(JSON.stringify(result));
      }catch{res.writeHead(500).end();}
    });
    await new Promise(resolve=>proxy.listen(0,'127.0.0.1',resolve));
    const configuration={schema:'cannabis.market-console.v1',rpc:'http://127.0.0.1:'+proxy.address().port,chainId:'31337',
      genesisHash:(await provider.getBlock(0)).hash,market:await market.getAddress(),marketCodeHash:keccak256(await provider.getCode(await market.getAddress())),
      nativeEscrow:await native.getAddress(),nativeEscrowCodeHash:keccak256(await provider.getCode(await native.getAddress())),
      cannabisEscrow:await cannabis.getAddress(),cannabisEscrowCodeHash:keccak256(await provider.getCode(await cannabis.getAddress())),
      token:await token.getAddress(),tokenCodeHash:keccak256(await provider.getCode(await token.getAddress())),founderRecipient:founder,
      maxFinalizedAgeSeconds:3600,maxHeadAgeSeconds:120,
      feeLimits:{gas:'2000000',maxFeePerGas:'100000000000',maxPriorityFeePerGas:'5000000000',maxTotalWei:'1000000000000000000'}};
    const makeConsole=(name,config=configuration,create=true)=>{
      const file=path.join(directory,name+'.sqlite');if(create)new MarketJournal(file,config,{create:true}).close();
      const console=new MarketConsole(config,file);journals.push(console);return console;
    };
    const buyer=makeConsole('requester'),seller=makeConsole('provider');
    const resource=()=>({schema:'cannabis.market-plan.v1',kind:'resource',provider:worker.address,resourceId:nonce(),serviceHash:nonce(),units:'2'});
    const offer=(resourcePlan,asset='ETH')=>{
      const now=Math.floor(Date.now()/1000),salt=nonce(),resource=prepareMarketPlan(configuration,resourcePlan).detail.resource;
      const offerId=keccak256(coder.encode(['address','bytes32'],[worker.address,salt]));
      return {schema:'cannabis.market-plan.v1',kind:'offer',provider:worker.address,nonce:salt,manifest:{
        schema:'cannabis.provider-manifest.v1',chainId:'31337',genesisHash:configuration.genesisHash,market:configuration.market,offerId,
        resource:{id:resource,provider:worker.address,serviceHash:resourcePlan.serviceHash,units:resourcePlan.units},
        offer:{resource,escrow:asset==='ETH'?configuration.nativeEscrow:configuration.cannabisEscrow,policyHash:nonce(),
          start:String(now+1000),end:String(now+2500),expiresAt:String(now+900),units:'1',grossPerUnitSecond:'100'},
        endpoints:[{role:'booking',origin:'https://isolated.invalid'},{role:'session',origin:'https://isolated.invalid'}],
        runtimes:[{adapter:'native-linux-x86_64-v1',architecture:'x86_64',os:'linux',digestSHA256:nonce(),tee:'snp',acceleratorClass:'cpu'}],
        terms:'Isolated workflow fixture. No hardware admission, live provider or real payment.'}};
    };
    const order=(offerPlan,asset='ETH')=>{
      const o=offerPlan.manifest.offer,start=Number(o.start),gross=10000n;
      return {schema:'cannabis.market-plan.v1',kind:'order',asset,
        job:{schema:'cannabis.compute.order.v2',id:'isolated-'+ ++sequence,requester:requester.address,packageSHA256:nonce().slice(2),
          policySHA256:o.policyHash.slice(2),acceptanceSHA256:nonce().slice(2),payment:{totalBudget:formatUnits(gross,18),feeBasisPoints:100,founderRecipient:founder}},
        settlement:{workers:[{account:worker.address,shareBps:10000}],deliveryManager:worker.address,adjudicator:judge.address,
          acceptBy:utc(start-300),deliverBy:utc(start+1500),reviewSeconds:86400,disputeSeconds:86400},
        bookings:[{reservationId:nonce(),offerId:offerPlan.manifest.offerId,start:String(start),end:String(start+100),units:'1',gross:String(gross),holdUntil:String(start-200)}]};
    };
    const httpConsole=async console=>{
      const observer=createObserver({cpu:'Isolated workflow fixture',graphics:[]}),server=createConsoleServer(observer,{market:console});
      await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));servers.push({server,observer});return 'http://127.0.0.1:'+server.address().port;
    };
    return {node,provider,requester,worker,judge,token,native,cannabis,market,configuration,options,buyer,seller,directory,
      makeConsole,resource,offer,order,httpConsole,async close(){
        for(const {server,observer}of servers){observer.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
        for(const console of journals)await console.close();proxy.closeAllConnections();await new Promise(resolve=>proxy.close(resolve));
        provider.destroy();node.child.kill();
        if(path.dirname(fs.realpathSync(directory))!==fs.realpathSync(os.tmpdir())||!path.basename(directory).startsWith('cannabis-market-console-'))
          throw Error('Refuse cleanup outside the owned temporary fixture directory');
        fs.rmSync(directory,{recursive:true,force:true});
      }};
  }catch(error){for(const console of journals)await console.close();proxy?.closeAllConnections();proxy?.close();provider.destroy();node.child.kill();throw error;}
}
