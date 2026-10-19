// Owned guest network checkpoint only. The private harness supplies a public
// fixture CA; the production operating entry never inherits this environment.
import fs from 'node:fs';
import https from 'node:https';
import {Resolver} from 'node:dns/promises';
import {isIP} from 'node:net';
import assert from 'node:assert/strict';
import {boundedDiscoveryRPC} from '../compute/discovery_rpc.mjs';
const config=JSON.parse(fs.readFileSync('/opt/cannabis/network-check.json','utf8'));
const checks={};
const resolver=new Resolver({timeout:2000,tries:2});resolver.setServers(['10.0.2.3']);
const addresses=await resolver.resolve4('example.com');assert.ok(addresses.length>0&&addresses.every(a=>isIP(a)===4));checks.dnsResolution=true;
const read=async(path='',port=config.tlsPort,timeoutMs=10000)=>{
  const transport=boundedDiscoveryRPC({timeoutMs});
  try {return await transport.getUrl({url:`https://10.0.2.2:${port}/${path}`,method:'POST',
    body:Buffer.from(JSON.stringify({jsonrpc:'2.0',id:1,method:'eth_chainId',params:[]}))});}
  finally{transport.close();}
};
const response=await read();assert.equal(JSON.parse(response.body).result,'0x7a69');checks.httpsRPCRead=true;
await assert.rejects(read('',config.untrustedPort));checks.untrustedCertificateRefused=true;
await assert.rejects(read('redirect'));checks.redirectRefused=true;
await assert.rejects(read('slow',config.tlsPort,150));checks.deadlineEnforced=true;
await assert.rejects(new Promise((resolve,reject)=>{
  const req=https.request({hostname:'10.0.2.2',port:config.tlsPort,servername:'wrong.invalid',path:'/',method:'POST',timeout:10000},resolve);
  req.on('error',reject);req.on('timeout',()=>req.destroy(Error('timeout')));req.end('{}');
}),error=>error.code==='ERR_TLS_CERT_ALTNAME_INVALID');checks.wrongTLSNameRefused=true;
console.log(JSON.stringify({schema:'cannabis.guest-network-rpc-check.v1',checks,isolatedRPCFixture:true,realChainObserved:false,
  hardwareValidated:false,customerKeysUsed:false,realPaidJob:false}));
