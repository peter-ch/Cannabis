// Fresh requester process for one owned integration. It has only retained
// requester custody, inbox and explicit replacement read access: no peer launch.
// Chain/signers are disposable loopback fixtures. Never run with public custody.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {localProvider} from '../../scripts/lib.mjs';
import {ResultInbox} from '../../compute/result_inbox.mjs';
import {recoverRequesterResultKey} from '../../compute/result_keys.mjs';
import {receiveHostedResult} from '../../requester/hosted-result.mjs';

const input=JSON.parse(fs.readFileSync(0,'utf8')),provider=await localProvider(input.rpc);
let inbox;
try {
  const requester=await provider.getSigner(input.context.requester);
  assert.equal(await requester.getAddress(),input.context.requester);
  assert.notEqual(input.originalOrigin,input.origin);
  // The old route is actually stopped, not merely omitted from a fake response.
  await assert.rejects(fetch(input.originalOrigin+'/api/work/results/'+input.access.id+'/manifest',
    {signal:AbortSignal.timeout(1000)}));
  inbox=new ResultInbox(input.inbox,input.context);
  const loadResultKey=expected=>recoverRequesterResultKey(input.resultSource,expected);
  let cancelledChunkObserved=false;
  async function retrieve(destination,{cancel=false}={}) {
    const controller=new AbortController();let read=false,signature,chunkRequested=false;
    const wire={signal:controller.signal,assertActive:()=>assert.equal(controller.signal.aborted,false),
      fail:()=>controller.abort(),readJSON:async()=>{assert.equal(read,false);read=true;return input.header;},
      writeJSON:async ack=>{signature=ack.signature;}};
    const result=await receiveHostedResult(wire,{inbox,approvalDigest:input.approvalDigest,loadResultKey,
      destination,maxCiphertextBytes:4*1024*1024,origin:input.origin,access:input.access,timeoutMs:10000,
      signStored:async p=>{
        assert.equal(cancel,false,'Cancelled retrieval must never request a storage signature');
        return requester.signTypedData(p.domain,p.types,p.value);
      },
      fetchImpl:async(url,options)=>{
        const response=await fetch(url,options);
        if(cancel&&url.endsWith('/chunks/0')){
          assert.equal(response.status,200);chunkRequested=true;cancelledChunkObserved=true;controller.abort();
        }
        return response;
      }});
    assert.equal(chunkRequested,false);
    return {result,signature};
  }
  const cancelled=input.destination+'.cancelled';
  await assert.rejects(retrieve(cancelled,{cancel:true}));
  assert.equal(cancelledChunkObserved,true);
  assert.equal(fs.existsSync(cancelled),false);
  const {result,signature}=await retrieve(input.destination);
  assert.equal(result.storageAcknowledged,true);assert.equal(result.paymentAuthorized,false);
  assert.equal(typeof signature,'string');
  const recovered=await inbox.recover(input.approvalDigest,loadResultKey);
  assert.equal(recovered.receipt.ciphertextSHA256,input.header.ciphertextSHA256);
  process.stdout.write(JSON.stringify({cancelledRetrievalRefused:true,cancelledFileRemoved:true,
    recovered:true,paymentAuthorized:false,signature,executionRetried:false}));
} catch(error) {
  process.stderr.write('Owned replacement recovery failed: '+error.stack+'\n');process.exitCode=1;
} finally {inbox?.close();provider.destroy();}
