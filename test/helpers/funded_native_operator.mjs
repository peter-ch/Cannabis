// Owned kernel integration only. Separate ordinary operator process with public
// launch data, local storage and opaque channels. No requester custody is passed.
import fs from 'node:fs';
import path from 'node:path';
import { Socket } from 'node:net';
import { performance } from 'node:perf_hooks';
import { GuestWire } from '../../compute/result_transport.mjs';
import { prepareGuestLaunch } from '../../compute/guest_launch.mjs';
import { relayAuthenticatedSession } from '../../operator/session-relay.mjs';
import { createWorkServer } from '../../service/work-server.mjs';
import { listenBookedPeers } from '../../compute/peer_network.mjs';
import { PeerDispatchJournal } from '../../compute/peer_dispatch.mjs';
import { localProvider } from '../../scripts/lib.mjs';
import tlsFixture from '../../test/helpers/peer-tls-fixture.json' with {type:'json'};
import { ResultSpool } from '../../operator/result-spool.mjs';
let guest,control,server,listener,provider,completionTimer,dispatchJournal,spool;
try {
  let raw='';for await(const part of process.stdin){raw+=part;if(raw.length>262144)throw Error('Fixture configuration bound');}
  const started=performance.now(),wallStart=Date.now();
  const c=JSON.parse(raw),p=c.public,launch=await prepareGuestLaunch(p.signedConfiguration,p.initialization,p.request);
  const remaining=()=>Math.floor(Math.min(launch.transport.timeoutMs-(performance.now()-started),launch.transport.timeoutMs-(Date.now()-wallStart)));
  const opened=createWorkServer({file:':memory:',resultFile:':memory:',origin:c.origin});server=opened.server;
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(new URL(c.origin).port,'127.0.0.1',resolve);});
  const wire=(read,write)=>new GuestWire(new Socket({fd:read,readable:true,writable:false}),
    new Socket({fd:write,readable:false,writable:true}),{timeoutMs:remaining()});
  guest=wire(c.fds.guestRead,c.fds.guestWrite);control=wire(c.fds.requesterRead,c.fds.requesterWrite);
  // Only this isolated fixture uses the loopback node's disposable signer.
  // localProvider refuses any public RPC or chain other than 31337.
  provider=await localProvider(p.signedConfiguration.configuration.network.rpc);
  const signer=await provider.getSigner(p.signedConfiguration.configuration.provider);
  let resolve,reject;const completed=new Promise((yes,no)=>{resolve=yes;reject=no;});completed.catch(()=>{});
  completionTimer=setTimeout(()=>reject(Error('Owned peer workflow expired')),Math.max(1,remaining()));
  spool=new ResultSpool(c.spool,{create:true});
  const journalFile=path.join(path.dirname(c.spool),'dispatch.sqlite');
  dispatchJournal=new PeerDispatchJournal(journalFile,{create:true});
  listener=await listenBookedPeers({origin:'https://localhost:0',listenHost:'127.0.0.1',
    dispatchJournal,
    tlsCredentials:{key:tlsFixture.key,cert:tlsFixture.cert},maxConnections:2,maxHandshakes:1,
    timeoutMs:Math.min(60000,remaining()),routes:[{signed:p.signedConfiguration,initialization:p.initialization,proof:p.request.proof,
      signApproval:q=>signer.signTypedData(q.domain,q.types,q.value),handle:async(requester,local)=>{
        try {
          const report=await relayAuthenticatedSession(guest,requester,{launch,origin:c.origin,spool,
    reserveResult:({approvalDigest,maxCiphertextBytes,serviceEnd},signal)=>{
      if(signal.aborted)throw Error('Cancelled reservation');
      const {uploadToken,readToken,...access}=opened.relay.reserve({approvalDigest,maxCiphertextBytes,expiresAt:serviceEnd*1000});
      return {upload:{...access,origin:c.origin,role:'upload',token:uploadToken},
        read:{...access,origin:c.origin,role:'read',token:readToken}};
    }});
          resolve({...report,bookedTLSPeerAuthenticated:requester.report.channelAuthenticated,
            peerAssignmentSHA256:requester.report.assignmentSHA256,peerRouteId:local.routeId});
        }catch(e){reject(e);throw e;}
      }}]});
  await control.writeJSON({protocol:'cannabis.owned-peer-ready.v1',origin:listener.origin});control.fail();control.close();
  const report=await completed,closed=await listener.close();
  if(closed.pendingTasks||closed.liveSockets)throw Error('Owned listener did not finish cleanup');
  report.peerListenerDisposed=true;
  spool.close();spool=new ResultSpool(c.spool);
  if(spool.status(report.spoolReservationId).state!=='acknowledged'||
    spool.recover(report.spoolReservationId).sourceFile!==report.sourceFile)throw Error('Local reservation or recovery record lost');
  report.localSpoolReservationRetained=true;
  dispatchJournal.close();dispatchJournal=new PeerDispatchJournal(journalFile);
  if(!['consumed','completed','failed'].includes(dispatchJournal.status(report.peerRouteId)?.state))throw Error('Dispatch marker lost');
  let refused=false;try{dispatchJournal.consume(report.peerRouteId,launch.interval.end*1000);}catch{refused=true;}
  if(!refused)throw Error('Consumed assignment reopened after restart');
  report.durableDispatchRetained=true;report.restartedDispatchRefused=true;
  fs.writeFileSync(c.report,JSON.stringify(report),{flag:'wx',mode:0o600});
}catch{process.stderr.write('Owned whole-session operator fixture failed\n');process.exitCode=1;}
finally {
  clearTimeout(completionTimer);guest?.fail();guest?.close();control?.fail();control?.close();await listener?.close();provider?.destroy();
  dispatchJournal?.close();spool?.close();
  if(server){server.closeAllConnections();await new Promise(r=>server.close(r));}
}
