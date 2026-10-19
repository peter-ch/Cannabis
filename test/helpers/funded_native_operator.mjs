// Owned kernel integration only. Separate ordinary operator process with public
// launch data, local storage and opaque channels. No requester custody is passed.
import fs from 'node:fs';
import { Socket } from 'node:net';
import { GuestWire } from '../../compute/result_transport.mjs';
import { prepareGuestLaunch } from '../../compute/guest_launch.mjs';
import { relayConfiguredSession } from '../../operator/session-relay.mjs';
import { createWorkServer } from '../../service/work-server.mjs';
let guest,requester,server;
try {
  let raw='';for await(const part of process.stdin){raw+=part;if(raw.length>262144)throw Error('Fixture configuration bound');}
  const c=JSON.parse(raw),p=c.public,launch=prepareGuestLaunch(p.authorities,p.signedConfiguration,p.initialization,p.request);
  const opened=createWorkServer({file:':memory:',resultFile:':memory:',origin:c.origin});server=opened.server;
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(new URL(c.origin).port,'127.0.0.1',resolve);});
  const wire=(read,write)=>new GuestWire(new Socket({fd:read,readable:true,writable:false}),
    new Socket({fd:write,readable:false,writable:true}),{timeoutMs:launch.transport.timeoutMs});
  guest=wire(c.fds.guestRead,c.fds.guestWrite);requester=wire(c.fds.requesterRead,c.fds.requesterWrite);
  const report=await relayConfiguredSession(guest,requester,{launch,origin:c.origin,spoolDirectory:c.spool,
    reserveResult:({approvalDigest,maxCiphertextBytes,serviceEnd},signal)=>{
      if(signal.aborted)throw Error('Cancelled reservation');
      const {uploadToken,readToken,...access}=opened.relay.reserve({approvalDigest,maxCiphertextBytes,expiresAt:serviceEnd*1000});
      return {upload:{...access,origin:c.origin,role:'upload',token:uploadToken},
        read:{...access,origin:c.origin,role:'read',token:readToken}};
    }});
  fs.writeFileSync(c.report,JSON.stringify(report),{flag:'wx',mode:0o600});
}catch{process.stderr.write('Owned whole-session operator fixture failed\n');process.exitCode=1;}
finally {
  guest?.fail();guest?.close();requester?.fail();requester?.close();
  if(server){server.closeAllConnections();await new Promise(r=>server.close(r));}
}
