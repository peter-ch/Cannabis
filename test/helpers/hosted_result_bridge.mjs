// Disposable operator-process fixture. Public approval, upload capability and
// encrypted stream only; this is not a production launcher or TEE admission.
import fs from 'node:fs';
import net from 'node:net';
import { once } from 'node:events';
import { GuestWire } from '../../compute/result_transport.mjs';
import { bridgeEncryptedResult } from '../../operator/result-bridge.mjs';
import { ResultSpool } from '../../operator/result-spool.mjs';
let guest,requester,socket,spool;
try {
  const config=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
  socket=net.connect({host:'127.0.0.1',port:config.requesterPort});await once(socket,'connect');
  guest=new GuestWire(process.stdin,process.stdout,{timeoutMs:5000});
  requester=new GuestWire(socket,socket,{timeoutMs:5000});
  spool=new ResultSpool(config.spoolDirectory,{create:true});
  const reservation=spool.reserve({expected:config.bridge.expected,maxCiphertextBytes:config.bridge.maxCiphertextBytes,serviceEnd:Math.floor(Date.now()/1000)+60});
  spool.dispatch(reservation);
  const result=await bridgeEncryptedResult(guest,requester,{...config.bridge,reservation});
  fs.writeFileSync(config.report,JSON.stringify(result),{flag:'wx',mode:0o600});
}catch{process.stderr.write('Owned operator bridge fixture failed\n');process.exitCode=1;}
finally{guest?.fail();guest?.close();requester?.fail();requester?.close();socket?.destroy();spool?.close();}
