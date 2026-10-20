// Public disposable certificate/key, bound exclusively to loopback tests.
import { createServer, connect } from 'node:tls';
import { once } from 'node:events';
import fixture from './peer-tls-fixture.json' with {type:'json'};
import { peerALPN } from '../../compute/peer_channel.mjs';
export async function peerTLSPair(t,{version='TLSv1.3',alpn=peerALPN,trusted=true}={}) {
  const connections=new Set(),server=createServer({key:fixture.key,cert:fixture.cert,
    minVersion:version,maxVersion:version,ALPNProtocols:[alpn]},socket=>connections.add(socket));
  server.on('tlsClientError',()=>{});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const accepted=once(server,'secureConnection'),port=server.address().port;
  const requester=connect({host:'127.0.0.1',port,servername:'localhost',ca:trusted?fixture.cert:[],
    rejectUnauthorized:trusted,minVersion:version,maxVersion:version,ALPNProtocols:[alpn]});
  const release=()=>{requester.destroy();for(const s of connections)s.destroy();};
  t.after(async()=>{release();await new Promise(resolve=>server.close(resolve));});
  await once(requester,'secureConnect');const [provider]=await accepted;
  return {requester,provider,origin:`https://localhost:${port}`,release};
}
