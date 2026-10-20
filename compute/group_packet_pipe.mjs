// Private pipes connect the protected TLS mesh to its owned TUN pump. These
// descriptors are created by the measured controller, never accepted from a host.
import {GuestGroupMesh,validateGroupPacket} from './group_mesh.mjs';
const failure=()=>Error('Protected group packet bridge failed');
const check=v=>{if(!v)throw failure();};
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});promise.catch(()=>{});return {promise,resolve,reject};};

export class GroupPacketPipe {
  #mesh;#maximum;#attached=deferred();#input;#output;#closed=false;#retiring=false;#queued=0;#failed;#reader;
  constructor(maxBufferedBytes) {
    check(Number.isInteger(maxBufferedBytes)&&maxBufferedBytes>=131072&&maxBufferedBytes<=8*1024*1024);
    this.#maximum=maxBufferedBytes;
  }
  // Kernel TCP teardown can still have packet writes in flight after every
  // application has completed. Only the authenticated all-rank barrier makes
  // those late pipe/mesh closures harmless.
  #fail(){if(!this.#closed&&!this.#retiring)this.#failed?.();}
  bind(mesh){check(!this.#mesh&&mesh instanceof GuestGroupMesh);this.#mesh=mesh;}
  metadata() {
    check(this.#mesh);this.#mesh.assertActive();const s=this.#mesh.status;
    return {schema:'cannabis.guest-group-network.v1',rank:s.rank,worldSize:s.worldSize,
      groupDigest:s.groupDigest,maxBufferedBytes:this.#maximum};
  }
  async receive(rank,packet) {
    check(!this.#closed&&this.#mesh);
    const s=this.#mesh.status;validateGroupPacket(packet,rank,s.rank,s.worldSize);
    if(this.#retiring)return;
    check(this.#queued+packet.length+4<=this.#maximum);this.#queued+=packet.length+4;
    try {
      await this.#attached.promise;check(!this.#closed);
      if(this.#retiring)return;
      const frame=Buffer.alloc(packet.length+4);frame.writeUInt32BE(packet.length);packet.copy(frame,4);
      try {await new Promise((resolve,reject)=>{
        let settled=false;const done=error=>{if(settled)return;settled=true;this.#input.off('close',closed);error?reject(failure()):resolve();};
        const closed=()=>done(failure());this.#input.once('close',closed);this.#input.write(frame,done);
      });} finally {frame.fill(0);}
    }catch(error){if(this.#retiring)return;this.#fail();throw failure();}finally{this.#queued-=packet.length+4;}
  }
  attach(input,output,failed) {
    check(!this.#input&&!this.#closed&&this.#mesh&&input?.writable&&output?.readable&&typeof failed==='function');
    this.metadata();this.#input=input;this.#output=output;this.#failed=failed;
    input.on('error',()=>this.#fail());output.on('error',()=>this.#fail());this.#attached.resolve();
    this.#reader=this.#read();this.#reader.catch(()=>this.#fail());
  }
  async #read() {
    let pending=Buffer.alloc(0);
    try {
      for await(const chunk of this.#output) {
        check(!this.#closed&&pending.length+chunk.length<=this.#maximum);
        const combined=Buffer.concat([pending,chunk]);pending.fill(0);pending=combined;
        while(pending.length>=4) {
          const length=pending.readUInt32BE();check(length>=20&&length<=1280);
          if(pending.length<length+4)break;
          const packet=Buffer.from(pending.subarray(4,length+4)),rest=Buffer.from(pending.subarray(length+4));
          pending.fill(0);pending=rest;
          try {const s=this.#mesh.status,rank=packet[19]-1;validateGroupPacket(packet,s.rank,rank,s.worldSize);
            if(!this.#retiring)await this.#mesh.sendPacket(rank,packet);
          } finally {packet.fill(0);}
        }
      }
      check(this.#retiring&&pending.length===0);
    } finally {pending.fill(0);}
  }
  async finish() {
    check(!this.#closed&&!this.#retiring);await this.#mesh.finish();
    this.#mesh.assertActive();this.#retiring=true;await this.#mesh.close();
  }
  async close() {
    if(this.#closed)return;
    this.#closed=true;this.#attached.reject(failure());
    this.#input?.destroy();this.#output?.destroy();
    if(this.#reader)await this.#reader.catch(()=>{});
    await this.#mesh?.close(this.#retiring?undefined:failure());
  }
}
