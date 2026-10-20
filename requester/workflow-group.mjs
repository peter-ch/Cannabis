// Requester-owned rendezvous for one already-booked complete task attempt.
// Unknown outcomes stay consumed in WorkflowStore; this class never retries.
import {webcrypto} from 'node:crypto';
import {groupAdmissionPayload,verifyGroupAdmission,GROUP_SCHEMA} from '../compute/group_admission.mjs';
import {RequesterGroupReadiness} from '../compute/group_mesh.mjs';
import {prepareGuestGroup,connectGuestGroup,startGuestGroup} from '../compute/group_transport.mjs';
const check=v=>{if(!v)throw Error('Requester protected group is incomplete or cancelled');};
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});promise.catch(()=>{});return {promise,resolve,reject};};
export class WorkflowGroup {
  #proof;#network;#assignments;#clock;#sign;#save;#entries=new Map();#result=deferred();#abort=new AbortController();
  #signal;#external;#closed=false;#started=false;
  constructor({proof,network,assignments,clock,sign,save,signal}) {
    check(assignments.length>=2&&assignments.length<=64&&assignments.every((a,i)=>a.initialization.binding.rank===i&&
      a.initialization.binding.worldSize===assignments.length&&a.task===assignments[0].task));
    this.#proof=structuredClone(proof);this.#network=structuredClone(network);this.#assignments=structuredClone(assignments);
    this.#clock=clock;this.#sign=sign;this.#save=save;this.#signal=signal;this.#external=()=>this.abort();
    signal?.addEventListener('abort',this.#external,{once:true});if(signal?.aborted)this.abort();
  }
  get signal(){return this.#abort.signal;}
  #active(){check(!this.#closed&&!this.signal.aborted);}
  join(rank,{channel,challenge,evidence,appraisal}) {
    this.#active();check(Number.isInteger(rank)&&rank>=0&&rank<this.#assignments.length&&!this.#entries.has(rank)&&!this.#started);
    this.#entries.set(rank,{channel,challenge:structuredClone(challenge),evidence:structuredClone(evidence),appraisal:structuredClone(appraisal)});
    if(this.#entries.size===this.#assignments.length) {
      this.#started=true;this.#assemble().then(result=>this.#result.resolve(result),()=>this.abort());
    }
    return this.#result.promise;
  }
  async #assemble() {
    let reviewer;
    try {
      this.#active();const entries=this.#assignments.map((_,rank)=>this.#entries.get(rank));
      const pair=await webcrypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
      const requesterChannelJwk=await webcrypto.subtle.exportKey('jwk',pair.publicKey);
      // Public JWK exports include key_ops/ext. The wire deliberately exposes
      // only the same exact four P-256 coordinates as guest attestation.
      const publicKey=Object.fromEntries(['kty','crv','x','y'].map(k=>[k,requesterChannelJwk[k]]));
      const issuedAt=this.#clock(),expiresAt=Math.min(issuedAt+120,...entries.map(e=>Math.min(e.challenge.expiresAt,e.appraisal.appraisal.expiresAt)),
        ...this.#assignments.map(a=>a.description.reservation.end));
      check(expiresAt>issuedAt);
      const group={schema:GROUP_SCHEMA,task:this.#assignments[0].task,issuedAt,expiresAt,requesterChannelJwk:publicKey,
        peers:this.#assignments.map((a,rank)=>({signed:a.signed,initialization:a.initialization,challenge:entries[rank].challenge,
          channelJwk:entries[rank].evidence.channelJwk,appraisal:entries[rank].appraisal.token,endpoint:a.groupEndpoint}))};
      const payload=await groupAdmissionPayload(this.#proof,this.#network,group,{clock:this.#clock});
      const requesterSignature=await this.#sign('group',payload,expiresAt,this.signal);this.#active();
      const approval={schema:'cannabis.protected-group-approval.v1',group,requesterSignature};
      const admission=await verifyGroupAdmission(this.#proof,this.#network,approval,{clock:this.#clock});
      this.#save('approval',approval);this.#active();
      reviewer=await RequesterGroupReadiness.create(admission,pair.privateKey);
      const bindings=entries.map((_,rank)=>({groupDigest:admission.groupDigest,rank,worldSize:entries.length}));
      // Every listener is established before anyone initiates a connection.
      await Promise.all(entries.map((e,rank)=>prepareGuestGroup(e.channel,approval,bindings[rank])));this.#active();
      const readiness=await Promise.all(entries.map((e,rank)=>connectGuestGroup(e.channel,bindings[rank])));this.#active();
      const startPayload=reviewer.review(readiness);this.#save('readiness',readiness);
      const startSignature=await this.#sign('group-start',startPayload,expiresAt,this.signal);this.#active();
      // A fresh MAC/window check after wallet review prevents stale readiness.
      reviewer.review(readiness);
      const start={schema:'cannabis.protected-group-start.v1',readiness,payload:startPayload,requesterSignature:startSignature};
      this.#save('start',start);
      await Promise.all(entries.map((e,rank)=>startGuestGroup(e.channel,start,bindings[rank])));this.#active();
      return {admission,bundle:{approval,start}};
    }finally{reviewer?.close();}
  }
  abort() {
    if(this.signal.aborted)return;
    this.#abort.abort();this.#result.reject(Error('Protected group stopped; retain all rank recovery material'));
    for(const e of this.#entries.values())e.channel.fail();
  }
  close(){if(this.#closed)return;this.#closed=true;this.#signal?.removeEventListener('abort',this.#external);this.abort();}
}
