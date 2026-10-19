// Booked requester/provider consent; no universal launch signer.
// These functions prepare/inspect commitments only; chain admission is separate.
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { TypedDataEncoder, getAddress, verifyTypedData } from 'ethers';
import { validateGuestConfiguration } from './guest_configuration.mjs';
import { guestInitialization } from './guest_initialization.mjs';
import { configuredMarketAttestationBinding } from './attestation.mjs';
import { verifyMarketLeaseProof, readMarketLeaseState } from './market_lease.mjs';
import { nativeServiceCommitment } from './guest_execution.mjs';

const fail=()=>{throw Error('Booked guest launch consent differs from the approved assignment');};
const exact=(v,fields)=>{if(!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).sort().join()!==[...fields].sort().join())fail();};
const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':
  v&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
const hash=v=>'0x'+createHash('sha256').update(v).digest('hex');
const roles={requester:0,provider:1};
export const launchConsentTypes=Object.freeze({BookedGuestLaunch:Object.freeze([
  ['role','uint8'],['configurationSHA256','bytes32'],['assignmentSHA256','bytes32'],
  ['leaseDigest','bytes32'],['bookingId','bytes32'],['requester','address'],['provider','address'],
  ['validFrom','uint64'],['validUntil','uint64']
].map(([name,type])=>Object.freeze({name,type})))});

function describe(configuration,initialization,proof) {
  const checked=validateGuestConfiguration(configuration),c=checked.configuration;
  if(c.schema!=='cannabis.guest-launch-configuration.v3')fail();
  const retained=guestInitialization(initialization),a=retained.assignment,b=a.binding;
  if(a.schema!=='cannabis.guest-initialization.v2'||a.tee!==c.attestationPolicyTemplate.tee||
    b.configurationSHA256!==checked.configurationSHA256)fail();
  const lease=verifyMarketLeaseProof(proof,c.context),r=lease.reservations.find(r=>r.reservationId===b.reservationId);
  if(!r||a.requester!==lease.requester||a.jobId!==lease.job.id||getAddress(c.provider)!==r.provider||
    c.resourceId!==r.resourceId||getAddress(c.network.escrow)!==lease.escrow||
    c.validFrom>r.start||c.validUntil<r.end||c.execution.profile.runtime.digestSHA256!==b.runtimeSHA256)fail();
  const service=nativeServiceCommitment(c.execution);
  if(service.serviceSHA256!==r.serviceSHA256||service.units!==r.units)fail();
  const run=Object.fromEntries(['runtimeSHA256','taskSHA256','attempt','rank','worldSize','acceleratorClass'].map(k=>[k,b[k]]));
  // Offline preparation is allowed before service starts; it never authorizes a
  // launch. Actual consent verification requires the live reserved interval.
  const expected=configuredMarketAttestationBinding(proof,c.context,r.reservationId,run,checked.configurationSHA256,r.start);
  if(canonical(expected)!==canonical(b))fail();
  return {...checked,initialization:retained.assignment,assignmentSHA256:hash(retained.canonical),
    initializationDigest:retained.digest,lease,reservation:r};
}

function payload(description,role) {
  if(!Object.hasOwn(roles,role))fail();
  const d=description,c=d.configuration,r=d.reservation;
  const domain={name:'Cannabis booked guest launch',version:'1',chainId:c.context.chainId,verifyingContract:getAddress(c.context.market)};
  const value={role:roles[role],configurationSHA256:d.configurationSHA256,assignmentSHA256:d.assignmentSHA256,
    leaseDigest:d.lease.digest,bookingId:r.reservationId,requester:d.lease.requester,provider:r.provider,
    validFrom:r.start,validUntil:r.end};
  return {domain,types:launchConsentTypes,value,digest:TypedDataEncoder.hash(domain,launchConsentTypes,value)};
}

export function launchConsentPayload(configuration,initialization,proof,role) {
  const d=describe(configuration,initialization,proof);
  return {...payload(d,role),signer:role==='requester'?d.lease.requester:d.reservation.provider,
    executionAuthorized:false,keyReleaseAuthorized:false,chainVerified:false};
}

// Validate the exact envelope and the requester's EOA signature. Provider wallet
// validity (EOA or ERC-1271) and canonical booking/funding must still be checked
// at fresh hash-bound chain observations before this can authorize anything.
export function inspectLaunchConsent(signed,initialization,proof,now=Math.floor(Date.now()/1000)) {
  signed=structuredClone(signed);exact(signed,['schema','configuration','consents']);
  if(signed.schema!=='cannabis.guest-launch-consent.v1'||Buffer.byteLength(canonical(signed))>256*1024||
    !Array.isArray(signed.consents)||signed.consents.length!==2)fail();
  const d=describe(signed.configuration,initialization,proof),r=d.reservation;
  if(!Number.isSafeInteger(now)||now<r.start||now>=r.end)fail();
  const approvals=[];
  for(const [i,role] of ['requester','provider'].entries()) {
    const entry=signed.consents[i];exact(entry,['role','signer','signature']);
    const signer=role==='requester'?d.lease.requester:r.provider;
    if(entry.role!==role||entry.signer!==signer||typeof entry.signature!=='string'||
      !/^0x(?:[0-9a-fA-F]{2}){1,8192}$/.test(entry.signature))fail();
    const p=payload(d,role);
    if(role==='requester'&&verifyTypedData(p.domain,p.types,p.value,entry.signature)!==signer)fail();
    approvals.push({role,signer,digest:p.digest,signature:entry.signature});
  }
  return {...d,approvals,executionAuthorized:false,keyReleaseAuthorized:false,chainVerified:false};
}

// Independently observe consent against the exact reviewed network and booking.
// RPC-reported canonicality/finality is not local consensus or runtime admission.
export async function readLaunchConsentState(signed,initialization,proof,{clock=()=>Math.floor(Date.now()/1000)}={}) {
  const started=clock(),checked=inspectLaunchConsent(signed,initialization,proof,started),r=checked.reservation;
  const end=performance.now()+(r.end-started)*1000;
  let last=started;
  const activeClock=()=>{
    const now=clock();
    if(!Number.isSafeInteger(now)||now<last||now<r.start||now>=r.end||performance.now()>=end)fail();
    last=now;return now;
  };
  activeClock();
  const funding=await readMarketLeaseState(checked.lease.proof,checked.configuration.network,activeClock,{launchApprovals:checked.approvals});
  activeClock();
  if(funding.headBlock.timestamp<r.start||funding.headBlock.timestamp>=r.end)fail();
  return {schema:'cannabis.guest-launch-consent-state.v1',configurationSHA256:checked.configurationSHA256,
    assignmentSHA256:checked.assignmentSHA256,initializationDigest:checked.initializationDigest,
    leaseDigest:checked.lease.digest,bookingId:r.reservationId,requester:checked.lease.requester,provider:r.provider,
    funding,executionAuthorized:false,keyReleaseAuthorized:false,hardwareVerified:false};
}
