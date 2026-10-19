// Signed capacity offers and atomic local reservations. Funded leases share this inventory.
import { openDurableDatabase } from './sqlite_runtime.mjs';
import { getAddress, TypedDataEncoder, verifyTypedData, ZeroAddress } from 'ethers';

const hash = value => typeof value === 'string' && /^0x[0-9a-f]{64}$/.test(value) && value !== '0x'+'0'.repeat(64);
function address(value) { const a=getAddress(value); if (a===ZeroAddress) throw Error('Zero address'); return a; }
function number(value, max=Number.MAX_SAFE_INTEGER) { if (!Number.isSafeInteger(value) || value<1 || value>max) throw Error('Positive bounded integer required'); return value; }
function amount(value) { if (typeof value!=='string' || !/^[1-9][0-9]{0,77}$/.test(value) || BigInt(value)>=2n**256n) throw Error('Canonical positive uint256 amount required'); return BigInt(value); }
function exact(value, keys) { if (!value || typeof value!=='object' || Array.isArray(value) || Object.keys(value).sort().join()!==[...keys].sort().join()) throw Error('Unexpected or missing fields'); }
export const offerTypes={CapacityOffer:[
  ['offerId','bytes32'],['provider','address'],['resourceId','bytes32'],['serviceSHA256','bytes32'],['policySHA256','bytes32'],
  ['token','address'],['windowStart','uint64'],['windowEnd','uint64'],['expiresAt','uint64'],['units','uint32'],
  ['grossPerUnitSecond','uint256'],['feeBps','uint16'],['termsSHA256','bytes32']
].map(([name,type])=>({name,type}))};
export const reservationTypes={CapacityReservation:[
  ['reservationId','bytes32'],['offerDigest','bytes32'],['requester','address'],['jobSHA256','bytes32'],
  ['start','uint64'],['end','uint64'],['units','uint32'],['grossBaseUnits','uint256'],['holdUntil','uint64']
].map(([name,type])=>({name,type}))};
export function domain(context) {
  exact(context,['chainId','registryId','token']);number(context.chainId);if(!hash(context.registryId))throw Error('Registry ID must be a nonzero bytes32');getAddress(context.token);
  return {name:'Cannabis capacity commitments',version:'1',chainId:context.chainId,salt:context.registryId};
}
export function offerPayload(context,offer) {
  const d=domain(context);exact(offer,offerTypes.CapacityOffer.map(x=>x.name));
  for(const key of ['offerId','resourceId','serviceSHA256','policySHA256','termsSHA256'])if(!hash(offer[key]))throw Error('Invalid offer commitment');
  // Zero identifies native ETH only in the asset position; participant and
  // resource-owner addresses remain nonzero. The signed offer binds the asset.
  address(offer.provider);if(getAddress(offer.token)!==getAddress(context.token))throw Error('Token mismatch');
  for(const key of ['windowStart','windowEnd','expiresAt'])number(offer[key]);number(offer.units,100000);
  amount(offer.grossPerUnitSecond);if(offer.feeBps!==100)throw Error('The included founder fee must be 1%');
  if(offer.windowEnd<=offer.windowStart || offer.expiresAt>offer.windowEnd || offer.windowEnd-offer.windowStart>90*86400)throw Error('Invalid service window');
  return {domain:d,types:offerTypes,value:offer,digest:TypedDataEncoder.hash(d,offerTypes,offer)};
}
export function verifyOffer(context,signed,now=Math.floor(Date.now()/1000)) {
  exact(signed,['offer','signature']);const payload=offerPayload(context,signed.offer);
  if(signed.offer.expiresAt<=now || signed.offer.windowEnd<=now)throw Error('Expired capacity offer');
  if(verifyTypedData(payload.domain,payload.types,payload.value,signed.signature)!==address(signed.offer.provider))throw Error('Provider signature mismatch');
  return payload;
}
export function reservationPayload(context,reservation) {
  const d=domain(context);exact(reservation,reservationTypes.CapacityReservation.map(x=>x.name));
  for(const key of ['reservationId','offerDigest','jobSHA256'])if(!hash(reservation[key]))throw Error('Invalid reservation commitment');
  address(reservation.requester);for(const key of ['start','end','holdUntil'])number(reservation[key]);number(reservation.units,100000);amount(reservation.grossBaseUnits);
  if (BigInt(reservation.grossBaseUnits) % 100n !== 0n) throw Error('Reservation gross must be a multiple of 100 base units for an exact 1% fee');
  if(reservation.end<=reservation.start)throw Error('Invalid reservation interval');
  return {domain:d,types:reservationTypes,value:reservation,digest:TypedDataEncoder.hash(d,reservationTypes,reservation)};
}

export class CapacityLedger {
  constructor(file,context) {
    this.context=structuredClone(context);domain(context);
    this.db=openDurableDatabase(file,{timeout:5000});
    this.db.exec(`PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK(id=1), context TEXT NOT NULL) STRICT;
      CREATE TABLE IF NOT EXISTS resources (provider TEXT NOT NULL, resource TEXT NOT NULL, service TEXT NOT NULL, units INTEGER NOT NULL, PRIMARY KEY(provider,resource)) STRICT;
      CREATE TABLE IF NOT EXISTS offers (digest TEXT PRIMARY KEY, provider TEXT NOT NULL, resource TEXT NOT NULL, offerId TEXT NOT NULL, body TEXT NOT NULL, UNIQUE(provider,offerId)) STRICT;
      CREATE TABLE IF NOT EXISTS reservations (id TEXT PRIMARY KEY, offerDigest TEXT NOT NULL REFERENCES offers(digest), provider TEXT NOT NULL, resource TEXT NOT NULL, requester TEXT NOT NULL, start INTEGER NOT NULL, end INTEGER NOT NULL, units INTEGER NOT NULL, holdUntil INTEGER NOT NULL, body TEXT NOT NULL) STRICT;
      CREATE INDEX IF NOT EXISTS reservation_resource_time ON reservations(provider,resource,start,end,holdUntil);
      CREATE TABLE IF NOT EXISTS lease_bundles (id TEXT PRIMARY KEY, digest TEXT NOT NULL UNIQUE, escrow TEXT NOT NULL, orderId TEXT NOT NULL, body TEXT NOT NULL, UNIQUE(escrow,orderId)) STRICT;
      CREATE TABLE IF NOT EXISTS leased_reservations (reservationId TEXT PRIMARY KEY REFERENCES reservations(id), leaseId TEXT NOT NULL REFERENCES lease_bundles(id)) STRICT;`);
    try {
      this.transaction(()=>{
        const saved=this.db.prepare('SELECT context FROM settings WHERE id=1').get();
        const canonical=JSON.stringify({chainId:context.chainId,registryId:context.registryId,token:getAddress(context.token)});
        if(saved && saved.context!==canonical)throw Error('Ledger domain cannot change');
        if(!saved)this.db.prepare('INSERT INTO settings VALUES (1,?)').run(canonical);
      });
    } catch(error){this.db.close();throw error;}
  }
  close(){this.db.close();}
  transaction(fn){this.db.exec('BEGIN IMMEDIATE');try{const result=fn();this.db.exec('COMMIT');return result;}catch(error){this.db.exec('ROLLBACK');throw error;}}
  // Trusted local inventory admission. Signature validation alone cannot prove physical capacity.
  admitResource({provider,resourceId,serviceSHA256,units}) {
    provider=address(provider);if(!hash(resourceId)||!hash(serviceSHA256))throw Error('Invalid resource identity');number(units,100000);
    this.db.prepare('INSERT INTO resources VALUES (?,?,?,?)').run(provider,resourceId,serviceSHA256,units);
  }
  addOffer(signed,now) {
    const p=verifyOffer(this.context,signed,now),o=signed.offer;
    return this.transaction(()=>{
      const resource=this.db.prepare('SELECT * FROM resources WHERE provider=? AND resource=?').get(address(o.provider),o.resourceId);
      if(!resource || resource.service!==o.serviceSHA256 || o.units>resource.units)throw Error('Offer exceeds admitted resource or changes its service definition');
      this.db.prepare('INSERT INTO offers VALUES (?,?,?,?,?)').run(p.digest,address(o.provider),o.resourceId,o.offerId,JSON.stringify(signed));
      return {offerDigest:p.digest,capacityAttested:false,redemptionOperational:false};
    });
  }
  reserve(signed,now=Math.floor(Date.now()/1000)) {
    exact(signed,['reservation','requesterSignature','providerSignature']);const r=signed.reservation,p=reservationPayload(this.context,r);
    if(verifyTypedData(p.domain,p.types,p.value,signed.requesterSignature)!==address(r.requester))throw Error('Requester signature mismatch');
    return this.transaction(()=>{
      const row=this.db.prepare('SELECT body FROM offers WHERE digest=?').get(r.offerDigest);if(!row)throw Error('Unknown offer');
      const signedOffer=JSON.parse(row.body);verifyOffer(this.context,signedOffer,now);const o=signedOffer.offer;
      if(verifyTypedData(p.domain,p.types,p.value,signed.providerSignature)!==address(o.provider))throw Error('Provider reservation signature mismatch');
      if(r.start<now || r.start<o.windowStart || r.end>o.windowEnd || r.units>o.units)throw Error('Reservation outside offer');
      if(r.holdUntil<=now || r.holdUntil>now+1800 || r.holdUntil>r.start || r.holdUntil>o.expiresAt)throw Error('Pre-funding hold must expire within 30 minutes, before work and offer expiry');
      const price=BigInt(o.grossPerUnitSecond)*BigInt(r.end-r.start)*BigInt(r.units);
      if(price!==BigInt(r.grossBaseUnits))throw Error('Reservation price differs from signed quote');
      const capacity=this.db.prepare('SELECT units FROM resources WHERE provider=? AND resource=?').get(address(o.provider),o.resourceId).units;
      const rows=this.db.prepare(`SELECT r.start,r.end,r.units,r.offerDigest FROM reservations r
        WHERE r.provider=? AND r.resource=? AND (r.holdUntil>? OR EXISTS(SELECT 1 FROM leased_reservations l WHERE l.reservationId=r.id)) AND r.start<? AND r.end>?`)
        .all(address(o.provider),o.resourceId,now,r.end,r.start);
      // Sweep intersecting intervals, with releases before acquisitions at the same instant.
      for(const [selected,limit,label] of [[rows,capacity,'Capacity'],[rows.filter(p=>p.offerDigest===r.offerDigest),o.units,'Offer capacity']]) {
        const events=[[r.start,r.units],[r.end,-r.units]];
        for(const prior of selected)events.push([Math.max(r.start,prior.start),prior.units],[Math.min(r.end,prior.end),-prior.units]);
        events.sort((a,b)=>a[0]-b[0]||a[1]-b[1]);let active=0;
        for(const [,delta] of events){active+=delta;if(active>limit)throw Error(label+' already reserved');}
      }
      this.db.prepare('INSERT INTO reservations VALUES (?,?,?,?,?,?,?,?,?,?)').run(r.reservationId,r.offerDigest,address(o.provider),o.resourceId,address(r.requester),r.start,r.end,r.units,r.holdUntil,JSON.stringify(signed));
      return {reservationId:r.reservationId,reservationDigest:p.digest,holdUntil:r.holdUntil,grossBaseUnits:r.grossBaseUnits,
        executionAuthorized:false,keyReleaseAuthorized:false,paymentAuthorized:false,
        note:'Local pre-funding hold only. Finalized escrow, fresh attestation and durable operational lease promotion are required before work.'};
    });
  }
}
