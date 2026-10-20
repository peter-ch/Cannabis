// Fresh funding observation inside the guest. Not hardware/runtime admission.
import { getAddress } from 'ethers';
import { performance } from 'node:perf_hooks';
import { verifyLeaseProof } from './lease_proof.mjs';
import { verifyMarketLeaseProof, readMarketLeaseState } from './market_lease.mjs';
import { guestInitialization } from './guest_initialization.mjs';
import { readFinalizedEscrow, readCurrentEscrow, readFundedEscrowAtAnchor } from './finality.mjs';
import { inspectLaunchConsent } from './guest_consent.mjs';
import { inspectGroupAdmission } from './group_admission.mjs';

const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':
  v&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);

export class GuestFunding {
  #lease; #reservation; #network; #clock; #last; #end; #market; #approvals; #groupApprovals; #closed = false; #busy = false;
  constructor(options, initialization, { clock = () => Math.floor(Date.now() / 1000) } = {}) {
    // All configuration except proof is independently approved measured-guest
    // configuration. A host may transport it, but must not choose its pins/RPC.
    options = structuredClone(options);
    const assignment = guestInitialization(initialization).assignment, b = assignment.binding;
    const configured=assignment.schema==='cannabis.guest-initialization.v2';
    const keys = ['proof', 'context', 'network', 'provider', 'resourceId', 'serviceSHA256',...(configured?['consent']:[])];
    if (!options || Object.keys(options).sort().join() !== keys.sort().join()) throw Error('Require approved guest funding configuration');
    this.#market = ['cannabis.market-lease.v1','cannabis.market-lease.v2'].includes(options.proof?.schema);
    const lease = this.#market ? verifyMarketLeaseProof(options.proof, options.context) : verifyLeaseProof(options.proof, options.context);
    if(lease.executionPlan&&!configured)throw Error('Planned funding requires jointly approved guest configuration');
    const reservation = lease.reservations.find(r => r.reservationId === b.reservationId);
    if (options.context.chainId !== b.chainId || lease.digest !== b.leaseDigest || lease.orderId !== b.orderId ||
        lease.escrow !== b.escrow || lease.requester !== assignment.requester || lease.job.id !== assignment.jobId ||
        lease.job.packageSHA256 !== b.packageSHA256 || lease.job.policySHA256 !== b.policySHA256 || !reservation ||
        reservation.provider !== getAddress(options.provider) || reservation.resourceId !== options.resourceId ||
        reservation.serviceSHA256 !== options.serviceSHA256) throw Error('Signed lease differs from retained guest assignment or approved resource');
    const network = options.network;
    if (BigInt(network.chainId) !== BigInt(b.chainId) || getAddress(network.escrow) !== b.escrow ||
        getAddress(network.token) !== getAddress(options.context.token) ||
        this.#market && getAddress(network.market) !== lease.market) throw Error('Guest funding network differs from approved capacity domain');
    this.#lease = lease; this.#reservation = reservation; this.#network = network; this.#clock = clock;
    const now = clock();
    if (!Number.isSafeInteger(now) || now < 1) throw Error('Invalid guest clock');
    if(configured) {
      const checked=inspectLaunchConsent(options.consent,assignment,options.proof,now),c=checked.configuration;
      if(!this.#market||canonical(c.network)!==canonical(network)||canonical(c.context)!==canonical(options.context)||
        getAddress(c.provider)!==getAddress(options.provider)||c.resourceId!==options.resourceId||
        checked.lease.digest!==lease.digest||checked.reservation.reservationId!==reservation.reservationId)
        throw Error('Guest funding differs from the jointly approved launch configuration');
      this.#approvals=checked.approvals;
    }
    this.#last = now;
    // Never restart the service interval on a later helper, refresh or key open.
    this.#end = performance.now() + Math.max(0, reservation.end - now) * 1000;
  }
  get interval() { return { start: this.#reservation.start, end: this.#reservation.end }; }
  bindGroup(admission) {
    this.assertWindow();
    const d=inspectGroupAdmission(admission);
    if(this.#groupApprovals||!this.#market||d.leaseDigest!==this.#lease.digest||
      !d.peers.some(p=>p.reservationId===this.#reservation.reservationId))throw Error('Group differs from retained funding');
    this.#groupApprovals=d.group.peers.filter(p=>p.initialization.binding.reservationId!==this.#reservation.reservationId)
      .map(p=>inspectLaunchConsent(p.signed,p.initialization,this.#lease.proof,this.#clock()).approvals);
  }
  assertService({ serviceSHA256, units }) {
    this.assertWindow();
    if (serviceSHA256 !== this.#reservation.serviceSHA256 || !Number.isSafeInteger(units) || units !== this.#reservation.units) {
      this.close(); throw Error('Execution profile differs from the signed service or unit count');
    }
  }
  close() { this.#closed = true; }
  assertWindow() {
    const now = this.#clock(), r = this.#reservation;
    if (this.#closed || !Number.isSafeInteger(now) || now < this.#last || now < r.start || now >= r.end || performance.now() >= this.#end) {
      this.close(); throw Error('Guest service interval is closed, not started or expired');
    }
    this.#last = now; return now;
  }
  remainingMilliseconds() {
    const now = this.assertWindow();
    return Math.max(0, Math.floor(Math.min(this.#end - performance.now(), (this.#reservation.end - now) * 1000)));
  }
  #active(snapshot) {
    if (snapshot.termsDigest !== this.#lease.termsDigest || snapshot.requester !== this.#lease.requester ||
        snapshot.orderId !== this.#lease.orderId || snapshot.state !== 2 || snapshot.acceptedCount !== this.#lease.providers.length ||
        BigInt(snapshot.acceptedBitmap) !== (1n << BigInt(this.#lease.providers.length)) - 1n) throw Error('Guest funding must match the signed, fully accepted active order');
  }
  async refresh() {
    if (this.#busy) throw Error('Guest funding inspection already in progress');
    this.#busy = true;
    try {
      this.assertWindow();
      if (this.#market) {
        const state = await readMarketLeaseState(this.#lease.proof, this.#network, () => this.assertWindow(),
          this.#approvals?{launchApprovals:this.#approvals}:{});
        // Each rank independently checks every booked peer's signatures against
        // current chain state. Four bounded readers avoid unbounded RPC fanout.
        if(this.#groupApprovals) {
          let next=0;
          await Promise.all(Array.from({length:Math.min(4,this.#groupApprovals.length)},async()=>{
            while(next<this.#groupApprovals.length) {
              const approvals=this.#groupApprovals[next++];
              await readMarketLeaseState(this.#lease.proof,this.#network,()=>this.assertWindow(),{launchApprovals:approvals});
            }
          }));
        }
        this.assertWindow();
        if (state.headBlock.timestamp < this.#reservation.start || state.headBlock.timestamp >= this.#reservation.end)
          throw Error('Funding head is outside the reserved service interval');
        return { ...state, schema: 'cannabis.guest-funding.v2', reservationId: this.#reservation.reservationId, interval: this.interval };
      }
      const network = { ...this.#network, orderId: this.#lease.orderId };
      const original = await readFundedEscrowAtAnchor({ ...network, fundedAnchor: this.#lease.fundedAnchor }, () => this.assertWindow());
      this.#active(original);
      if (original.finalizedBlock.timestamp !== this.#lease.fundedAnchor.timestamp || original.finalizedBlock.timestamp > this.#lease.signingExpiresAt) throw Error('Funding was not observed inside the lease signing window');
      const finalized = await readFinalizedEscrow(network, () => this.assertWindow());
      this.#active(finalized);
      if (finalized.finalizedBlock.number < original.finalizedBlock.number) throw Error('Guest funding finality regressed');
      const head = await readCurrentEscrow({ ...network, finalizedAnchor: finalized.finalizedBlock,
        fundingAnchor: original.finalizedBlock }, () => this.assertWindow());
      this.#active(head); this.assertWindow();
      if (head.headBlock.number < finalized.finalizedBlock.number || head.headBlock.timestamp < this.#reservation.start || head.headBlock.timestamp >= this.#reservation.end) throw Error('Funding head is outside the reserved service interval');
      return { schema: 'cannabis.guest-funding.v1', leaseDigest: this.#lease.digest, reservationId: this.#reservation.reservationId,
        interval: this.interval, finalizedBlock: finalized.finalizedBlock, headBlock: head.headBlock,
        observedAt: head.observedAt, executionAuthorized: false, hardwareVerified: false };
    } catch (error) { this.close(); throw error; }
    finally { this.#busy = false; }
  }
}
