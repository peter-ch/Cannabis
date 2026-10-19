// Fresh funding observation inside the guest. Not hardware/runtime admission.
import { getAddress } from 'ethers';
import { performance } from 'node:perf_hooks';
import { verifyLeaseProof } from './lease_proof.mjs';
import { guestInitialization } from './guest_initialization.mjs';
import { readFinalizedEscrow, readCurrentEscrow, readFundedEscrowAtAnchor } from './finality.mjs';

export class GuestFunding {
  #lease; #reservation; #network; #clock; #last; #end; #closed = false; #busy = false;
  constructor(options, initialization, { clock = () => Math.floor(Date.now() / 1000) } = {}) {
    // All configuration except proof is independently approved measured-guest
    // configuration. A host may transport it, but must not choose its pins/RPC.
    options = structuredClone(options);
    const keys = ['proof', 'context', 'network', 'provider', 'resourceId', 'serviceSHA256'];
    if (!options || Object.keys(options).sort().join() !== keys.sort().join()) throw Error('Require approved guest funding configuration');
    const assignment = guestInitialization(initialization).assignment, b = assignment.binding;
    const lease = verifyLeaseProof(options.proof, options.context);
    const reservation = lease.reservations.find(r => r.reservationId === b.reservationId);
    if (options.context.chainId !== b.chainId || lease.digest !== b.leaseDigest || lease.orderId !== b.orderId ||
        lease.escrow !== b.escrow || lease.requester !== assignment.requester || lease.job.id !== assignment.jobId ||
        lease.job.packageSHA256 !== b.packageSHA256 || lease.job.policySHA256 !== b.policySHA256 || !reservation ||
        reservation.provider !== getAddress(options.provider) || reservation.resourceId !== options.resourceId ||
        reservation.serviceSHA256 !== options.serviceSHA256) throw Error('Signed lease differs from retained guest assignment or approved resource');
    const network = options.network;
    if (BigInt(network.chainId) !== BigInt(b.chainId) || getAddress(network.escrow) !== b.escrow ||
        getAddress(network.token) !== getAddress(options.context.token)) throw Error('Guest funding network differs from approved capacity domain');
    this.#lease = lease; this.#reservation = reservation; this.#network = network; this.#clock = clock;
    const now = clock();
    if (!Number.isSafeInteger(now) || now < 1) throw Error('Invalid guest clock');
    this.#last = now;
    // Never restart the service interval on a later helper, refresh or key open.
    this.#end = performance.now() + Math.max(0, reservation.end - now) * 1000;
  }
  get interval() { return { start: this.#reservation.start, end: this.#reservation.end }; }
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
