// Offline owned consent checks only. No chain, customer keys or authorization.
import { Wallet, AbiCoder, formatUnits, keccak256, ZeroAddress } from 'ethers';
import { launchFixture } from './launch_fixture.mjs';
import { nativeServiceCommitment } from '../../compute/guest_execution.mjs';
import { validateGuestConfiguration } from '../../compute/guest_configuration.mjs';
import { configuredMarketAttestationBinding } from '../../compute/attestation.mjs';
import { verifyMarketLeaseProof } from '../../compute/market_lease.mjs';
import { bookingPayload } from '../../compute/market.mjs';
import { settlementTerms,termsDigest } from '../../scripts/compute-escrow.mjs';
import { policy } from '../../scripts/compute-plan.mjs';
import { launchConsentPayload } from '../../compute/guest_consent.mjs';
const h=n=>'0x'+n.toString(16).padStart(64,'0'),coder=AbiCoder.defaultAbiCoder();
const utc=n=>new Date(n*1000).toISOString().replace('.000Z','Z');
export async function consentFixture({sameParty=false,start=1000,end=start+1000}={}) {
  const requester=Wallet.createRandom(),provider=sameParty?requester:Wallet.createRandom(),c=launchFixture().configuration;
  c.schema='cannabis.guest-launch-configuration.v3';c.context={chainId:31337,market:Wallet.createRandom().address,token:ZeroAddress};
  c.network.market=c.context.market;c.network.marketCodeHash=h(99);c.provider=provider.address;
  const resourceId=keccak256(coder.encode(['address','bytes32'],[provider.address,h(10)]));c.resourceId=resourceId;
  c.validFrom=start;c.validUntil=end;
  const gross=BigInt(end-start)*100n,service=nativeServiceCommitment(c.execution);
  const job={schema:'cannabis.compute.order.v2',id:'owned-consent-only',requester:requester.address,
    packageSHA256:h(2).slice(2),policySHA256:h(3).slice(2),acceptanceSHA256:h(4).slice(2),
    payment:{totalBudget:formatUnits(gross,18),feeBasisPoints:100,founderRecipient:policy.founderRecipient}};
  const settlement={workers:[{account:provider.address,shareBps:10000}],deliveryManager:provider.address,
    adjudicator:Wallet.createRandom().address,acceptBy:utc(start-1),deliverBy:utc(end+100),reviewSeconds:86400,disputeSeconds:86400};
  const terms=settlementTerms(job,settlement);
  const orderId=keccak256(coder.encode(['string','uint256','address','address','bytes32'],
    ['Cannabis compute order v1',31337,c.network.escrow,requester.address,terms.terms.jobHash]));
  const digest=termsDigest({chainId:31337,escrow:c.network.escrow,token:ZeroAddress,founderRecipient:policy.founderRecipient,...terms});
  const booking={reservationId:h(5),offerId:h(6),requester:requester.address,orderId,termsDigest:digest,
    start:String(start),end:String(end),units:'1',gross:gross.toString(),holdUntil:String(start-1)};
  const bookingId=bookingPayload(c.context,booking).digest;
  const proof={schema:'cannabis.market-lease.v1',chainId:31337,market:c.context.market,token:ZeroAddress,escrow:c.network.escrow,job,settlement,
    bookings:[{bookingId,booking,offer:{resource:resourceId,escrow:c.network.escrow,policyHash:'0x'+job.policySHA256,manifestHash:h(7),
      start:String(start),end:String(end),expiresAt:String(start-1),units:'1',grossPerUnitSecond:'100'},resource:{provider:provider.address,serviceHash:service.serviceSHA256,units:'1'}}],
    fundedAnchor:{number:12,hash:h(8),timestamp:start-1}};
  verifyMarketLeaseProof(proof,c.context); // Consistent invented records are NOT chain evidence.
  const configHash=validateGuestConfiguration(c).configurationSHA256;
  const run={runtimeSHA256:c.execution.profile.runtime.digestSHA256,taskSHA256:h(9).slice(2),attempt:1,rank:0,worldSize:1,acceleratorClass:'cpu'};
  const binding=configuredMarketAttestationBinding(proof,c.context,bookingId,run,configHash,start);
  const initialization={schema:'cannabis.guest-initialization.v2',tee:'snp',requester:requester.address,jobId:job.id,binding};
  const consents=[];
  for(const [role,wallet] of [['requester',requester],['provider',provider]]) {
    const p=launchConsentPayload(c,initialization,proof,role);
    consents.push({role,signer:wallet.address,signature:await wallet.signTypedData(p.domain,p.types,p.value)});
  }
  const signed={schema:'cannabis.guest-launch-consent.v1',configuration:c,consents};
  return {requester,provider,configuration:c,initialization,proof,signed};
}
