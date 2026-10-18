import { formatEther } from 'ethers';
import { connected } from './lib.mjs';
const { provider, state, token } = await connected();
try { console.log(JSON.stringify({ ...state, name: await token.name(), totalSupply: formatEther(await token.totalSupply()),
  communityIssued: formatEther(await token.communityIssued()), verifiedClaimCount: String(await token.communityIssued() / await token.CLAIM_AMOUNT()), semaphore: await token.semaphore(), enrollment: await token.enrollment() }, null, 2)); }
finally { provider.destroy(); }
