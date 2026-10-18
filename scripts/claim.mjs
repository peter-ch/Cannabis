// Local development only. Human verification is mocked, never a production approval service.
import { formatEther } from 'ethers';
import { connected, localProof, closeProver } from './lib.mjs';
const index = process.argv.includes('--account') ? Number(process.argv[process.argv.indexOf('--account') + 1]) : 1;
if (!Number.isInteger(index) || index < 0 || index > 19) throw Error('Use --account 0..19 for a local test account');
const { provider, token } = await connected();
try {
  const signer = await provider.getSigner(index), recipient = await signer.getAddress();
  const proof = await localProof(provider, token, recipient, index);
  const head = await provider.getBlock('latest');
  const start = Number(await token.claimsStartAt());
  if (start > head.timestamp) await provider.send('evm_setNextBlockTimestamp', [start]);
  const receipt = await (await token.connect(signer).claim(recipient, proof)).wait();
  console.log(JSON.stringify({ network: 'local-devnet', verification: 'LOCAL_MOCK_ONLY', recipient,
    transaction: receipt.hash, reward: formatEther(await token.CLAIM_AMOUNT()), balance: formatEther(await token.balanceOf(recipient)), gasUsed: receipt.gasUsed.toString() }));
} finally { provider.destroy(); await closeProver(); }
