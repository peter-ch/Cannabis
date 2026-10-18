// Verify a real ZK claim against a deployed contract and export a wallet-reviewable unsigned transaction.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Contract, FetchRequest, JsonRpcProvider, getAddress, keccak256, toBeHex } from 'ethers';
import { compile } from './compile.mjs';

export async function prepareClaim({ rpc, chainId, token, recipient, codeHash, proof }) {
  const url = new URL(rpc);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && url.hostname === '127.0.0.1')) throw Error('Use HTTPS RPC or local verification RPC');
  chainId = BigInt(chainId); token = getAddress(token); recipient = getAddress(recipient);
  if (chainId <= 0n || !/^0x[0-9a-fA-F]{64}$/.test(codeHash)) throw Error('Expected chain ID and deployed code hash are required');
  const request = new FetchRequest(rpc); request.timeout = 15000;
  const provider = new JsonRpcProvider(request, undefined, { cacheTimeout: -1 });
  try {
    if ((await provider.getNetwork()).chainId !== chainId) throw Error('RPC chain ID does not match');
    const code = await provider.getCode(token);
    if (code === '0x' || keccak256(code).toLowerCase() !== codeHash.toLowerCase()) throw Error('Contract code does not match verified release');
    const contract = new Contract(token, compile().Cannabis.abi, provider);
    if (BigInt(proof.message) !== BigInt(recipient) || BigInt(proof.scope) !== await contract.claimScope()) throw Error('Proof recipient or scope does not match');
    await contract.claim.staticCall(recipient, proof, { from: recipient });
    return { name: 'Cannabis', status: 'UNSIGNED_VERIFIED_CLAIM', checkedAt: new Date().toISOString(),
      chainId: chainId.toString(), token, recipient, deployedCodeHash: keccak256(code),
      transaction: { chainId: toBeHex(chainId), from: recipient, to: token,
        data: contract.interface.encodeFunctionData('claim', [recipient, proof]), value: '0x0' },
      sent: false, review: 'Review the canonical chain, contract and recipient in your wallet. Re-simulate immediately before signing; membership updates can stale the proof. Network fees apply.' };
  } finally { provider.destroy(); }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2), options = {};
  const names = { rpc: 'rpc', 'chain-id': 'chainId', token: 'token', recipient: 'recipient', 'code-hash': 'codeHash', proof: 'proofFile', out: 'out' };
  for (let i = 0; i < args.length; i += 2) {
    const key = names[args[i]?.slice(2)];
    if (!args[i]?.startsWith('--') || !key || !args[i + 1]) throw Error('Use documented --name value arguments');
    options[key] = args[i + 1];
  }
  for (const key of Object.values(names)) if (!options[key]) throw Error('Missing ' + key);
  if (fs.existsSync(options.out)) throw Error('Output exists; choose a new file');
  const proof = JSON.parse(fs.readFileSync(options.proofFile, 'utf8'));
  const result = await prepareClaim({ ...options, proof });
  fs.writeFileSync(options.out, JSON.stringify(result, null, 2) + '\n', { flag: 'wx' });
  console.log(JSON.stringify({ output: path.resolve(options.out), status: result.status, sent: false }));
}
