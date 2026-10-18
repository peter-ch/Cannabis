import fs from 'node:fs';
import path from 'node:path';
import { readBounded } from '../claims/identity.mjs';
import { quoteDeploymentFee } from '../launch/fees.mjs';
try {
  const [flag, configPath, outFlag, outPath, ...extra] = process.argv.slice(2);
  if (flag !== '--config' || outFlag !== '--out' || !configPath || !outPath || extra.length || fs.existsSync(outPath)) throw Error('Invalid quote arguments');
  const config = JSON.parse(readBounded(path.resolve(configPath), 16384).toString('utf8'));
  if (!config || Object.keys(config).sort().join(',') !== 'expectedDataHash,manifestFile,rpc' || !path.isAbsolute(config.manifestFile)) throw Error('Invalid quote configuration');
  const manifest = JSON.parse(readBounded(config.manifestFile, 1024 * 1024).toString('utf8'));
  if (manifest.name !== 'Cannabis' || manifest.status !== 'UNSIGNED_DRAFT' || manifest.deploymentDataKeccak256 !== config.expectedDataHash ||
      String(manifest.chain?.chainId) !== BigInt(manifest.transaction?.chainId).toString() || manifest.founderBeneficiary !== manifest.transaction.from) throw Error('Inconsistent release manifest');
  const result = await quoteDeploymentFee({ rpc: config.rpc, transaction: manifest.transaction, expectedDataHash: config.expectedDataHash });
  fs.writeFileSync(outPath, JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ chainId: result.chainId, estimatedNetworkFeeETH: result.estimatedNetworkFeeETH, planningBudgetETH: result.planningBudgetETH, spendAuthorized: false, sent: false }));
} catch {
  console.error('Deployment quote failed. Check the reviewed data hash, private manifest, supported network, current RPC state and fee-oracle profile. No funds were spent.');
  process.exitCode = 1;
}
