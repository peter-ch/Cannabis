import solc from 'solc';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export function compile(extraSources = {}) {
  const importedSources = {};
  const input = {
    language: 'Solidity',
    sources: {
      'Cannabis.sol': { content: fs.readFileSync(path.join(root, 'contracts/Cannabis.sol'), 'utf8') },
      'ComputeEscrow.sol': { content: fs.readFileSync(path.join(root, 'contracts/ComputeEscrow.sol'), 'utf8') }, ...extraSources },
    settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: 'cancun',
      outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object', 'evm.bytecode.linkReferences'] } } }
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input), { import: name => {
    if (!['@openzeppelin/contracts/', '@semaphore-protocol/contracts/', '@zk-kit/lean-imt.sol/', 'poseidon-solidity/'].some(prefix => name.startsWith(prefix)) || name.includes('..')) return { error: 'Unsupported import' };
    const contents = fs.readFileSync(path.join(root, 'node_modules', name), 'utf8');
    importedSources[name] = { content: contents };
    return { contents };
  } }));
  for (const error of output.errors ?? []) if (error.severity === 'error') throw Error(error.formattedMessage);
  fs.mkdirSync(path.join(root, 'artifacts'), { recursive: true });
  fs.writeFileSync(path.join(root, 'artifacts/compiler-input.json'), JSON.stringify({ ...input, sources: { ...input.sources, ...importedSources } }, null, 2));
  const artifacts = {};
  for (const [source, contracts] of Object.entries(output.contracts)) {
    for (const [name, contract] of Object.entries(contracts)) {
      if (!Object.hasOwn(input.sources, source) && !['Semaphore', 'SemaphoreVerifier', 'PoseidonT3'].includes(name)) continue;
      const artifact = { contractName: name, compiler: solc.version(), abi: contract.abi, bytecode: `0x${contract.evm.bytecode.object}`, linkReferences: contract.evm.bytecode.linkReferences };
      fs.writeFileSync(path.join(root, 'artifacts', `${name}.json`), JSON.stringify(artifact, null, 2));
      artifacts[name] = artifact;
    }
  }
  return artifacts;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(`Compiled ${Object.keys(compile()).join(', ')} using solc ${solc.version()}`);
}
