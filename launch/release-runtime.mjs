import solc from 'solc';
import { isDeepStrictEqual } from 'node:util';
import { keccak256 } from 'ethers';
import { releaseArtifacts } from './release.mjs';

export function compileReleaseRuntime({ compilerInput, artifacts, plan }) {
  if (solc.version() !== plan.compiler) throw Error('Use the exact release compiler');
  const input = structuredClone(compilerInput);
  if (input.language !== 'Solidity' || !input.sources || Object.values(input.sources).some(source =>
    typeof source.content !== 'string' || Object.hasOwn(source, 'urls'))) throw Error('Require complete inline Solidity source');
  input.settings.outputSelection = { '*': { '*': ['abi', 'evm.bytecode.object', 'evm.bytecode.linkReferences',
    'evm.deployedBytecode.object', 'evm.deployedBytecode.linkReferences', 'evm.deployedBytecode.immutableReferences'] } };
  // No import callback or network fetch: the committed package must be complete.
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  if ((output.errors ?? []).some(error => error.severity === 'error')) throw Error('Packaged source does not compile');
  const runtimes = {};
  for (const name of releaseArtifacts) {
    const matches = Object.values(output.contracts).filter(source => Object.hasOwn(source, name));
    if (matches.length !== 1) throw Error('Ambiguous release contract source');
    const compiled = matches[0][name], artifact = artifacts[name], runtime = compiled.evm.deployedBytecode;
    if ('0x' + compiled.evm.bytecode.object !== artifact.bytecode || !isDeepStrictEqual(compiled.abi, artifact.abi) ||
        !isDeepStrictEqual(compiled.evm.bytecode.linkReferences, artifact.linkReferences) ||
        Object.keys(runtime.linkReferences).length || !/^(?:[0-9a-f]{2})+$/.test(runtime.object))
      throw Error('Recompiled release creation or runtime does not match');
    runtimes[name] = { bytecode: '0x' + runtime.object, immutableReferences: runtime.immutableReferences ?? {} };
  }
  return runtimes;
}

export function matchReleaseRuntime(code, template) {
  if (typeof code !== 'string' || !/^0x(?:[0-9a-f]{2})+$/i.test(code) || code.length > 2 + 24576 * 2 ||
      code.length !== template.bytecode.length) throw Error('Missing or changed deployed runtime');
  const actual = Buffer.from(code.slice(2), 'hex'), expected = Buffer.from(template.bytecode.slice(2), 'hex');
  const occupied = new Set(), immutableValues = {};
  for (const [id, ranges] of Object.entries(template.immutableReferences)) {
    if (!/^[0-9]+$/.test(id) || !Array.isArray(ranges) || !ranges.length) throw Error('Invalid compiler immutable references');
    for (const { start, length } of ranges) {
      if (!Number.isSafeInteger(start) || start < 0 || length !== 32 || start + length > actual.length)
        throw Error('Invalid compiler immutable range');
      const value = actual.subarray(start, start + length).toString('hex');
      if (immutableValues[id] && immutableValues[id] !== value) throw Error('Repeated immutable values disagree');
      immutableValues[id] = value;
      for (let i = start; i < start + length; ++i) {
        if (occupied.has(i) || expected[i] !== 0) throw Error('Overlapping or nonempty compiler immutable slots');
        occupied.add(i); actual[i] = 0;
      }
    }
  }
  if (!actual.equals(expected)) throw Error('Deployed code differs outside compiler immutable slots');
  return { runtimeKeccak256: keccak256(code), bytes: actual.length, immutableSlotCount: occupied.size / 32,
    distinctImmutables: Object.keys(immutableValues).length };
}
