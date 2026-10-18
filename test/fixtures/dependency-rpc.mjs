import http from 'node:http';
import { Interface, keccak256 } from 'ethers';

export async function dependencyRPC(mutate = () => {}, chainId = '8453') {
  const addresses = { semaphore: '0x' + '22'.repeat(20), verifier: '0x' + '33'.repeat(20), poseidon: '0x' + '44'.repeat(20) };
  const codes = { semaphore: '0x73' + addresses.poseidon.slice(2) + '600056', verifier: '0x600160005260206000f3', poseidon: '0x600260005260206000f3' };
  const dependencies = { schema: 'cannabis.semaphore-dependencies.v1', chainId, poseidonLinkOffsets: [1] };
  for (const [name, address] of Object.entries(addresses)) dependencies[name] = { address, codeHash: keccak256(codes[name]) };
  const now = Math.floor(Date.now() / 1000), requests = [];
  const anchor = { number: '0x64', hash: '0x' + 'aa'.repeat(32), timestamp: '0x' + (now - 30).toString(16) };
  const head = { number: '0x65', hash: '0x' + 'bb'.repeat(32), timestamp: '0x' + now.toString(16) };
  const abi = new Interface(['function verifier() view returns (address)']);
  const server = http.createServer(async (request, response) => {
    try {
      const chunks = []; for await (const chunk of request) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks)); requests.push(body);
      let result;
      if (body.method === 'eth_chainId') result = '0x' + BigInt(chainId).toString(16);
      else if (body.method === 'eth_getBlockByNumber') result = structuredClone(['finalized', '0x64'].includes(body.params[0]) ? anchor : head);
      else if (body.method === 'eth_getCode') result = codes[Object.keys(addresses).find(name => addresses[name].toLowerCase() === body.params[0].toLowerCase())] ?? '0x';
      else if (body.method === 'eth_call') result = abi.encodeFunctionResult('verifier', [addresses.verifier]);
      else throw Error('Unexpected fixture RPC method');
      const payload = { jsonrpc: '2.0', id: body.id, result };
      await mutate(body, payload, { requests, anchor, head });
      response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify(payload));
    } catch { response.writeHead(500); response.end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { config: { rpc: `http://127.0.0.1:${server.address().port}`, dependencies }, requests, codes, addresses,
    close: () => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }) };
}
