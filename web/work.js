import { openResults, sha256, MAX_RESULT_BYTES } from './work-results.js';

const $ = id => document.getElementById(id);
const enc = new TextEncoder();
let pending = null, address = null;
const access = new Map(), downloads = [];
const feedback = message => { $('feedback').textContent = message; };
function download(name, bytes, type = 'application/octet-stream') {
  const url = URL.createObjectURL(new Blob([bytes], { type })), link = document.createElement('a');
  link.href = url; link.download = name; link.click(); setTimeout(() => URL.revokeObjectURL(url), 60_000);
}
async function jsonFile(file, limit = 1024 * 1024) {
  if (!file || file.size > limit) throw Error('Choose a JSON file within the size limit');
  return JSON.parse(await file.text());
}
async function api(path, { method = 'GET', body, token } = {}) {
  const response = await fetch('./api/work/' + path, { method, credentials: 'same-origin', cache: 'no-store', redirect: 'error',
    headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: 'Bearer ' + token } : {}) },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
  if (!(response.headers.get('content-type') ?? '').includes('application/json')) throw Error('Order service unavailable here. Open cannabis-coin.online/work.html; local result decryption remains available.');
  const result = await response.json(); if (!response.ok) throw Error(result.error ?? 'Request failed'); return result;
}
function decimal(atomic) {
  const n = BigInt(atomic), whole = n / 10n ** 18n, fraction = String(n % 10n ** 18n).padStart(18, '0').replace(/0+$/, '');
  return String(whole) + (fraction ? '.' + fraction : '');
}
function budgetAtomic(value) {
  if (!/^(0|[1-9]\d{0,59})(\.\d{1,18})?$/.test(value)) throw Error('Enter a positive exact decimal budget');
  const [whole, fraction = ''] = value.split('.'), amount = BigInt(whole) * 10n ** 18n + BigInt(fraction.padEnd(18, '0'));
  if (amount <= 0n || amount >= 2n ** 256n || amount % 100n) throw Error('Use increments of 0.0000000000000001 for an exact included fee');
  return amount;
}
function preview() {
  try {
    const total = budgetAtomic($('budget').value), asset = $('asset').value;
    $('fee-preview').textContent = `Total ${decimal(total)} ${asset} · Workers ${decimal(total - total / 100n)} · Included service fee ${decimal(total / 100n)} (1%). Network fees are separate.`;
  } catch { $('fee-preview').textContent = 'Enter your budget to see the included 1% service fee and 99% worker payment. Network fees are separate.'; }
}
async function commitments() {
  const file = $('order-manifest').files[0]; if (!file) return null;
  const order = await jsonFile(file, 8192);
  const allowed = ['schema', 'id', 'requester', 'packageSHA256', 'policySHA256', 'acceptanceSHA256', 'payment'];
  if (order.schema !== 'cannabis.compute.order.v2' || Object.keys(order).sort().join() !== allowed.sort().join() || order.payment?.totalBudget !== $('budget').value || order.payment?.feeBasisPoints !== 100 || order.payment?.founderRecipient?.toLowerCase() !== '0xe02ad92413ad0a3aac8263ee3c2bd9410955f89b') throw Error('Use a public v2 order manifest whose budget and fee match this preparation');
  return Object.fromEntries(['id', 'requester', 'packageSHA256', 'policySHA256', 'acceptanceSHA256'].map(k => [k, order[k]]));
}
async function validateRecovery(value) {
  if (value?.schema !== 'cannabis.web-recovery.v1' || value.origin !== location.origin || typeof value.accessKey !== 'string' || !/^[0-9a-f]{64}$/.test(value.accessKey) || await sha256(enc.encode(value.accessKey)) !== value.order?.accessHash || typeof value.order?.id !== 'string' || !/^[0-9a-f-]{36}$/.test(value.order.id)) throw Error('Recovery file is invalid or belongs to another website origin');
  return value;
}
function renderOrders(orders) {
  $('orders').replaceChildren();
  if (!orders.length) { $('orders').textContent = 'No linked orders yet. Guest orders remain accessible through their recovery files.'; return; }
  for (const order of orders) {
    const card = document.createElement('article'); card.className = 'order-card';
    const title = document.createElement('h3'); title.textContent = `${order.budget} ${order.asset} · Prepared`;
    const id = document.createElement('small'); id.textContent = order.id;
    const details = document.createElement('p'); details.textContent = `Not funded. ${order.commitments ? 'Encrypted package commitments attached.' : 'Package can be prepared with the compute client.'} Retained until ${new Date(order.expires).toLocaleDateString()}.`;
    const quote = document.createElement('button'); quote.type = 'button'; quote.textContent = 'Check payment availability';
    quote.addEventListener('click', () => action(quote, async () => { await api(`orders/${order.id}/quote`, { method: 'POST', body: {}, token: access.get(order.id) }); }));
    const remove = document.createElement('button'); remove.type = 'button'; remove.textContent = 'Delete preparation';
    remove.addEventListener('click', () => action(remove, async () => {
      await api(`orders/${order.id}`, { method: 'DELETE', token: access.get(order.id) }); card.remove(); access.delete(order.id); feedback('Preparation deleted. No payment was involved.');
    }));
    card.append(title, id, details, quote, remove); $('orders').append(card);
  }
}
async function action(button, fn) {
  if (button) button.disabled = true;
  try { await fn(); } catch (error) { feedback(error.message || 'The operation could not be completed'); }
  finally { if (button) button.disabled = false; }
}
function signedIn(value) {
  address = value; $('sign-in').hidden = !!address; $('sign-out').hidden = !address;
  $('link-account').disabled = !address; if (!address) $('link-account').checked = false;
  $('account-status').textContent = address ? `Signed in: ${address}. Guest preparations stay separate unless you choose account saving.` : 'Guest mode. No registration needed.';
}
$('asset').addEventListener('change', preview); $('budget').addEventListener('input', preview);
$('prepare-form').addEventListener('submit', event => {
  event.preventDefault(); action(event.submitter, async () => {
    budgetAtomic($('budget').value);
    const accessKey = Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
    pending = { schema: 'cannabis.web-recovery.v1', origin: location.origin, accessKey,
      order: { id: crypto.randomUUID(), accessHash: await sha256(enc.encode(accessKey)), asset: $('asset').value, budget: $('budget').value, account: $('link-account').checked, commitments: await commitments() } };
    download(`cannabis-order-${pending.order.id}.json`, JSON.stringify(pending, null, 2), 'application/json');
    $('pending-save').hidden = false; $('confirm-recovery').value = '';
    feedback('Recovery file created locally. Reopen your saved copy to verify recovery and save this preparation online.');
  });
});
$('confirm-recovery').addEventListener('change', () => action(null, async () => {
  const value = await validateRecovery(await jsonFile($('confirm-recovery').files[0], 8192));
  if (!pending || JSON.stringify(value) !== JSON.stringify(pending)) throw Error('Reopen the recovery file for the preparation you just created');
  const order = await api('orders', { method: 'POST', body: value.order }); access.set(order.id, value.accessKey);
  pending = null; $('pending-save').hidden = true; $('confirm-recovery').value = ''; renderOrders([order]); feedback('Preparation saved. Keep the recovery file. No funds were sent and no work has been queued.');
}));
$('recover').addEventListener('change', () => action(null, async () => {
  const value = await validateRecovery(await jsonFile($('recover').files[0], 8192));
  const order = await api(`orders/${value.order.id}`, { token: value.accessKey }); access.set(order.id, value.accessKey);
  renderOrders([order]); $('recover').value = ''; feedback('Preparation recovered.');
}));
$('sign-in').addEventListener('click', () => action($('sign-in'), async () => {
  if (!window.ethereum?.request) throw Error('Use a browser wallet to create an optional account, or continue as a guest.');
  const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
  const chainHex = await window.ethereum.request({ method: 'eth_chainId' });
  const challenge = await api('auth/challenge', { method: 'POST', body: { address: accounts[0], chainId: Number(BigInt(chainHex)) } });
  const hex = '0x' + Array.from(enc.encode(challenge.message), b => b.toString(16).padStart(2, '0')).join('');
  const signature = await window.ethereum.request({ method: 'personal_sign', params: [hex, accounts[0]] });
  const result = await api('auth/verify', { method: 'POST', body: { id: challenge.id, signature } }); signedIn(result.address); feedback('Wallet account ready. Signing in did not authorize a payment.');
}));
$('sign-out').addEventListener('click', () => action($('sign-out'), async () => { await api('auth/logout', { method: 'POST', body: {} }); signedIn(null); $('orders').replaceChildren(); feedback('Signed out.'); }));
$('refresh-orders').addEventListener('click', () => action($('refresh-orders'), async () => renderOrders((await api('orders')).orders)));
function clearResults() { downloads.splice(0).forEach(URL.revokeObjectURL); $('results').replaceChildren(); }
$('clear-results').addEventListener('click', () => { clearResults(); $('results-form').reset(); feedback('Result files and key inputs cleared from this page.'); });
$('results-form').addEventListener('submit', event => {
  event.preventDefault(); action(event.submitter, async () => {
    clearResults(); const spec = await jsonFile($('workload').files[0]);
    const selected = [...$('result-files').files];
    if (selected.length > 256 || selected.reduce((n, f) => n + f.size, 0) > MAX_RESULT_BYTES) throw Error('Use the streaming client for result sets above 64 MiB or 128 receipts');
    const receipts = [], encrypted = new Map();
    for (const file of selected) {
      if (file.name.endsWith('.json')) receipts.push(await jsonFile(file));
      else { const bytes = new Uint8Array(await file.arrayBuffer()), digest = await sha256(bytes); if (encrypted.has(digest)) throw Error('Duplicate encrypted result'); encrypted.set(digest, bytes); }
    }
    if (receipts.length !== encrypted.size) throw Error('Select one receipt for every encrypted result');
    const results = receipts.map(receipt => { const bytes = encrypted.get(receipt.ciphertextSHA256); if (!bytes) throw Error('Missing encrypted result for a receipt'); return { receipt, bytes }; });
    const identityFile = $('result-key').files[0]; if (!identityFile || identityFile.size > 4096) throw Error('Choose a bounded age result identity file');
    const identity = await identityFile.text(); $('result-key').value = '';
    const files = await openResults({ spec, packageSHA256: $('package-hash').value, identity, results });
    for (const [name, bytes] of files) {
      const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' })); downloads.push(url);
      const a = document.createElement('a'); a.href = url; a.download = name.split('/').pop(); a.textContent = `Download ${name} · ${bytes.length} bytes`; $('results').append(a);
    }
    feedback('Archive integrity and selected workload fields checked. Results decrypted locally. Use the requester recovery client to verify the approved execution and active attempt. Review output quality before approving payment; this did not approve or send a transaction.');
  });
});
window.addEventListener('pagehide', clearResults);
action(null, async () => {
  const status = await api('status'); $('service-status').textContent = status.message;
  signedIn((await api('account')).address);
}).finally(() => { if ($('service-status').textContent.includes('Connecting')) $('service-status').textContent = 'The order service is unavailable here. Local result decryption remains available.'; });
