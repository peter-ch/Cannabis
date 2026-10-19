import { sha256, MAX_RESULT_BYTES } from './work-results.js';
import { approvedArchiveDescriptors, openApprovedResults, MAX_RECOVERY_BYTES } from './work-approvals.js';
import { BrowserResultInbox } from './work-inbox.js';
import { downloadApprovedArchives, EncryptedDownloadCache } from './work-relay.js';
import {initializeWorkMarket} from './work-market.js';

const $ = id => document.getElementById(id);
const enc = new TextEncoder();
let pending = null, address = null;
const access = new Map(), downloads = [];
let inboxPromise, reviewedRecovery=null, selectedRecovery=null, resultGeneration=0;
const encryptedDownloads=new EncryptedDownloadCache();let resultController=null;
const inbox=()=>inboxPromise??=BrowserResultInbox.open();
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
  if (!(response.headers.get('content-type') ?? '').includes('application/json')) throw Error('Optional preparation storage is unavailable here. Direct market tools and local result decryption remain independent of this service.');
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
function clearResults({discardDownloads=true}={}) {
  resultGeneration++;resultController?.abort();resultController=null;
  if(discardDownloads)encryptedDownloads.clear();
  downloads.splice(0).forEach(URL.revokeObjectURL);$('results').replaceChildren();$('transfer-progress').textContent='';
}
function resultSource() {
  const hosted=$('result-source').value==='hosted';$('local-results').hidden=hosted;$('hosted-results').hidden=!hosted;
  $('result-files').required=!hosted;$('relay-access').required=hosted;
}
$('result-source').addEventListener('change',()=>{clearResults();resultSource();});
for(const id of ['workload','package-hash','result-files','relay-access','result-key'])
  $(id).addEventListener('change',()=>clearResults({discardDownloads:id==='workload'||id==='package-hash'}));
async function listRecoveries() {
  const entries=await (await inbox()).list();$('saved-results').replaceChildren(new Option('Choose saved job…',''));
  for(const entry of entries)if(entry.active)$('saved-results').append(new Option(`${entry.jobId} · ${entry.active} approved results`,entry.id));
}
function showSelection(snapshot) {
  clearResults();selectedRecovery=snapshot;
  $('selected-execution').textContent=`${snapshot.jobId}: ${snapshot.bundle.entries.length} selected approved results. Chain ${snapshot.bundle.context.chainId}, requester ${snapshot.bundle.context.requester}, escrow ${snapshot.bundle.context.escrow}.`;
  $('retire-results').disabled=false;
}
$('execution-recovery').addEventListener('change',()=>action(null,async()=>{
  reviewedRecovery=null;$('select-execution').disabled=true;$('execution-review').textContent='';
  const review=await (await inbox()).prepare(await jsonFile($('execution-recovery').files[0],MAX_RECOVERY_BYTES));
  reviewedRecovery=review;
  $('execution-review').textContent=`Review ${review.jobId}: ${review.count} signed approvals on chain ${review.context.chainId}. Requester ${review.context.requester}. Escrow ${review.context.escrow}. Attempts ${review.attempts.map(a=>`${a.attempt} (rank ${a.rank})`).join(', ')}. Use your latest requester export; this file cannot establish whether another device selected a newer attempt.`;
  $('select-execution').disabled=false;
}));
$('select-execution').addEventListener('click',()=>action($('select-execution'),async()=>{
  showSelection(await (await inbox()).select(reviewedRecovery));reviewedRecovery=null;
  $('execution-recovery').value='';$('execution-review').textContent='';await listRecoveries();
  feedback('Approved attempts selected on this browser. Result keys and private files remain on your device.');
}).finally(()=>{$('select-execution').disabled=!reviewedRecovery;}));
$('saved-results').addEventListener('change',()=>action(null,async()=>{
  clearResults();selectedRecovery=null;
  $('selected-execution').textContent='No execution selected.';$('retire-results').disabled=true;
  if($('saved-results').value)showSelection(await (await inbox()).read($('saved-results').value));
}));
$('retire-results').addEventListener('click',()=>action($('retire-results'),async()=>{
  if(!selectedRecovery)throw Error('Choose a saved job first');
  await (await inbox()).retire(selectedRecovery);clearResults();selectedRecovery=null;
  $('selected-execution').textContent='Selected attempts retired on this browser. Existing downloads are unchanged.';
  await listRecoveries();feedback('Retired attempts cannot be reselected. A replacement needs a higher requester-approved attempt.');
}).finally(()=>{$('retire-results').disabled=!selectedRecovery;}));
$('clear-results').addEventListener('click', () => { clearResults(); $('results-form').reset(); resultSource(); feedback('Result files and key inputs cleared from this page.'); });
$('results-form').addEventListener('submit', event => {
  event.preventDefault(); action(event.submitter, async () => {
    clearResults({discardDownloads:false}); const generation=resultGeneration,snapshot=selectedRecovery;
    if(!snapshot)throw Error('Review an execution recovery export or choose a saved job first');
    const assertCurrent=async()=>{
      if(generation!==resultGeneration)throw Error('Result opening was cleared or superseded');
      await (await inbox()).checkCurrent(snapshot);
      if(generation!==resultGeneration)throw Error('Result opening was cleared or superseded');
    };
    await assertCurrent();
    const spec = await jsonFile($('workload').files[0]);
    const packageSHA256=$('package-hash').value,hosted=$('result-source').value==='hosted';let encrypted;
    const identityFile = $('result-key').files[0]; if (!identityFile || identityFile.size > 4096) throw Error('Choose a bounded age result identity file');
    const identity = await identityFile.text(); $('result-key').value = '';
    if(hosted) {
      const selected=[...$('relay-access').files];
      if(!selected.length||selected.length>128)throw Error('Choose one read-access file per selected result');
      const accessFiles=[];for(const file of selected)accessFiles.push(await jsonFile(file,8192));
      const descriptors=await approvedArchiveDescriptors({bundle:snapshot.bundle,spec,packageSHA256,identity});
      await assertCurrent();const controller=new AbortController();resultController=controller;
      encrypted=await downloadApprovedArchives({descriptors,accessFiles,origin:location.origin,cache:encryptedDownloads,signal:controller.signal,assertCurrent,
        onProgress:({completed,total,retrySeconds})=>{
          if(generation===resultGeneration)$('transfer-progress').textContent=`Encrypted download: ${completed.toLocaleString()} / ${total.toLocaleString()} bytes.${retrySeconds?` Retrying in ${retrySeconds} seconds…`:''}`;
        }});
      await assertCurrent();
    } else {
      const selected=[...$('result-files').files];
      if(!selected.length||selected.length>128||selected.reduce((n,f)=>n+f.size,0)>MAX_RESULT_BYTES)throw Error('Use the streaming client for result sets above 64 MiB or 128 archives');
      encrypted=[];
      for(const file of selected) {
        if(!file.name.endsWith('.age'))throw Error('Select encrypted .age archives; authenticated receipts come from your recovery export');
        encrypted.push(new Uint8Array(await file.arrayBuffer()));
      }
    }
    const files = await openApprovedResults({bundle:snapshot.bundle,spec,packageSHA256,identity,encrypted});
    try {
      if(generation!==resultGeneration)throw Error('Result opening was cleared or superseded');
      await (await inbox()).useCurrent(snapshot,()=>{
        if(generation!==resultGeneration)throw Error('Result opening was cleared or superseded');
        for (const [name, bytes] of files) {
          const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' })); downloads.push(url);
          const a = document.createElement('a'); a.href = url; a.download = name.split('/').pop(); a.textContent = `Download ${name} · ${bytes.length} bytes`;
          a.addEventListener('click',event=>{event.preventDefault();action(null,async()=>{
            try {await (await inbox()).useCurrent(snapshot,()=>{
              if(generation!==resultGeneration)throw Error('Result selection was cleared');
              const link=document.createElement('a');link.href=url;link.download=a.download;link.click();
            });}catch(error){clearResults();throw error;}
          });});
          $('results').append(a);
        }
      },{verified:true});
    }catch(error){if(generation===resultGeneration)clearResults();throw error;}
    finally {for(const bytes of files.values())bytes.fill(0);if(generation===resultGeneration){encryptedDownloads.clear();resultController=null;}}
    feedback('Requester approvals, encrypted receipts, selected attempts and archive contents verified. Results decrypted locally. Review output quality before approving payment; no transaction was signed or sent.');
  });
});
window.addEventListener('pagehide', clearResults);
initializeWorkMarket().catch(()=>{$('direct-market-message').textContent='Direct market tools could not initialize. Use the reviewed local console; no payment was requested.';});
listRecoveries().catch(()=>{$('selected-execution').textContent='Local result storage is unavailable. Use the requester desktop client.';});
void (async () => {try {
  const status = await api('status'); $('service-status').textContent = status.message;
  $('hosted-option').disabled=status.encryptedResultStorageAvailable!==true;
  signedIn((await api('account')).address);
}catch { $('service-status').textContent = 'Optional preparation storage is unavailable here. Direct market tools and local result decryption remain available.'; }})();
