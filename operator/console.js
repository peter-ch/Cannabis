import {initializeStorage,renderStorage,setStorageConnected} from './results.js';
const $ = id => document.getElementById(id);
let paused = false, report = null, pending = false, timer;
const gib = bytes => (bytes / 2 ** 30).toFixed(1);
function render(value) {
  report = value;
  const { resources, inventory, worker } = value;
  $('cpu').textContent = resources.cpuPercent === null ? 'Sampling…' : `${resources.cpuPercent}%`;
  $('cpu-bar').value = resources.cpuPercent ?? 0;
  const used = resources.totalMemoryBytes - resources.freeMemoryBytes;
  $('memory').textContent = `${gib(used)} GB`;
  $('memory-total').textContent = `of ${gib(resources.totalMemoryBytes)} GB total`;
  $('memory-bar').value = used / resources.totalMemoryBytes * 100;
  $('jobs').textContent = worker.completedJobsThisSession;
  $('earnings').textContent = worker.earningsThisSession;
  $('processor').textContent = `${inventory.cpu} · ${inventory.logicalCpus} logical processors`;
  $('graphics').textContent = inventory.graphics.length ? inventory.graphics.join(' · ') : 'Inventory unavailable on this platform';
  $('system').textContent = `${inventory.os} / ${inventory.architecture}`;
  $('requirements').replaceChildren(...value.requirements.map(item => {
    const li = document.createElement('li'), title = document.createElement('strong'), description = document.createElement('p');
    title.textContent = item.name; description.textContent = item.detail; li.append(title, description); return li;
  }));
  $('download').disabled = false;
  renderStorage(value.resultStorage);
}
function connection(text, state = 'ok') { $('connection').textContent = text; $('connection').dataset.state = state; }
function lastObservation() { return report ? new Date(report.observedAt).toLocaleTimeString() : 'none'; }
async function refresh() {
  if (pending) return;
  pending = true; $('refresh').disabled = true;
  try {
    const response = await fetch('/api/status', { cache: 'no-store', signal: AbortSignal.timeout(5000) });
    if (!response.ok) throw Error('Unavailable');
    const value = await response.json();
    const age = Date.now() - Date.parse(value.observedAt);
    if (value.schema !== 'cannabis.worker-console.v1' || !Number.isFinite(age) || age < -5000 || age > 15000 ||
        value.worker?.admitted !== false || value.worker?.acceptingJobs !== false) throw Error('Unsupported report');
    render(value);
    setStorageConnected(true);
    connection(`${paused ? 'Monitoring paused. Snapshot' : 'Local monitor connected. Observed'} at ${lastObservation()}. Activity belongs to the whole computer.`);
  } catch {
    setStorageConnected(false);
    connection(`Local monitor unavailable. Last observation: ${lastObservation()}. Displayed readings are stale; worker intake remains unavailable.`, 'error');
    $('download').disabled = true;
  } finally { pending = false; $('refresh').disabled = false; }
}
function schedule() { clearInterval(timer); if (!paused) timer = setInterval(refresh, 3000); }
$('refresh').addEventListener('click', refresh);
$('pause').addEventListener('click', () => {
  paused = !paused; $('pause').textContent = paused ? 'Resume monitoring' : 'Pause monitoring';
  $('pause').setAttribute('aria-pressed', String(paused)); schedule();
  if (paused) connection(`Monitoring paused. Last observation: ${lastObservation()}. Pausing affects this view only.`);
  else refresh();
});
$('download').addEventListener('click', () => {
  if (!report) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2) + '\n'], { type: 'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = 'cannabis-worker-readiness.json'; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
await initializeStorage(refresh);await refresh(); schedule();
