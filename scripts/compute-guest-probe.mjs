// Inspect the guest-local AA protocol endpoint; never create keys or request evidence.
import { probeGuestAgent } from '../compute/guest_session.mjs';
try {
  const [tee, agentUrl = 'http://127.0.0.1:8006', ...extra] = process.argv.slice(2);
  if (!['snp', 'tdx'].includes(tee) || extra.length) throw Error('Usage: node scripts/compute-guest-probe.mjs snp|tdx [http://127.0.0.1:8006]');
  console.log(JSON.stringify(await probeGuestAgent({ tee, agentUrl }), null, 2));
} catch (error) { console.error(JSON.stringify({ error: error.message })); process.exitCode = 1; }
