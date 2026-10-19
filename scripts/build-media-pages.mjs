import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { assertPublicNarration } from './media-metadata.mjs';
import { editorialArt } from './editorial-art.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const escape = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const hash = value => createHash('sha256').update(value).digest('hex');
export const displayText = value => String(value).replace(/\bCannabis coin\b/gi, 'Cannabis');
export function verifyCaptionText(file, spoken) {
  const blocks = fs.readFileSync(file, 'utf8').replaceAll('\r', '').trim().split(/\n\s*\n/).filter(block => block !== 'WEBVTT');
  const text = blocks.map(block => {
    const lines = block.split('\n');
    const timing = lines.findIndex(line => line.includes(' --> '));
    if (timing < 0 || timing > 1 || timing === lines.length - 1) throw Error(`Invalid caption cue: ${path.basename(file)}`);
    return lines.slice(timing + 1).join(' ');
  }).join(' ').replace(/\s+/g, ' ').trim();
  if (text !== displayText(spoken).replace(/\s+/g, ' ').trim()) throw Error(`Outdated caption text: ${path.basename(file)}`);
}
function verifyFilmNarration(film) {
  const base = path.join(root, 'media/series', film.id);
  const spoken = film.lines.join('\n');
  const record = JSON.parse(fs.readFileSync(base + '.json'));
  assertPublicNarration(record);
  if (/\bCannabis\b(?! coin\b)/i.test(spoken) || record.text !== spoken || record.scriptSHA256 !== hash(spoken) ||
      record.segments.map(segment => segment.text).join('\n') !== spoken ||
      fs.readFileSync(base + '.txt', 'utf8').replace(/\r\n?/g, '\n').trim() !== spoken ||
      !/^[a-f0-9]{64}$/.test(record.wavSHA256)) {
    throw Error(`Outdated narration assets: ${film.id}`);
  }
  for (const extension of ['srt', 'vtt']) {
    if (fs.existsSync(base + '.' + extension)) verifyCaptionText(base + '.' + extension, spoken);
  }
}
function filmReady(film, format) {
  const id = film.id;
  const file = path.join(root, 'media/series', `${id}-${format}.mp4`);
  const report = path.join(root, 'media/series', `${id}-${format}.render.json`);
  if (!fs.existsSync(file) && !fs.existsSync(report)) return false;
  if (!fs.existsSync(file) || !fs.existsSync(report)) throw Error(`Incomplete film export: ${id}-${format}`);
  const record = JSON.parse(fs.readFileSync(report));
  const spoken = film.lines.join('\n');
  const scriptHash = createHash('sha256').update(spoken).digest('hex');
  const narration = JSON.parse(fs.readFileSync(path.join(root, 'media/series', `${id}.json`)));
  if (/\bCannabis\b(?! coin\b)/i.test(spoken) || record.scriptSHA256 !== scriptHash ||
      narration.scriptSHA256 !== scriptHash || narration.text !== spoken ||
      !/^[a-f0-9]{64}$/.test(narration.wavSHA256) || record.voiceSHA256 !== narration.wavSHA256) {
    throw Error(`Outdated voiceover: ${id}-${format}`);
  }
  const [width, height] = format === 'portrait' ? [1080, 1920] : [1920, 1080];
  const bytes = fs.readFileSync(file);
  if (record.bytes !== bytes.length || record.sha256 !== createHash('sha256').update(bytes).digest('hex') ||
      record.width !== width || record.height !== height || record.fps !== 24 || record.videoCodec !== 'h264' ||
      record.audioStreams !== 1 || record.audioCodec !== 'aac' || record.audio !== 'English narration only' ||
      !Number.isFinite(record.seconds) || record.seconds <= 0) throw Error(`Film export verification failed: ${id}-${format}`);
  for (const extension of ['srt', 'vtt']) {
    const captions = path.join(root, 'media/series', `${id}.${extension}`);
    if (!fs.existsSync(captions)) throw Error(`Missing ${extension} captions: ${id}`);
    if (record.captionsSHA256?.[extension] !== hash(fs.readFileSync(captions))) throw Error(`Changed ${extension} captions: ${id}`);
  }
  return true;
}
export function page(title, intro, body, { mainClass = 'library', showIntro = true, script = null } = {}) {
  const artwork = { 'Pass the spark on.': 'community-garden',
    'Your place starts here.': 'creation-atelier', 'Put compute to work.': 'network-constellation',
    'Meet Cannabis. Put ideas to work.': 'launch-horizon', 'Allocation and service terms.': 'payment-current' }[title] ?? 'knowledge-prism';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#07130f"><title>${escape(title)} / Cannabis</title><meta name="description" content="${escape(intro)}"><meta property="og:title" content="${escape(title)} / Cannabis"><meta property="og:description" content="${escape(intro)}"><meta property="og:image" content="https://cannabis-coin.online/assets/campaign/purpose-landscape.png"><meta name="twitter:card" content="summary_large_image"><link rel="icon" href="/assets/emblem.png"><link rel="stylesheet" href="/style.css">${script ? `<script src="${escape(script)}" defer></script>` : ''}</head><body><a class="skip-link" href="#main">Skip to content</a><div class="notice"><span class="status-dot" aria-hidden="true"></span> Preparing mainnet launch <a href="/#launch">Follow the progress ↗</a></div><header class="site-header"><a class="wordmark" href="/" aria-label="Cannabis home"><span class="brand-symbol" aria-hidden="true">✳</span> Cannabis<span class="brand-dot">.</span></a><nav aria-label="Main navigation"><a href="/network.html">The network</a><a href="/work.html">Your work</a><a href="/docs/index.html">Guides</a><a class="nav-join" href="/#join">Find your place <span aria-hidden="true">↗</span></a></nav></header><main class="${escape(mainClass)}" id="main">${showIntro ? `<div class="library-hero"><div class="library-intro"><div class="eyebrow">CANNABIS / OPEN TO POSSIBILITY</div><h1>${escape(title)}</h1><p>${escape(intro)}</p></div>${editorialArt(artwork, "editorial-art library-art", "eager")}</div>` : ''}${body}</main><footer class="site-footer"><div class="footer-top"><a class="wordmark" href="/">✳ Cannabis<span class="brand-dot">.</span></a><p>Grow like nature. Power what’s next.</p><div><a href="/share.html">Share Cannabis</a><a href="/docs/index.html">Guides</a><a href="https://github.com/peter-ch/Cannabis">Explore the code ↗</a></div></div><div class="footer-bottom"><p>Preparing mainnet launch. Wallet transactions remain public.</p><div><a href="/#donate">Donate</a><a href="/terms.html">Allocation & service terms</a><a href="/docs/risks.html">Risks</a><a href="/docs/privacy-security.html">Privacy</a></div></div></footer></body></html>\n`;
}
export function buildMediaPages(out) {
  // Old collection bookmarks return to the site; artwork belongs in each page.
  fs.writeFileSync(path.join(out, 'collection.html'), '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><meta http-equiv="refresh" content="0;url=./"><title>Cannabis</title></head><body><a href="/">Continue to Cannabis</a></body></html>');
  const share = `<div class="share-intro"><p>A spark travels further when people pass it on. Add your perspective and invite someone curious to explore Cannabis.</p></div><section class="share-copy"><h2>Start a conversation.</h2><blockquote>Cannabis. Grow like nature. Power what’s next. An open community building a currency for useful computing. Bring your ideas, explore the code and help shape what comes next.</blockquote>${editorialArt("metal-maker", "editorial-art inline-people")}<div class="actions"><a class="button" href="/assets/campaign/cannabis-graphics.zip" download>Download sharing kit</a><a class="text-link" href="/network.html">Explore the network ↗</a></div></section><p class="micro">Use the supplied graphics with their launch status intact. Share with communities that welcome the project, and link to the website for details and terms.</p>`;
  fs.writeFileSync(path.join(out,'share.html'),page('Pass the spark on.','Share an idea. Invite a curious mind. Help useful computing grow.',share));
  const setup = `<div class="setup-layout"><section class="setup-panel"><div class="eyebrow">WINDOWS / YOUR OWN DEVICE</div><h2>Make your first move.</h2><p>The guided Windows tools help you create your own participation identity and a portable backup. Your secrets stay on your device. No wallet seed is required.</p><div class="actions"><a class="button" href="https://github.com/peter-ch/Cannabis/releases/tag/windows-tools-2026.10.19">Get the Windows kit <span aria-hidden="true">↗</span></a><a class="text-link" href="/docs/windows-setup.html">Read the complete guide ↗</a></div><ol class="setup-steps"><li><span>01</span><div><h3>Make it yours.</h3><p>Review the release, extract the download and open <strong>Start-Cannabis.cmd</strong>. Choose “Create my identity” or restore an existing one.</p></div></li><li><span>02</span><div><h3>Keep recovery in your hands.</h3><p>Save a password-encrypted backup, then use “Restore or verify a backup” to check it. Keep your passphrase separate and private.</p></div></li><li><span>03</span><div><h3>Be ready for the opening.</h3><p>After a successful recovery check, prepare your enrollment request. Keep it private until the official verification flow asks for it.</p></div></li></ol></section><figure class="setup-art"><img src="/assets/crystal-aurora.webp" alt="Emerald crystal catching sunlight in a clear glass gallery" width="941" height="1672"><figcaption>GOOD THINGS GROW TOGETHER.</figcaption></figure></div>${editorialArt("night-builder", "editorial-art inline-people")}<section class="economy-card"><div class="eyebrow">WHERE WE ARE TODAY</div><h2>Preparation now. Participation together.</h2><p>The tools prepare identity custody and an enrollment request. Cannabis will run recurring synchronized in-person ceremonies, with later rounds for future newcomers. Enrollment and claims open after the human-verification process and mainnet release complete review. The verified release will publish the contracts, ceremony policy and common opening time.</p><p>Read the eligibility, allocation and service terms before participating. The Windows tools still require independent custody review; ARM64 support needs platform validation. Your identity backup is separate from any wallet recovery.</p><div class="doc-links"><a href="/docs/community-claims.html">Community participation ↗</a><a href="/terms.html">Allocation & service terms ↗</a><a href="/docs/privacy-security.html">Privacy design ↗</a><a href="/docs/risks.html">Risks ↗</a></div></section>`;
  fs.writeFileSync(path.join(out,'start.html'),page('Your place starts here.','Prepare for community participation with the Windows guide. Your identity, your backup, your next chapter.',setup));
  const diagrams=[['compute-network-client','From your job to your result','Declare the task graph, encrypt the package, use attested workers, then verify, decrypt and assemble outputs on your own client. Payments flow from requester to escrow to workers, with the disclosed founder fee.'],['compute-packages','Inside an encrypted job','Private code and inputs enter a protected execution boundary. Keys are released only after policy-bound attestation. Resource metadata and public payments remain visible.'],['compute-pricing','Clear quotes. Fair settlement.','Illustrative arithmetic: worker subtotals of 40, 30 and 20 plus an agreed completion bonus of 10 give a gross budget of 100. An accepted payment sends 99 to workers and 1 to the founder. These are explanatory numbers, not live market quotes.']];
  let network='<section class="economy-card"><div class="eyebrow">MONEY FOR USEFUL COMPUTING</div><h2>Real services. Defined commitments.</h2><p>Cannabis aims to connect token payments with useful computing and redeemable provider capacity. Providers must publish what they can deliver, at what price, and under which deadlines and remedies.</p><p>Capacity redemption and confidential workers are being prepared. The client and escrow implementation are available for review.</p><a class="text-link" href="/docs/compute-economy.html">Read the economic design ↗</a></section>';
  const distribution=JSON.parse(fs.readFileSync(path.join(root,'media/distribution.json')));
  const diagramSection=([id,title,description])=>`<section class="diagram-section"><h2>${title}</h2><p>${description}</p><img src="/assets/diagrams/${id}.png" alt="${escape(description)}" loading="lazy" width="1672" height="941"><a class="text-link" href="/assets/diagrams/${id}.png" download>Download full-size diagram ↗</a></section>`;
  network+=editorialArt('workshop-engineer', 'editorial-art inline-people');
  network+=diagrams.filter(([id])=>!distribution.termsDiagrams.includes(id)).map(diagramSection).join('');
  network+='<div class="doc-links"><a href="/docs/universal-compute.html">Universal workload client ↗</a><a href="/docs/confidential-compute.html">Protected execution ↗</a><a href="/docs/compute-payments.html">Escrow, review windows and disputes ↗</a></div><p class="micro">Architecture illustrations. Protected worker execution, metered pricing, capacity reservation and mainnet settlement require integration and review. The current escrow uses fixed budgets and agreed worker shares. Undisputed deliveries become payable after their review window expires.</p>';
  fs.writeFileSync(path.join(out,'network.html'),page('Put compute to work.','A general-purpose network design: package software, find suitable capacity, protect execution and bring the result home.',network));
  const films=JSON.parse(fs.readFileSync(path.join(root,'media/series/scripts.json'))).films.slice().sort((a,b)=>a.id.localeCompare(b.id));
  const routed=[...distribution.promotionalFilms,...distribution.termsFilms];
  if(new Set(routed).size!==routed.length || routed.length!==films.length || films.some(film=>!routed.includes(film.id))) throw Error('Each film needs exactly one reviewed distribution category');
  const cards=new Map();
  const withheld = new Set(distribution.withheldFilms ?? []);
  if ([...withheld].some(id => !routed.includes(id))) throw Error('Unknown withheld film');
  for (const film of films.filter(film => !withheld.has(film.id))) {
    verifyFilmNarration(film);
    const ready=filmReady(film, 'landscape');
    const portrait=filmReady(film, 'portrait');
    const format=ready?'landscape':portrait?'portrait':null;
    const art=film.art.find(x=>x.startsWith('crystal-')) || 'crystal-lustre';
    cards.set(film.id,`<article class="lesson"><div class="eyebrow">FILM ${film.id.slice(0,2)}</div><h2>${escape(displayText(film.title))}</h2>${format?`<video class="${format}" controls playsinline preload="none" poster="/assets/${art}.webp" aria-label="${escape(displayText(film.title))}"><source src="/media/series/${film.id}-${format}.mp4" type="video/mp4"><track kind="captions" src="/media/series/${film.id}.vtt" srclang="en" label="English"></video><p><a href="/media/series/${film.id}-${format}.mp4" download>Download film ↗</a> · ${ready&&portrait?`<a href="/media/series/${film.id}-portrait.mp4">Vertical film ↗</a> · `:''}<a href="/media/series/${film.id}.srt">Captions ↗</a></p>`:'<p class="status-tag">FILM IN PRODUCTION</p>'}<details><summary>Read the film text</summary>${film.lines.map(line=>`<p>${escape(displayText(line))}</p>`).join('')}</details></article>`);
  }
  const lessons=editorialArt('hiphop-maker', 'editorial-art inline-people')+'<div class="lesson-grid">'+distribution.promotionalFilms.filter(id=>cards.has(id)).map(id=>cards.get(id)).join('')+'</div><p class="micro">English narration, cinematic animation and accessible captions. Further films appear after review. <a href="/terms.html">Allocation and payment guides ↗</a></p>';
  fs.writeFileSync(path.join(out,'learn.html'),page('Meet Cannabis. Put ideas to work.','Short films about community, useful computing and protected workloads.',lessons));
  const terms=`<section class="terms-summary"><h2>Allocation and vesting</h2><table><thead><tr><th scope="col">Term</th><th scope="col">Published parameter</th></tr></thead><tbody><tr><th scope="row">Supply cap</th><td>420,000,000 Cannabis</td></tr><tr><th scope="row">Community allocation</th><td>99% — 415,800,000 Cannabis</td></tr><tr><th scope="row">Founder allocation</th><td>1% — 4,200,000 Cannabis, locked at creation and released linearly over 24 calendar months from the common public opening</td></tr><tr><th scope="row">Community claims</th><td>420 once per eligible verified person; up to 990,000 people</td></tr></tbody></table><h2>Claim minimum</h2><p>The initial claim minimum is configurable and defaults to one verified member. The founder wallet may raise it only up to the already enrolled count, without revoking completed claims or blocking eligible members. Changes are recorded on-chain. One-member groups have no membership anonymity; small groups limit privacy. <a href="/docs/community-claims.html#configurable-claim-minimum">Read the controls and limits</a>.</p><h2>Service fee and payment rules</h2><p>The founder service fee is <strong>1% of accepted paid work</strong>, included in the gross job budget and separate from the founder token allocation. An accepted payment of 100 Cannabis distributes 99 to workers and 1 to the founder. Refunded amounts incur no founder service fee. Network transaction fees are separate.</p><p>Quotes and payment preparation show the fee, worker amount and total before the requester commits funds. Read the review-window, dispute, cancellation and refund rules before submitting a job.</p><div class="doc-links"><a href="/docs/tokenomics.html">Complete allocation and service terms ↗</a><a href="/docs/compute-payments.html">Payment rules ↗</a><a href="/docs/community-claims.html">Claim eligibility ↗</a><a href="/docs/risks.html">Risks ↗</a></div><p>These parameters describe the current implementation. Mainnet deployment, enrollment and protected worker operation remain in preparation; independent security and privacy review is outstanding.</p></section>${editorialArt("morning-founder", "editorial-art terms-people")}<section class="library-section"><h2>Allocation and payment guides</h2><div class="lesson-grid">${distribution.termsFilms.filter(id=>cards.has(id)).map(id=>cards.get(id)).join('')}</div></section>${diagrams.filter(([id])=>distribution.termsDiagrams.includes(id)).map(diagramSection).join('')}<section class="library-section"><h2>Launch terms overview</h2><p>The narrated overview includes allocation disclosures. <a href="/media/cannabis-landscape.mp4">Landscape overview ↗</a> · <a href="/media/cannabis-portrait.mp4">Vertical overview ↗</a> · <a href="/media/narration.txt">Transcript ↗</a></p></section>`;
  fs.writeFileSync(path.join(out,'terms.html'),page('Allocation and service terms.','Read the supply, vesting, eligibility and payment rules before participating.',terms));
}
