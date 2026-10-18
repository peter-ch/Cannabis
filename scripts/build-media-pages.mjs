import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { assertPublicNarration } from './media-metadata.mjs';
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
function page(title, intro, body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(title)} / Cannabis</title><meta name="description" content="${escape(intro)}"><link rel="icon" href="/assets/emblem.png"><link rel="stylesheet" href="/style.css"></head><body><div class="notice">PREPARING MAINNET LAUNCH</div><header><a class="wordmark" href="/">✳ Cannabis</a><nav aria-label="Main navigation"><a href="/collection.html">Artwork</a><a href="/network.html">Compute</a><a href="/learn.html">Films</a></nav></header><main class="library"><div class="library-intro"><div class="eyebrow">CANNABIS / EXPLORE THE PROJECT</div><h1>${escape(title)}</h1><p>${escape(intro)}</p></div>${body}</main><footer><a class="wordmark" href="/">✳ Cannabis</a><p>Open code. Visible rules. Useful work.<br>Original artwork and English narration.</p><a href="https://github.com/peter-ch/Cannabis">Explore the code ↗</a></footer></body></html>\n`;
}
export function buildMediaPages(out) {
  const sets = [
    ['Landscape', [['lustre','Lustre','Faceted emerald leaf and platinum circle in soft daylight'],['dawn','First light','Emerald crystal in warm sunrise light'],['tide','Still water','Emerald crystal and clean reflective water'],['prism','Prismatic','Emerald facets and natural rainbow refractions']]],
    ['Square', [['purity','Purity','Emerald crystal leaf on clear quartz'],['crown','Crown','Polished emerald crystal centerpiece'],['dew','Dew','Emerald crystal and fresh water droplets'],['facets','Facets','Luminous emerald facets and polished metal']]],
    ['Portrait', [['prestige','Prestige','Emerald crystal on a dark polished pedestal'],['monolith','Monolith','Tall sculptural emerald crystal composition'],['waterfall','Waterfall','Emerald crystal with flowing clear water'],['aurora','Aurora','Emerald crystal illuminated by vivid natural light']]]
  ];
  let gallery='';
  for (const [format,arts] of sets) gallery+=`<section class="library-section"><h2>${format}</h2><div class="art-grid">${arts.map(([id,title,alt])=>`<figure><a href="/assets/crystal-${id}.png"><img src="/assets/crystal-${id}.png" alt="${alt}" loading="lazy"></a><figcaption><strong>${title}</strong><a href="/assets/crystal-${id}.png" download>Download PNG ↗</a></figcaption></figure>`).join('')}</div></section>`;
  gallery+='<p class="micro">Twelve original brand images in three compositions. Crystal and metal are artistic motifs.</p>';
  fs.writeFileSync(path.join(out,'collection.html'),page('The crystal collection.','Emerald depth. Clean light. Natural sparkle. Artwork made to share.',gallery));
  const diagrams=[['compute-network-client','From your job to your result','Declare the task graph, encrypt the package, use attested workers, then verify, decrypt and assemble outputs on your own client. Payments flow from requester to escrow to workers, with the disclosed founder fee.'],['compute-packages','Inside an encrypted job','Private code and inputs enter a protected execution boundary. Keys are released only after policy-bound attestation. Resource metadata and public payments remain visible.'],['compute-pricing','Clear quotes. Fair settlement.','Illustrative arithmetic: worker subtotals of 40, 30 and 20 plus an agreed completion bonus of 10 give a gross budget of 100. An accepted payment sends 99 to workers and 1 to the founder. These are explanatory numbers, not live market quotes.']];
  let network='<section class="economy-card"><div class="eyebrow">MONEY FOR USEFUL COMPUTING</div><h2>Real services. Defined commitments.</h2><p>Cannabis aims to connect token payments with useful computing and redeemable provider capacity. Providers must publish what they can deliver, at what price, and under which deadlines and remedies.</p><p>Capacity redemption and confidential workers are being prepared. The client and escrow implementation are available for review.</p><a class="text-link" href="/docs/compute-economy.md">Read the economic design ↗</a></section>';
  network+=diagrams.map(([id,title,description])=>`<section class="diagram-section"><h2>${title}</h2><p>${description}</p><a href="/assets/diagrams/${id}.png"><img src="/assets/diagrams/${id}.png" alt="${escape(description)}" loading="lazy" width="1672" height="941"></a><a class="text-link" href="/assets/diagrams/${id}.png" download>Download full-size diagram ↗</a></section>`).join('');
  network+='<div class="doc-links"><a href="/docs/universal-compute.md">Universal workload client ↗</a><a href="/docs/confidential-compute.md">Protected execution ↗</a><a href="/docs/compute-payments.md">Escrow, review windows and disputes ↗</a></div><p class="micro">Architecture illustrations. Protected worker execution, metered pricing, capacity reservation and mainnet settlement require integration and review. The current escrow uses fixed budgets and agreed worker shares. Undisputed deliveries become payable after their review window expires.</p>';
  fs.writeFileSync(path.join(out,'network.html'),page('Put compute to work.','A general-purpose network design: package software, find suitable capacity, protect execution and bring the result home.',network));
  const films=JSON.parse(fs.readFileSync(path.join(root,'media/series/scripts.json'))).films.slice().sort((a,b)=>a.id.localeCompare(b.id));
  let lessons='<div class="lesson-grid">';
  for (const film of films) {
    verifyFilmNarration(film);
    const ready=filmReady(film, 'landscape');
    const portrait=filmReady(film, 'portrait');
    const art=film.art.find(x=>x.startsWith('crystal-')) || 'crystal-lustre';
    lessons+=`<article class="lesson"><div class="eyebrow">FILM ${film.id.slice(0,2)}</div><h2>${escape(displayText(film.title))}</h2>${ready?`<video controls playsinline preload="none" poster="/assets/${art}.png" aria-label="${escape(displayText(film.title))}"><source src="/media/series/${film.id}-landscape.mp4" type="video/mp4"><track kind="captions" src="/media/series/${film.id}.vtt" srclang="en" label="English"></video><p>${portrait?`<a href="/media/series/${film.id}-portrait.mp4">Vertical film ↗</a> · `:''}<a href="/media/series/${film.id}.srt">Captions ↗</a></p>`:'<p class="status-tag">FILM IN PRODUCTION</p>'}<details><summary>Read the film text</summary>${film.lines.map(line=>`<p>${escape(displayText(line))}</p>`).join('')}</details></article>`;
  }
  lessons+='</div><p class="micro">English narration, cinematic animation and accessible captions. Films are published after review. Films explain the published design and launch status.</p>';
  fs.writeFileSync(path.join(out,'learn.html'),page('Meet Cannabis. Learn the design.','Short films about participation, useful computing, privacy, pricing and visible rules.',lessons));
}
