import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import MarkdownIt from 'markdown-it';
import { page } from './build-media-pages.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const escape = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const guideGroups = [
  ['start', 'Start here', 'Get to know the idea and prepare to participate.', [
    ['technical-paper', 'The technical paper', 'Supply, eligibility privacy and the computing architecture in one place.'],
    ['windows-setup', 'The Windows guide', 'Create your participation identity and verify your portable backup.'],
    ['community-claims', 'Community participation', 'Understand eligibility, the common opening and one-person claims.'],
    ['energy', 'Efficient by design', 'Useful work without a proof-of-work mining race.'],
    ['privacy-security', 'Privacy and security', 'What stays private, what remains public and how the protections fit together.']
  ]],
  ['compute', 'Useful computing', 'From a software task to an accepted result.', [
    ['useful-compute', 'Put compute to work', 'Explore the service, compatible hardware and useful workloads.'],
    ['compute-economy', 'The computing economy', 'How payments, service commitments and real delivery connect.'],
    ['universal-compute', 'Package a workload', 'Runtime adapters, task graphs and requester-side result assembly.'],
    ['compute-payments', 'Job payments', 'Budgets, acceptance, review windows, disputes and refunds.'],
    ['microjobs', 'Small jobs', 'Exact fees and ways to reduce transaction overhead for small payments.'],
    ['capacity-commitments', 'Provider capacity', 'Signed offers, reservations and fulfillment commitments.'],
    ['../compute/README', 'Compute software', 'Commands, job manifests and the software components.'],
    ['../compute/examples/README', 'Workload examples', 'A starting point for an application-specific execution contract.']
  ]],
  ['identity', 'Identity and eligibility', 'Participation with secrets held on your own device.', [
    ['claim-identity', 'Your claim identity', 'Create, recover and use a private eligibility identity.'],
    ['person-verification', 'Person verification', 'Distinct-person enrollment and non-biometric provider integration.'],
    ['membership-snapshot', 'Membership snapshots', 'Download and check the complete enrollment group before proving.']
  ]],
  ['protected', 'Protected execution', 'The details behind confidential computing.', [
    ['confidential-compute', 'Confidential computation', 'Protect customer code and data while the job runs.'],
    ['job-key-custody', 'Job key custody', 'Separate encrypted input keys and requester-controlled output keys.'],
    ['trustee-attestation', 'Attestation before access', 'Check signed evidence before authorizing a protected worker.'],
    ['key-delivery', 'Encrypted key delivery', 'Bind each key envelope to the approved job and guest channel.'],
    ['worker-deployment', 'Worker deployment', 'The acceptance requirements for a confidential worker.'],
    ['guest-attestation', 'Guest evidence', 'Connect guest-held channels with hardware evidence.'],
    ['guest-workload', 'The approved workload', 'Move from an attested session to the protected workload.'],
    ['guest-service-build', 'Build guest services', 'Reproduce the pinned evidence-service binaries.'],
    ['guest-image-build', 'Build a guest image', 'Assemble and check the kernel and boot filesystem.'],
    ['guest-firmware', 'Build guest firmware', 'Pinned firmware builds and SNP reference measurements.']
  ]],
  ['release', 'Release and terms', 'Published parameters and the path to mainnet.', [
    ['tokenomics', 'Allocation and service terms', 'Supply, community claims, founder vesting and service fees.'],
    ['mainnet-release', 'The mainnet release', 'The canonical release package and deployment requirements.'],
    ['dependency-verification', 'Verify dependencies', 'Check the verifier, library and network dependencies.'],
    ['deployment-fees', 'Deployment costs', 'Read unsigned network-fee estimates before deployment.'],
    ['launch-plan', 'Launch acceptance', 'The required milestones for a reviewed public opening.'],
    ['launch-review', 'Launch review', 'Legal and operational review before a public offer or listing.'],
    ['risks', 'Participation risks', 'The material risks to understand before taking part.']
  ]]
];

export function guideRoutes() {
  return new Map(guideGroups.flatMap(([, , , guides]) => guides.map(([slug]) => {
    const source = path.posix.normalize(`docs/${slug}.md`);
    return [source, source.replace(/README\.md$/, 'index.html').replace(/\.md$/, '.html')];
  })));
}

// Only local documentation URLs are rewritten. External source references stay intact.
export function resolveGuideLink(href, source, routes = guideRoutes()) {
  if (/^(?:[a-z][a-z\d+.-]*:|\/\/|#)/i.test(href)) return href;
  const [, pathname, suffix = ''] = /^([^?#]*)(.*)$/.exec(href);
  const absolute = path.posix.normalize(pathname.startsWith('/') ? pathname.slice(1) : path.posix.join(path.posix.dirname(source), pathname));
  const target = routes.get(absolute) ?? routes.get(absolute.replace(/\/$/, '') + '/README.md');
  if (!target) return href;
  const output = routes.get(source) ?? source;
  return (path.posix.relative(path.posix.dirname(output), target) || path.posix.basename(target)) + suffix;
}

const parser = new MarkdownIt({ html: false, linkify: true, typographer: false });
const plain = token => (token.children ?? []).map(child => child.type === 'image' ? child.content : child.children ? plain(child) : child.content).join('');

export function renderGuide(markdown, source, routes = guideRoutes()) {
  const tokens = parser.parse(markdown, {});
  const headings = [], used = new Set();
  let title = 'Cannabis guide';
  if (tokens[0]?.type === 'heading_open' && tokens[0].tag === 'h1') {
    title = plain(tokens[1]);
    tokens.splice(0, 3);
  }
  function rewrite(tokens) {
    for (const token of tokens) {
      if (token.type === 'link_open') token.attrSet('href', resolveGuideLink(token.attrGet('href'), source, routes));
      if (token.children) rewrite(token.children);
    }
  }
  rewrite(tokens);
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (token.type !== 'heading_open') continue;
    const label = plain(tokens[i + 1]);
    const base = label.toLowerCase().replace(/[^\p{L}\p{N}\s_-]/gu, '').trim().replace(/\s/g, '-') || 'section';
    let id = base, count = 1;
    while (used.has(id)) id = `${base}-${count++}`;
    used.add(id); token.attrSet('id', id);
    if (token.tag === 'h1') { token.tag = 'h2'; tokens[i + 2].tag = 'h2'; }
    headings.push({ id, label, level: Number(token.tag.slice(1)) });
  }
  const html = parser.renderer.render(tokens, parser.options, {}).replace(/<table>/g, '<div class="guide-table" role="region" aria-label="Scrollable reference table" tabindex="0"><table>').replace(/<\/table>/g, '</table></div>');
  return { title, html, headings, minutes: Math.max(1, Math.ceil(markdown.split(/\s+/).length / 220)) };
}

export function buildDocPages(out) {
  const routes = guideRoutes();
  const actual = fs.readdirSync(path.join(root, 'docs')).filter(name => name.endsWith('.md')).map(name => `docs/${name}`);
  for (const file of actual) if (!routes.has(file)) throw Error(`Add this guide to the documentation navigation: ${file}`);
  const catalog = guideGroups.map(([id, title, description, guides]) => ({ id, title, description, guides: guides.map(([slug, label, summary]) => {
    const source = path.posix.normalize(`docs/${slug}.md`);
    return { source, target: routes.get(source), label, summary, ...renderGuide(fs.readFileSync(path.join(root, source), 'utf8'), source, routes) };
  }) }));
  for (const group of catalog) for (const guide of group.guides) {
    const toc = guide.headings.filter(heading => heading.level === 2).map(heading => `<a href="#${escape(heading.id)}">${escape(heading.label)}</a>`).join('');
    const related = group.guides.filter(other => other !== guide).map(other => `<a href="/${other.target}">${escape(other.label)}<span aria-hidden="true">↗</span></a>`).join('');
    const body = `<div class="guide-breadcrumb"><a href="/docs/index.html">Guides</a><span aria-hidden="true">/</span><a href="/docs/index.html#${group.id}">${group.title}</a></div>
      <div class="guide-layout"><article class="guide-article"><header class="guide-header"><p class="eyebrow">${group.title.toUpperCase()} <span aria-hidden="true">/</span> ${guide.minutes} MIN READ</p><h1>${escape(guide.title)}</h1><p class="guide-deck">${escape(guide.summary)}</p></header>
      ${toc ? `<details class="guide-mobile-toc"><summary>On this page</summary><nav aria-label="Sections on this page">${toc}</nav></details>` : ''}
      <div class="guide-prose">${guide.html}</div><div class="guide-end"><a class="text-link" href="/docs/index.html">← All guides</a><a class="text-link" href="https://github.com/peter-ch/Cannabis/blob/main/${guide.source}">View source on GitHub ↗</a></div></article>
      <aside class="guide-sidebar">${toc ? `<div><p class="eyebrow">ON THIS PAGE</p><nav aria-label="Sections on this page">${toc}</nav></div>` : ''}<div><p class="eyebrow">${group.title.toUpperCase()}</p><nav aria-label="Related guides">${related}</nav></div><a class="guide-sidebar-all" href="/docs/index.html">Browse all guides <span aria-hidden="true">↗</span></a></aside></div>`;
    const target = path.join(out, guide.target);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, page(guide.title, guide.summary, body, { mainClass: 'documentation', showIntro: false }));
  }
  const hero = `<section class="guides-hero"><div><p class="eyebrow">CANNABIS / THE KNOWLEDGE GARDEN</p><h1>Big ideas.<br><span class="accent">Clear answers.</span></h1><p>Find your starting point. Explore the community, understand the network, or get into the details of building with Cannabis.</p><a class="text-link" href="/docs/windows-setup.html">New here? Start with the Windows guide ↗</a></div><img src="/assets/crystal-prism.webp" alt="Light passing through an emerald crystal sculpture" width="1672" height="941"></section>`;
  const search = `<div class="guide-search" data-guide-search hidden><label for="guide-query">Find a guide</label><div><input id="guide-query" type="search" placeholder="Try privacy, payments or Windows" autocomplete="off"><span data-guide-count role="status" aria-live="polite">${routes.size} guides</span></div></div>`;
  const categories = `<nav class="guide-categories" aria-label="Guide topics">${catalog.map(group => `<a href="#${group.id}">${group.title}</a>`).join('')}</nav>`;
  const sections = catalog.map((group, index) => `<section class="guide-group" id="${group.id}" data-guide-group><div class="guide-group-heading"><span class="eyebrow">0${index + 1}</span><div><h2>${group.title}</h2><p>${group.description}</p></div></div><div class="guide-grid">${group.guides.map(guide => `<a class="guide-card" href="/${guide.target}" data-guide-card><span class="guide-card-arrow" aria-hidden="true">↗</span><h3>${escape(guide.label)}</h3><p>${escape(guide.summary)}</p><span class="guide-card-meta">${guide.minutes} min read</span></a>`).join('')}</div></section>`).join('');
  fs.writeFileSync(path.join(out, 'docs/index.html'), page('Guides', 'Explore Cannabis: community participation, useful computing, privacy and technical guides.', hero + search + categories + sections + '<p class="guide-no-results" data-guide-empty hidden>No matching guides. Try a different word or clear the search.</p>', { mainClass: 'documentation guide-home', showIntro: false, script: '/docs.js' }));
  return routes;
}
