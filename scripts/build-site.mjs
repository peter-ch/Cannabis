import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildMediaPages, displayText, verifyCaptionText } from './build-media-pages.mjs';
import { createHash } from 'node:crypto';
import { assertPublicNarration } from './media-metadata.mjs';
import { buildDocPages, resolveGuideLink } from './build-doc-pages.mjs';
import { build } from 'esbuild';
import { bundleNotices } from './bundle-notices.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = path.join(root, 'dist-site');
const siteOrigin = 'https://cannabis-coin.online';
const narration = JSON.parse(fs.readFileSync(path.join(root, 'media/narration.json')));
assertPublicNarration(narration);
const spoken = fs.readFileSync(path.join(root, 'media/narration.txt'), 'utf8').replace(/\r\n?/g, '\n').trim();
const scriptHash = createHash('sha256').update(spoken).digest('hex');
const voiceHash = createHash('sha256').update(fs.readFileSync(path.join(root, 'media/narration.wav'))).digest('hex');
if (/\bCannabis\b(?! coin\b)/i.test(spoken) || narration.scriptSHA256 !== scriptHash || narration.text !== spoken || narration.wavSHA256 !== voiceHash) {
  throw Error('Original promo voiceover is outdated');
}
verifyCaptionText(path.join(root, 'media/captions.srt'), spoken);
const captionHash = createHash('sha256').update(fs.readFileSync(path.join(root, 'media/captions.srt'))).digest('hex');
for (const format of ['landscape', 'portrait']) {
  const file = path.join(root, 'media', `cannabis-${format}.mp4`);
  if (!fs.existsSync(file)) continue;
  const record = JSON.parse(fs.readFileSync(file.replace(/\.mp4$/, '.render.json')));
  const bytes = fs.readFileSync(file);
  if (record.scriptSHA256 !== scriptHash || record.voiceSHA256 !== voiceHash || record.captionsSHA256 !== captionHash || record.bytes !== bytes.length || record.sha256 !== createHash('sha256').update(bytes).digest('hex')) {
    throw Error(`Original promo export is outdated: ${format}`);
  }
}
if (fs.existsSync(out)) {
  const resolved = fs.realpathSync(out);
  if (path.dirname(resolved) !== fs.realpathSync(root) || path.basename(resolved) !== 'dist-site') throw Error('Unexpected build-directory target');
  fs.rmSync(resolved, { recursive: true, force: true, maxRetries: 12, retryDelay: 250 });
}
fs.mkdirSync(out, { recursive: true });
fs.cpSync(path.join(root, 'web'), out, { recursive: true });
const workPage=path.join(out,'work.html');
fs.writeFileSync(workPage,fs.readFileSync(workPage,'utf8').replace('<!-- CANNABIS_MARKET_PANEL -->',fs.readFileSync(path.join(root,'operator/market-panel.html'),'utf8')));
fs.copyFileSync(path.join(root,'operator/market.css'),path.join(out,'market.css'));
const walletSource={name:'shared-market-wallet',setup(builder){builder.onResolve({filter:/market-wallet\.js$/},args=>{
  if(path.resolve(args.resolveDir,args.path)===path.join(root,'operator/market-wallet.js'))return {path:path.join(root,'operator/market-wallet-source.js')};
});}};
const bundled = await build({ absWorkingDir: root, entryPoints: [path.join(root, 'web/work.js')], outfile: path.join(out, 'work.js'), bundle: true, format: 'esm', platform: 'browser', target: 'es2023', minify: true, legalComments: 'linked', metafile: true,plugins:[walletSource] });
bundleNotices(bundled.metafile, root, path.join(out, 'work.js.LEGAL.txt'));
for(const name of ['work-results.js','work-approvals.js','work-inbox.js','work-relay.js','work-market.js','work-payment.js','market-journal.js','market-order-form.js'])
  if(fs.existsSync(path.join(out,name)))fs.unlinkSync(path.join(out,name)); // bundled; no bare npm imports
buildMediaPages(out);
fs.cpSync(path.join(root, 'docs'), path.join(out, 'docs'), { recursive: true });
fs.cpSync(path.join(root, 'compute'), path.join(out, 'compute'), { recursive: true,
  filter: source => fs.statSync(source).isDirectory() ? path.basename(source) !== '__pycache__' : /\.(md|json|py|mjs)$/.test(source) });
const docRoutes = buildDocPages(out);
fs.mkdirSync(path.join(out, 'media'), { recursive: true });
for (const name of ['cannabis-landscape.mp4', 'cannabis-portrait.mp4', 'narration.txt', 'captions.srt']) {
  const source = path.join(root, 'media', name);
  if (fs.existsSync(source)) {
    const target = path.join(out, 'media', name);
    if (name.endsWith('.txt')) fs.writeFileSync(target, displayText(fs.readFileSync(source, 'utf8')));
    else fs.copyFileSync(source, target);
  }
}

fs.mkdirSync(path.join(out, 'media/series'), { recursive: true });
const withheldFilms = new Set(JSON.parse(fs.readFileSync(path.join(root, 'media/distribution.json'))).withheldFilms ?? []);
for (const entry of fs.readdirSync(path.join(root, 'media/series'), { withFileTypes: true })) {
  if ([...withheldFilms].some(id => entry.name.startsWith(id + '.') || entry.name.startsWith(id + '-'))) continue;
  if (entry.isFile() && /\.(mp4|srt|vtt|txt|json)$/.test(entry.name)) {
    const source = path.join(root, 'media/series', entry.name);
    const target = path.join(out, 'media/series', entry.name);
    if (entry.name === 'scripts.json') {
      const catalog = JSON.parse(fs.readFileSync(source));
      catalog.films = catalog.films.filter(film => !withheldFilms.has(film.id));
      fs.writeFileSync(target, JSON.stringify(catalog, null, 2) + '\n');
    } else if (entry.name.endsWith('.txt')) fs.writeFileSync(target, displayText(fs.readFileSync(source, 'utf8')));
    else fs.copyFileSync(source, target);
  }
}
const pages = fs.readdirSync(out, { recursive: true }).map(name => name.split(path.sep).join('/')).filter(name => name.endsWith('.html')).sort();
const assetVersions = new Map(['style.css', 'site.js', 'donate.js', 'docs.js', 'work.js', 'work.css', 'market.css', 'work-market.css'].map(name => [name, createHash('sha256').update(fs.readFileSync(path.join(out, name))).digest('hex').slice(0, 12)]));
for (const name of pages) {
  let html = fs.readFileSync(path.join(out, name), 'utf8');
  const prefix = '../'.repeat(name.split('/').length - 1) || './';
  html = html.replace(/\b(href|src|poster)="([^"]*)"/g, (_, attribute, value) => {
    if (attribute === 'href') value = resolveGuideLink(value, name, docRoutes);
    if (value.startsWith('/') && !value.startsWith('//')) value = prefix + value.slice(1);
    const localAsset = path.posix.normalize(path.posix.join(path.posix.dirname(name), value));
    if (assetVersions.has(localAsset)) value += `?v=${assetVersions.get(localAsset)}`;
    return `${attribute}="${value}"`;
  });
  html = html.replace(/\bsrcset="([^"]*)"/g, (_, value) => `srcset="${value.split(',').map(item => item.trim().replace(/^\/(?!\/)/, prefix)).join(', ')}"`);
  const canonical = siteOrigin + '/' + (['index.html', 'collection.html'].includes(name) ? '' : name);
  html = html.replace('</head>', `<link rel="canonical" href="${canonical}"></head>`);
  fs.writeFileSync(path.join(out, name), html);
}
fs.writeFileSync(path.join(out, 'robots.txt'), `User-agent: *\nAllow: /\nSitemap: ${siteOrigin}/sitemap.xml\n`);
fs.writeFileSync(path.join(out, 'sitemap.xml'), '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
  pages.filter(name => name !== 'collection.html').map(name => `  <url><loc>${siteOrigin}/${name === 'index.html' ? '' : name}</loc></url>`).join('\n') + '\n</urlset>\n');
fs.writeFileSync(path.join(out, '.nojekyll'), '');
console.log('Built public project website in dist-site/');
