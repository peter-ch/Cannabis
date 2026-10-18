import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildMediaPages, displayText, verifyCaptionText } from './build-media-pages.mjs';
import { createHash } from 'node:crypto';
import { assertPublicNarration } from './media-metadata.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = path.join(root, 'dist-site');
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
  fs.rmSync(resolved, { recursive: true, force: true });
}
fs.mkdirSync(out, { recursive: true });
fs.cpSync(path.join(root, 'web'), out, { recursive: true });
buildMediaPages(out);
fs.cpSync(path.join(root, 'docs'), path.join(out, 'docs'), { recursive: true });
fs.cpSync(path.join(root, 'compute'), path.join(out, 'compute'), { recursive: true,
  filter: source => fs.statSync(source).isDirectory() ? path.basename(source) !== '__pycache__' : /\.(md|json|py|mjs)$/.test(source) });
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
for (const entry of fs.readdirSync(path.join(root, 'media/series'), { withFileTypes: true })) {
  if (entry.isFile() && /\.(mp4|srt|vtt|txt|json)$/.test(entry.name)) {
    const source = path.join(root, 'media/series', entry.name);
    const target = path.join(out, 'media/series', entry.name);
    if (entry.name.endsWith('.txt')) fs.writeFileSync(target, displayText(fs.readFileSync(source, 'utf8')));
    else fs.copyFileSync(source, target);
  }
}
for (const name of fs.readdirSync(out).filter(name => name.endsWith('.html'))) {
  let html = fs.readFileSync(path.join(out, name), 'utf8');
  html = html.replaceAll('href="/', 'href="./').replaceAll('src="/', 'src="./').replaceAll('poster="/', 'poster="./');
  fs.writeFileSync(path.join(out, name), html);
}
fs.writeFileSync(path.join(out, '.nojekyll'), '');
console.log('Built public project website in dist-site/');
