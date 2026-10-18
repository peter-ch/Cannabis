import assert from 'node:assert/strict';
import test from 'node:test';
import { renderGuide, resolveGuideLink } from '../scripts/build-doc-pages.mjs';

test('guide links keep sections and external source URLs while routing nested READMEs', () => {
  assert.equal(resolveGuideLink('worker-deployment.md#complete-the-worker-acceptance-run', 'docs/guest-image-build.md'), 'worker-deployment.html#complete-the-worker-acceptance-run');
  assert.equal(resolveGuideLink('../compute/examples/', 'docs/universal-compute.md'), '../compute/examples/index.html');
  assert.equal(resolveGuideLink('../docs/privacy-security.md?view=all#privacy', 'compute/README.md'), '../docs/privacy-security.html?view=all#privacy');
  assert.equal(resolveGuideLink('/docs/technical-paper.md', 'index.html'), 'docs/technical-paper.html');
  assert.equal(resolveGuideLink('https://example.com/source.md', 'docs/technical-paper.md'), 'https://example.com/source.md');
});

test('guides render tables, fenced code and unique section links without losing text', () => {
  const guide = renderGuide('# A **guide**\n\n## Same heading\n\nA [link](energy.md).\n\n## Same heading\n\n| Name | Value |\n| --- | --- |\n| Work | 420 |\n\n```sh\nnode app.mjs --limit 10\n```\n', 'docs/technical-paper.md');
  assert.equal(guide.title, 'A guide');
  assert.deepEqual(guide.headings.map(h => h.id), ['same-heading', 'same-heading-1']);
  assert.match(guide.html, /<table>/);
  assert.match(guide.html, /<code class="language-sh">node app.mjs --limit 10/);
  assert.match(guide.html, /href="energy.html"/);
  assert.doesNotMatch(guide.html, /<h1/);
});

test('documentation keeps raw HTML inert and rejects executable link schemes', () => {
  const guide = renderGuide('# Safety\n\n<script>alert(1)</script>\n\n<img src=x onerror=alert(1)>\n\n[unsafe](javascript:alert(1))\n\n[safe](https://example.com/)\n', 'docs/risks.md');
  assert.doesNotMatch(guide.html, /<script|<img|href="javascript:/);
  assert.match(guide.html, /&lt;script&gt;/);
  assert.match(guide.html, /href="https:\/\/example.com\/"/);
});
