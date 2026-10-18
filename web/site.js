// Guided architecture illustration; no live activity feed.
for (const story of document.querySelectorAll('[data-compute-story]')) {
  const steps = [...story.querySelectorAll('[data-step]')];
  const nodes = [...story.querySelectorAll('[data-node]')];
  for (const step of steps) {
    step.addEventListener('click', () => {
      for (const candidate of steps) {
        const selected = candidate === step;
        candidate.classList.toggle('active', selected);
        candidate.setAttribute('aria-pressed', String(selected));
      }
      for (const node of nodes) node.classList.toggle('active', node.dataset.node === step.dataset.step);
    });
  }
}
