const search = document.querySelector('[data-guide-search]');
if (search) {
  const input = search.querySelector('input');
  const cards = [...document.querySelectorAll('[data-guide-card]')];
  search.hidden = false;
  input.addEventListener('input', () => {
    const words = input.value.toLocaleLowerCase().trim().split(/\s+/).filter(Boolean);
    let count = 0;
    for (const card of cards) {
      card.hidden = !words.every(word => card.textContent.toLocaleLowerCase().includes(word));
      if (!card.hidden) count++;
    }
    for (const group of document.querySelectorAll('[data-guide-group]')) {
      group.hidden = !group.querySelector('[data-guide-card]:not([hidden])');
      document.querySelector(`.guide-categories a[href="#${group.id}"]`).hidden = group.hidden;
    }
    search.querySelector('[data-guide-count]').textContent = `${count} ${count === 1 ? 'guide' : 'guides'}`;
    document.querySelector('[data-guide-empty]').hidden = count !== 0;
  });
}
