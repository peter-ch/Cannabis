const descriptions = {
  'moonlit-geode': 'Moonlit obsidian opening onto luminous emerald and quartz crystals',
  'tidal-garden': 'A botanical crystal garden beneath clear turquoise water',
  'forest-lattice': 'Fine silver branches and crystal droplets suspended in a sunlit forest',
  'alpine-light': 'Clear quartz and emerald prisms scattering light across alpine snow',
  'network-constellation': 'Emerald cores in clear crystal cubes connected into a branching sculpture',
  'privacy-sanctuary': 'An emerald seed sheltered inside luminous nested crystal shells',
  'community-garden': 'Emerald and quartz leaves growing together in a sunlit stone garden',
  'compute-engine': 'Precision crystal layers and emerald cores in a sculptural assembly',
  'payment-current': 'Two glass streams carrying emerald crystals into a shared basin',
  'knowledge-prism': 'A fan of quartz pages scattering sunlight across pale stone',
  'launch-horizon': 'A monumental emerald arch beside a sunlit sea',
  'creation-atelier': 'Faceted emerald leaves and quartz connectors on an artisan workbench'
};
const assignments = {
  'technical-paper':'knowledge-prism', 'windows-setup':'creation-atelier', 'community-claims':'community-garden', 'energy':'alpine-light',
  'privacy-security':'privacy-sanctuary', 'useful-compute':'compute-engine', 'compute-economy':'payment-current',
  'universal-compute':'network-constellation', 'decentralized-compute':'network-constellation', 'compute-payments':'payment-current', 'website-orders':'creation-atelier',
  'microjobs':'tidal-garden', 'capacity-commitments':'network-constellation', 'claim-identity':'privacy-sanctuary',
  'person-verification':'community-garden', 'membership-snapshot':'forest-lattice', 'confidential-compute':'privacy-sanctuary',
  'job-key-custody':'moonlit-geode', 'trustee-attestation':'moonlit-geode', 'key-delivery':'forest-lattice',
  'worker-deployment':'compute-engine', 'worker-console':'compute-engine', 'guest-attestation':'crystal-purity', 'guest-initialization':'creation-atelier',
  'guest-workload':'network-constellation', 'guest-service-build':'compute-engine', 'guest-image-build':'crystal-facets',
  'guest-firmware':'crystal-monolith', 'tokenomics':'payment-current', 'mainnet-release':'launch-horizon',
  'dependency-verification':'forest-lattice', 'deployment-fees':'payment-current', 'launch-plan':'alpine-light',
  'launch-review':'knowledge-prism', 'risks':'moonlit-geode', 'README':'compute-engine'
};
export function artName(topic) { return assignments[topic.split('/').pop().replace(/\.md$/, '')] ?? 'knowledge-prism'; }
export function editorialArt(name, className = 'editorial-art', loading = 'lazy') {
  const modern = Object.hasOwn(descriptions, name), src = `/assets/${modern ? 'editorial/' : ''}${name}.webp`;
  const alt = descriptions[name] ?? 'Emerald crystal sculpture with natural light and prismatic reflections';
  return `<figure class="${className}"><img src="${src}"${modern ? ` srcset="/assets/editorial/${name}-small.webp 720w, ${src} 1440w" sizes="(max-width: 700px) calc(100vw - 32px), 900px"` : ''} alt="${alt}" width="1440" height="720" loading="${loading}" decoding="async"></figure>`;
}
