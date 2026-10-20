const people = {
  'roots-producer': 'A smiling producer with long dreadlocks standing at a studio mixing console',
  'hiphop-maker': 'A confident hip-hop enthusiast relaxing on studio steps in morning sunlight',
  'business-creator': 'A smiling designer in an emerald suit reviewing a tablet facing her',
  'night-builder': 'A young developer typing in a quiet workspace lit by a desk lamp and monitor',
  'metal-maker': 'A smiling metal musician in a leather jacket standing with her guitar',
  'researcher': 'A scientist sharing a molecular visualization beside a research monitor',
  'craft-designer': 'A product designer examining a small model at a sunlit workbench',
  'morning-founder': 'A professional enjoying morning light on a balcony with a closed laptop',
  'workshop-engineer': 'An engineer smiling beside a mechanical prototype in a daylight workshop',
  'rainy-creative': 'A creative professional walking through a rain-lit city at blue hour',
  'shared-ideas': 'Three people sharing ideas around a cafe table in natural daylight',
  'evening-provider': 'A confident computer builder standing beside a tidy workstation at twilight'
};
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
const peopleAssignments = {
  "windows-setup": "night-builder",
  "community-claims": "shared-ideas",
  "useful-compute": "researcher",
  "compute-economy": "morning-founder",
  "universal-compute": "craft-designer",
  "website-orders": "business-creator",
  "microjobs": "hiphop-maker",
  "capacity-commitments": "workshop-engineer",
  "claim-identity": "rainy-creative",
  "person-verification": "shared-ideas",
  "worker-deployment": "evening-provider",
  "worker-console": "evening-provider",
  "guest-initialization": "night-builder",
  "guest-workload": "researcher",
  "guest-service-build": "night-builder",
  "dependency-verification": "workshop-engineer"
};
export function artName(topic) { return assignments[topic.split('/').pop().replace(/\.md$/, '')] ?? 'knowledge-prism'; }
export function companionArt(topic, group) {
  const scenes = { start: 'morning-founder', compute: 'craft-designer', identity: 'shared-ideas', protected: 'night-builder', release: 'workshop-engineer' };
  const topicName = topic.split('/').pop().replace(/\.md$/, '');
  return editorialArt(peopleAssignments[topicName] ?? scenes[group] ?? 'researcher', 'editorial-art guide-companion');
}
export function editorialArt(name, className = 'editorial-art', loading = 'lazy') {
  const human = Object.hasOwn(people, name), modern = human || Object.hasOwn(descriptions, name);
  const folder = human ? 'people/' : modern ? 'editorial/' : '';
  const src = `/assets/${folder}${name}.webp`;
  const alt = people[name] ?? descriptions[name] ?? 'Emerald crystal sculpture with natural light and prismatic reflections';
  return `<figure class="${className}"><img src="${src}"${modern ? ` srcset="/assets/${folder}${name}-small.webp 720w, ${src} 1440w" sizes="(max-width: 700px) calc(100vw - 32px), 900px"` : ''} alt="${alt}" width="1440" height="720" loading="${loading}" decoding="async"></figure>`;
}
