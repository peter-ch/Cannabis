const narrationFields = new Set([
  'id', 'text', 'segments', 'seconds', 'sampleRate', 'sample_rate',
  'scriptSHA256', 'wavSHA256', 'peak', 'clippedSamples'
]);
const segmentFields = new Set(['start', 'end', 'text']);

function assertFields(record, allowed, label) {
  if (!record || Array.isArray(record) || typeof record !== 'object' ||
      Object.keys(record).some(key => !allowed.has(key))) {
    throw Error(`Unexpected fields in public ${label}`);
  }
}

export function assertPublicNarration(record) {
  assertFields(record, narrationFields, 'narration metadata');
  if (!Array.isArray(record.segments) || record.segments.length === 0) {
    throw Error('Public narration requires timed segments');
  }
  for (const segment of record.segments) assertFields(segment, segmentFields, 'caption segment');
}
