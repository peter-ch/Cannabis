"""Private, explicit task-to-task artifact mappings. No execution or authorization."""
from .client import MAX_BYTES, MAX_FILES, safe_name


def validate_dependency_inputs(spec, task):
    mappings = task.get('dependencyInputs')
    if mappings is None:
        if 'dependencyInputMaxBytes' in task:
            raise ValueError('Dependency input budget requires explicit mappings')
        return None
    if not isinstance(mappings, list) or not 1 <= len(mappings) <= MAX_FILES:
        raise ValueError('Require a bounded nonempty dependency input allowlist')
    limit = task.get('dependencyInputMaxBytes')
    if type(limit) is not int or not 0 <= limit <= MAX_BYTES:
        raise ValueError('Require a bounded dependency plaintext budget')
    tasks = {t['id']: t for t in spec['tasks']}
    used, paths = set(), [safe_name(p).casefold() for p in spec['files']]
    for item in mappings:
        if not isinstance(item, dict) or set(item) != {'task', 'rank', 'output', 'destination'}:
            raise ValueError('Dependency input fields differ')
        source = tasks.get(item['task'])
        if source is None or item['task'] not in task.get('dependsOn', []):
            raise ValueError('Dependency input must reference a direct predecessor')
        rank = item['rank']
        if (type(rank) is not int or not 0 <= rank < source['resources']['nodes']
                or (rank and source.get('outputScope', 'leader') == 'leader')):
            raise ValueError('Dependency input references an unavailable output rank')
        if item['output'] not in source.get('outputs', []):
            raise ValueError('Dependency input references an undeclared output')
        target = safe_name(item['destination']).casefold()
        paths.append(target)
        used.add(item['task'])
    names = set(paths)
    if len(names) != len(paths) or any('/'.join(p.split('/')[:i]) in names for p in paths for i in range(1, len(p.split('/')))):
        raise ValueError('Dependency destination collides with a package or input path')
    if used != set(task.get('dependsOn', [])):
        raise ValueError('Every declared predecessor needs an explicit input mapping')
    return mappings
