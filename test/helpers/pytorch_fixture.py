"""Public owned fixture preparation and independent numeric result checks."""
import json
import math
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[2]
OUTPUTS = ['result.json', 'checkpoint.json', 'stdout.txt', 'stderr.txt']
ENVIRONMENT = {'OMP_NUM_THREADS': '1', 'MKL_NUM_THREADS': '1', 'OPENBLAS_NUM_THREADS': '1',
               'PYTHONDONTWRITEBYTECODE': '1'}


def prepare(source, *, collective_timeout=60):
    assert type(collective_timeout) is int and collective_timeout in (60, 300)
    shutil.copyfile(ROOT / 'test/fixtures/pytorch-training.py', source / 'program.py')
    (source / 'training.json').write_text(json.dumps({'x': [-3, -1, 1, 3], 'y': [-7, -1, 5, 11],
                                                   'collectiveTimeoutSeconds': collective_timeout}))


def verify(directory, rank, world):
    report = json.loads((directory / 'result.json').read_text())
    weights = json.loads((directory / 'checkpoint.json').read_text())
    assert report['rank'] == rank and report['worldSize'] == world
    assert report['steps'] == 80 and report['checkpointRestored']
    assert report['torch'] == '2.14.1+cpu'
    assert math.isfinite(report['finalLoss']) and report['finalLoss'] < 1e-8
    assert report['initialLoss'] > 1
    assert set(weights) == {'weight', 'bias'}
    assert len(weights['weight']) == len(weights['weight'][0]) == len(weights['bias']) == 1
    slope, bias = weights['weight'][0][0], weights['bias'][0]
    assert math.isfinite(slope) and math.isfinite(bias)
    # A fresh requester-side computation verifies the fitted model on unseen data.
    assert abs((slope * 7 + bias) - 23) < 1e-4
    assert abs((slope * -5 + bias) + 13) < 1e-4
    assert 'Owned CPU training completed' in (directory / 'stdout.txt').read_text()
    return slope, bias
