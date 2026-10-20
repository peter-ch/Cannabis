import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compute.native_graph import validate_native_graph


def graph():
    return {'schema': 'cannabis.native-step-graph.v1', 'steps': [
        {'id': 'second', 'dependsOn': ['first'], 'inputs': [{'step': 'first', 'output': 'part', 'destination': 'part'}],
         'launch': {'argv': ['/bin/program']}, 'outputs': ['answer'], 'outputMaxBytes': 100},
        {'id': 'first', 'dependsOn': [], 'inputs': [{'package': 'program', 'destination': 'program'}],
         'launch': {'argv': ['/input/program']}, 'outputs': ['part'], 'outputMaxBytes': 100}],
        'collect': [{'step': 'second', 'output': 'answer', 'destination': 'answer'}]}


class NativeGraphTests(unittest.TestCase):
    def test_explicit_topology_is_detached_and_does_not_execute(self):
        value = graph()
        result = validate_native_graph(value, ['program'], ['answer'])
        self.assertEqual([s['id'] for s in result['steps']], ['first', 'second'])
        value['steps'][1]['launch']['argv'][0] = '/changed'
        self.assertEqual(result['steps'][0]['launch']['argv'], ['/input/program'])

    def test_refuses_ambiguous_or_undeclared_dataflow_before_packaging(self):
        changes = [
            lambda g: g['steps'][0].update(dependsOn=[]),
            lambda g: g['steps'][1].update(dependsOn=['second']),
            lambda g: g['steps'][0]['inputs'][0].update(output='undeclared'),
            lambda g: g['steps'][1]['inputs'][0].update(package='private-key'),
            lambda g: g['steps'][0]['inputs'].append({'package': 'program', 'destination': 'PART'}),
            lambda g: g['steps'][0]['inputs'].append({'package': 'program', 'destination': 'part/child'}),
            lambda g: g['collect'][0].update(destination='../outside'),
            lambda g: g['collect'][0].update(output='undeclared'),
            lambda g: g.update(collect=[]),
            lambda g: g['steps'][0].update(outputMaxBytes=True),
            lambda g: g['steps'][0].update(resources={'nodes': 2}),
            lambda g: g['steps'][0]['launch'].update(stdout='undeclared'),
            lambda g: g['steps'][0].update(id='first'),
            lambda g: g.update(steps=g['steps'] * 33),
        ]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                value = graph(); change(value)
                with self.assertRaises(ValueError): validate_native_graph(value, ['program'], ['answer'])

    def test_workload_validation_rejects_bad_native_graph_before_encryption(self):
        from test_compute_client import fixture
        from compute.client import validate_workload
        value = fixture()
        value['tasks'][0]['runtime']['adapter'] = 'native-linux-x86_64-v1'
        value['tasks'][0]['launch'] = graph()
        with self.assertRaises(ValueError): validate_workload(value)


if __name__ == '__main__': unittest.main()
