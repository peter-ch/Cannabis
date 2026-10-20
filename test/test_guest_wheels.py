"""Offline wheel recipe boundary checks; no package code is imported."""
import hashlib
import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('wheel_recipe', ROOT / 'scripts/build-guest-wheels.py')
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)


class WheelRecipeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.cache = self.base / 'cache'
        self.cache.mkdir()
        self.runtime = self.base / 'runtime'
        self.runtime.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def wheel(self, extras=(), name='owned'):
        path = self.base / (name + '.whl')
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr(name + '-1.0.dist-info/METADATA', f'Name: {name}\nVersion: 1.0\n')
            archive.writestr(name + '-1.0.dist-info/licenses/LICENSE', 'owned fixture license')
            for item, content in extras:
                archive.writestr(item, content)
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        (self.cache / digest).write_bytes(raw)
        with zipfile.ZipFile(path) as archive:
            return {'name': name, 'version': '1.0', 'sha256': digest, 'bytes': len(raw),
                    'entries': len(archive.infolist()),
                    'unpackedBytes': sum(i.file_size for i in archive.infolist())}

    def test_retains_licenses_without_executing_package(self):
        item = self.wheel([('owned/__init__.py', "raise RuntimeError('never run during assembly')")])
        result = recipe.add_wheels(self.runtime, {'packages': [item]}, self.cache)
        self.assertFalse(result['packageCodeExecutedDuringAssembly'])
        license = self.runtime / recipe.SITE / 'owned-1.0.dist-info/licenses/LICENSE'
        self.assertEqual(license.read_text(), 'owned fixture license')
        self.assertEqual(stat.S_IMODE(license.stat().st_mode), 0o644)

    def test_parent_traversal_refused_before_writing(self):
        item = self.wheel([('../../escape', 'invalid')])
        with self.assertRaises(ValueError):
            recipe.add_wheels(self.runtime, {'packages': [item]}, self.cache)
        self.assertEqual(list(self.runtime.iterdir()), [])

    def test_member_symlink_refused(self):
        link = zipfile.ZipInfo('owned/link')
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        item = self.wheel([(link, '/etc/passwd')])
        with self.assertRaises(ValueError):
            recipe.add_wheels(self.runtime, {'packages': [item]}, self.cache)

    def test_cross_wheel_collision_refused_before_writing(self):
        a = self.wheel([('shared.py', 'a')])
        b = self.wheel([('shared.py', 'b')], 'other')
        with self.assertRaises(ValueError):
            recipe.add_wheels(self.runtime, {'packages': [a, b]}, self.cache)
        self.assertEqual(list(self.runtime.iterdir()), [])

    def test_changed_archive_refused(self):
        item = self.wheel()
        with (self.cache / item['sha256']).open('ab') as stream:
            stream.write(b'changed')
        with self.assertRaises(ValueError):
            recipe.add_wheels(self.runtime, {'packages': [item]}, self.cache)

    def test_image_file_overwrite_refused(self):
        item = self.wheel([('owned.py', 'wheel')])
        output = self.runtime / recipe.SITE / 'owned.py'
        output.parent.mkdir(parents=True)
        output.write_text('image')
        with self.assertRaises(ValueError):
            recipe.add_wheels(self.runtime, {'packages': [item]}, self.cache)
        self.assertEqual(output.read_text(), 'image')


if __name__ == '__main__':
    unittest.main()
