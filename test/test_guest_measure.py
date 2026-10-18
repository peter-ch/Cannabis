"""Regression checks for the exact bytes consumed by offline SNP measurement."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('guest_measure', Path(__file__).resolve().parents[1] / 'scripts/measure-guest-snp.py')
measure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure)


class MeasurementInputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.original = self.directory / 'vmlinuz'
        self.output = self.directory / 'snapshot'
        self.data = b'approved boot artifact' * 70000
        self.original.write_bytes(self.data)
        self.record = {'bytes':len(self.data), 'sha256':hashlib.sha256(self.data).hexdigest()}

    def test_original_changes_after_snapshot_do_not_change_measured_bytes(self):
        measure.snapshot(self.original, self.output, self.record)
        self.original.write_bytes(b'different boot artifact')
        self.assertEqual(self.output.read_bytes(), self.data)
        measure.checked(self.output, self.record)

    def test_changed_open_file_fails_without_leaving_a_snapshot(self):
        original_open = os.open
        def replace_on_open(path, flags):
            descriptor = original_open(path, flags)
            self.original.write_bytes(b'x' * len(self.data))
            return descriptor
        with patch.object(measure.os, 'open', side_effect=replace_on_open):
            with self.assertRaisesRegex(ValueError, 'recorded boot artifact changed'):
                measure.snapshot(self.original, self.output, self.record)
        self.assertFalse(self.output.exists())

    def test_existing_destination_is_preserved(self):
        self.output.write_bytes(b'previous approved snapshot')
        with self.assertRaises(FileExistsError):
            measure.snapshot(self.original, self.output, self.record)
        self.assertEqual(self.output.read_bytes(), b'previous approved snapshot')

    def test_oversized_replacement_fails(self):
        self.original.write_bytes(self.data + b'changed')
        with self.assertRaisesRegex(ValueError, 'recorded boot artifact changed'):
            measure.snapshot(self.original, self.output, self.record)
        self.assertFalse(self.output.exists())

    @unittest.skipUnless(hasattr(os, 'O_NOFOLLOW'), 'Linux no-follow input opening')
    def test_symlink_input_fails(self):
        link = self.directory / 'indirect'
        link.symlink_to(self.original)
        with self.assertRaises(OSError):
            measure.checked(link, self.record)
        with self.assertRaises(OSError):
            measure.snapshot(link, self.output, self.record)
        self.assertFalse(self.output.exists())

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'Linux special file rejection')
    def test_fifo_is_rejected_without_blocking(self):
        fifo = self.directory / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, 'regular boot artifacts'):
            measure.checked(fifo, self.record)
        with self.assertRaisesRegex(ValueError, 'regular boot artifacts'):
            measure.snapshot(fifo, self.output, self.record)
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
