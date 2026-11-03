import hashlib
import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from backup_restore_doctor.archive import Limits, inspect_archive, SafetyError, _copy_checked
from backup_restore_doctor.cli import main


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def zip(self, entries):
        path = self.root / 'fixture.zip'
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, data in entries:
                archive.writestr(name, data)
        return path

    def test_default_audit_reads_data_but_creates_nothing(self):
        path = self.zip([('docs/readme.txt', b'synthetic')])
        before = set(self.root.iterdir())
        result = inspect_archive(path)
        self.assertEqual(result['files'], 1)
        self.assertEqual(result['bytes_verified'], 9)
        self.assertEqual(result['mode'], 'audit')
        self.assertEqual(set(self.root.iterdir()), before)

    def test_restore_requires_new_destination_and_restores_both_formats(self):
        for kind in ('zip', 'tar', 'tar.gz', 'tar.bz2', 'tar.xz'):
            with self.subTest(kind=kind):
                if kind == 'zip':
                    path = self.zip([('docs/readme.txt', b'synthetic')])
                else:
                    path = self.root / ('fixture.' + kind)
                    compression = {'tar': 'w', 'tar.gz': 'w:gz', 'tar.bz2': 'w:bz2', 'tar.xz': 'w:xz'}[kind]
                    with tarfile.open(path, compression) as archive:
                        info = tarfile.TarInfo('docs/readme.txt')
                        info.size = 9
                        archive.addfile(info, io.BytesIO(b'synthetic'))
                destination = self.root / ('restored-' + kind)
                result = inspect_archive(path, restore_to=destination)
                self.assertEqual((destination / 'docs/readme.txt').read_bytes(), b'synthetic')
                self.assertEqual(result['mode'], 'restore')

    def test_traversal_absolute_drive_unc_and_windows_special_paths_rejected(self):
        for name in ('../escape', 'a/../escape', '/absolute', 'C:/drive', 'C:relative',
                     '\\\\server\\share', 'a\\..\\escape', 'a:stream', 'CON.txt', 'a./x'):
            with self.subTest(name=name):
                with self.assertRaises(SafetyError):
                    inspect_archive(self.zip([(name, b'x')]))

    def test_zip_symlink_is_rejected(self):
        path = self.root / 'link.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            info = zipfile.ZipInfo('link')
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, 'elsewhere')
        with self.assertRaises(SafetyError):
            inspect_archive(path)

    def test_tar_links_and_devices_are_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE,
                     tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_SPARSE):
            path = self.root / 'special.tar'
            with tarfile.open(path, 'w') as archive:
                info = tarfile.TarInfo('special')
                info.type = kind
                info.linkname = 'target'
                archive.addfile(info)
            with self.assertRaises(SafetyError):
                inspect_archive(path)

    def test_duplicate_casefold_normalization_and_file_parent_collisions(self):
        for names in (('a.txt', 'A.txt'), ('a/./b', 'a/b'), ('a', 'a/b'),
                      ('A/one', 'a/two'), ('cafe\u0301', 'caf\u00e9')):
            with self.subTest(names=names):
                with self.assertRaises(SafetyError):
                    inspect_archive(self.zip([(name, b'x') for name in names]))

    def test_bomb_metadata_limits_reject_before_destination_exists(self):
        path = self.zip([('compressible', b'0' * 100_000)])
        destination = self.root / 'restore'
        with self.assertRaises(SafetyError):
            inspect_archive(path, restore_to=destination, limits=Limits(max_file_bytes=1024))
        self.assertFalse(destination.exists())

    def test_entry_and_total_limits(self):
        path = self.zip([('one', b'123'), ('two', b'456')])
        for limits in (Limits(max_entries=1), Limits(max_total_bytes=5), Limits(max_archive_bytes=1)):
            with self.assertRaises(SafetyError):
                inspect_archive(path, limits=limits)

    def test_streaming_checks_do_not_trust_declared_size(self):
        with self.assertRaises(SafetyError):
            _copy_checked(io.BytesIO(b'123456'), None, 3, Limits(max_file_bytes=5), [0])
        with self.assertRaises(SafetyError):
            _copy_checked(io.BytesIO(b'123'), None, 3, Limits(max_total_bytes=5), [4])

    def test_manifest_and_required_file_checks(self):
        path = self.zip([('config/demo.txt', b'synthetic')])
        digest = hashlib.sha256(b'synthetic').hexdigest()
        result = inspect_archive(path, manifest={'config/demo.txt': digest}, required=['config/demo.txt'])
        self.assertEqual(result['hashes_checked'], 1)
        with self.assertRaises(SafetyError):
            inspect_archive(path, required=['missing.txt'])

    def test_hash_mismatch_removes_only_own_partial_destination(self):
        path = self.zip([('one', b'1'), ('two', b'2')])
        destination = self.root / 'partial'
        sentinel = self.root / 'untouched.txt'
        sentinel.write_text('synthetic')
        with self.assertRaises(SafetyError):
            inspect_archive(path, restore_to=destination, manifest={'two': '0' * 64})
        self.assertFalse(destination.exists())
        self.assertEqual(sentinel.read_text(), 'synthetic')
        # Simulate a changed payload on the restore pass after the first audit succeeds.
        def changed_second_pass(source, target, declared, limits, total):
            digest = _copy_checked(source, target, declared, limits, total)
            return 'f' * 64 if target is not None else digest
        with patch('backup_restore_doctor.archive._copy_checked', side_effect=changed_second_pass):
            with self.assertRaises(SafetyError):
                inspect_archive(path, restore_to=destination,
                                manifest={'two': hashlib.sha256(b'2').hexdigest()})
        self.assertFalse(destination.exists())
        self.assertEqual(sentinel.read_text(), 'synthetic')

    def test_existing_destination_is_never_touched(self):
        path = self.zip([('item', b'new')])
        destination = self.root / 'exists'
        destination.mkdir()
        sentinel = destination / 'keep'
        sentinel.write_text('keep')
        with self.assertRaises(SafetyError):
            inspect_archive(path, restore_to=destination)
        self.assertEqual(sentinel.read_text(), 'keep')

    def test_manifest_rejects_malformed_digests_and_missing_entries(self):
        path = self.zip([('item', b'demo')])
        for manifest in ({'item': 'bad'}, {'missing': '0' * 64}, {'../bad': '0' * 64}):
            with self.assertRaises(SafetyError):
                inspect_archive(path, manifest=manifest)

    def test_cli_hides_sensitive_exception_details(self):
        output = io.StringIO()
        with patch('sys.stdout', output):
            code = main([str(self.root / 'private-name-and-token.zip')])
        self.assertEqual(code, 2)
        self.assertNotIn('private-name', output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['status'], 'rejected')
        for args in (['demo.zip', 'SYNTHETIC_PRIVATE_EXTRA'],
                     ['demo.zip', '--unknown=SYNTHETIC_PRIVATE_EXTRA'],
                     ['demo.zip', '--max-entries=SYNTHETIC_PRIVATE_EXTRA']):
            output, errors = io.StringIO(), io.StringIO()
            with patch('sys.stdout', output), patch('sys.stderr', errors):
                with self.assertRaises(SystemExit) as stopped:
                    main(args)
            self.assertEqual(stopped.exception.code, 2)
            self.assertNotIn('SYNTHETIC_PRIVATE_EXTRA', output.getvalue() + errors.getvalue())
        with patch('sys.stdout', io.StringIO()) as help_output:
            with self.assertRaises(SystemExit) as stopped:
                main(['--help'])
        self.assertEqual(stopped.exception.code, 0)
        self.assertIn('--restore-to', help_output.getvalue())

    def test_invalid_archive_is_a_safe_error(self):
        path = self.root / 'corrupt.zip'
        path.write_bytes(b'not an archive')
        with self.assertRaises(SafetyError):
            inspect_archive(path)


if __name__ == '__main__':
    unittest.main()
