"""Read archive payloads without extractall or trusting archive paths/metadata."""
from contextlib import ExitStack
from dataclasses import dataclass
import bz2
import gzip
import hashlib
import lzma
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import unicodedata
import zipfile


class SafetyError(Exception):
    """A stable, non-sensitive error code; never an underlying exception message."""


@dataclass(frozen=True)
class Limits:
    max_entries: int = 10_000
    max_total_bytes: int = 512 * 1024 * 1024
    max_file_bytes: int = 64 * 1024 * 1024
    max_archive_bytes: int = 128 * 1024 * 1024

    def __post_init__(self):
        if any(type(value) is not int or value <= 0 for value in vars(self).values()):
            raise SafetyError('invalid_limits')


def normalize_name(name):
    """Use a deliberately conservative portable filename policy."""
    if not isinstance(name, str) or len(name) > 4096:
        raise SafetyError('unsafe_path')
    name = unicodedata.normalize('NFC', name.replace('\\', '/'))
    if name.startswith('/') or re.match(r'^[A-Za-z]:', name):
        raise SafetyError('unsafe_path')
    parts = []
    for part in name.split('/'):
        if part == '..':
            raise SafetyError('unsafe_path')
        if part in ('', '.'):
            continue
        if (part.endswith((' ', '.')) or any(ord(c) < 32 or c in ':<>"|?*' for c in part)
                or re.match(r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)', part, re.I)):
            raise SafetyError('unsafe_path')
        parts.append(part)
    if not parts:
        raise SafetyError('unsafe_path')
    return '/'.join(parts)


class _Index:
    def __init__(self, limits):
        self.limits = limits
        self.entries = {}
        self.prefixes = {}
        self.total = 0

    def add(self, name, size, directory):
        normalized = normalize_name(name)
        if len(self.entries) >= self.limits.max_entries:
            raise SafetyError('entry_limit')
        if normalized.casefold() in self.entries:
            raise SafetyError('path_collision')
        parts = normalized.split('/')
        for depth in range(1, len(parts) + 1):
            prefix = '/'.join(parts[:depth])
            key = prefix.casefold()
            if key in self.prefixes and self.prefixes[key] != prefix:
                raise SafetyError('path_collision')
            self.prefixes[key] = prefix
            previous = self.entries.get(key)
            if previous is not None and not previous[1]:
                raise SafetyError('path_collision')
        if not directory and any(k.startswith(normalized.casefold() + '/') for k in self.prefixes):
            raise SafetyError('path_collision')
        if size < 0 or size > self.limits.max_file_bytes:
            raise SafetyError('file_size_limit')
        self.total += size
        if self.total > self.limits.max_total_bytes:
            raise SafetyError('total_size_limit')
        self.entries[normalized.casefold()] = (normalized, directory)
        return normalized


def _copy_checked(source, target, declared, limits, total):
    digest = hashlib.sha256()
    actual = 0
    while True:
        chunk = source.read(64 * 1024)
        if not chunk:
            break
        actual += len(chunk)
        total[0] += len(chunk)
        if actual > declared or actual > limits.max_file_bytes:
            raise SafetyError('file_size_limit')
        if total[0] > limits.max_total_bytes:
            raise SafetyError('total_size_limit')
        digest.update(chunk)
        if target is not None:
            target.write(chunk)
    if actual != declared:
        raise SafetyError('truncated_payload')
    return digest.hexdigest()


class _SafeTarInfo(tarfile.TarInfo):
    @classmethod
    def frombuf(cls, buf, encoding, errors):
        info = super().frombuf(buf, encoding, errors)
        # Reject extension headers before tarfile follows them or allocates their payload.
        if not (info.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)):
            raise SafetyError('unsupported_entry')
        return info


class _BudgetReader:
    def __init__(self, source, limit):
        self.source, self.remaining = source, limit

    def read(self, size=-1):
        if size < 0:
            size = self.remaining + 1
        data = self.source.read(min(size, self.remaining + 1))
        self.remaining -= len(data)
        if self.remaining < 0:
            raise SafetyError('tar_envelope_limit')
        return data


def _tar_members(stack, raw, limits):
    raw.seek(0)
    magic = raw.read(6)
    raw.seek(0)
    if magic.startswith(b'\x1f\x8b'):
        decoded = stack.enter_context(gzip.GzipFile(fileobj=raw))
    elif magic.startswith(b'BZh'):
        decoded = stack.enter_context(bz2.BZ2File(raw))
    elif magic == b'\xfd7zXZ\x00':
        decoded = stack.enter_context(lzma.LZMAFile(raw))
    else:
        decoded = raw
    envelope = limits.max_total_bytes + limits.max_entries * 1024 + 10240
    budget = _BudgetReader(decoded, envelope)
    return stack.enter_context(tarfile.open(fileobj=budget, mode='r|', tarinfo=_SafeTarInfo))


def _process(raw, limits, manifest, required, output):
    index = _Index(limits)
    total = [0]
    hashes = 0
    files = set()
    raw.seek(0)
    with ExitStack() as stack:
        if zipfile.is_zipfile(raw):
            raw.seek(0)
            archive = stack.enter_context(zipfile.ZipFile(raw))
            members = archive.infolist()
            if len(members) > limits.max_entries:
                raise SafetyError('entry_limit')
            entries = []
            for info in members:
                if info.orig_filename != info.filename:
                    raise SafetyError('unsafe_path')
                mode = (info.external_attr >> 16) & 0o170000
                directory = info.is_dir()
                if mode not in (0, stat.S_IFREG, stat.S_IFDIR) or bool(info.flag_bits & 1):
                    raise SafetyError('unsupported_entry')
                if (mode == stat.S_IFDIR and not directory) or (directory and info.file_size):
                    raise SafetyError('unsupported_entry')
                name = index.add(info.filename, info.file_size, directory)
                entries.append((name, info.file_size, directory, info))
            opener = archive.open
        else:
            archive = _tar_members(stack, raw, limits)

            def tar_entries():
                for info in archive:
                    directory = info.isdir()
                    if directory and info.size:
                        raise SafetyError('unsupported_entry')
                    yield index.add(info.name, info.size, directory), info.size, directory, info

            entries = tar_entries()
            opener = archive.extractfile
        for name, size, directory, info in entries:
            target_path = output.joinpath(*name.split('/')) if output is not None else None
            if directory:
                if target_path is not None:
                    target_path.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            files.add(name)
            with ExitStack() as payload_stack:
                source = payload_stack.enter_context(opener(info))
                target = None
                if target_path is not None:
                    target_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    # New exclusive files, restrictive modes; no archive permission or owner restoration.
                    fd = os.open(target_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    target = payload_stack.enter_context(os.fdopen(fd, 'wb'))
                digest = _copy_checked(source, target, size, limits, total)
            if name in manifest:
                hashes += 1
                if digest != manifest[name]:
                    raise SafetyError('hash_mismatch')
        if not required.issubset(files):
            raise SafetyError('required_file_missing')
        if not set(manifest).issubset(files):
            raise SafetyError('manifest_file_missing')
    return {'status': 'ok', 'mode': 'audit', 'entries': len(index.entries),
            'files': len(files), 'bytes_verified': total[0], 'hashes_checked': hashes}


def _manifest_values(manifest):
    if manifest is None:
        return {}
    if not isinstance(manifest, dict):
        raise SafetyError('invalid_manifest')
    checked = {}
    folded = set()
    for name, digest in manifest.items():
        name = normalize_name(name)
        if name.casefold() in folded or not isinstance(digest, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', digest):
            raise SafetyError('invalid_manifest')
        folded.add(name.casefold())
        checked[name] = digest.lower()
    return checked


def inspect_archive(path, *, restore_to=None, limits=None, manifest=None, required=()):
    """Audit every payload, then optionally repeat into a destination created exclusively here.

    The output parent must be trusted and not writable by hostile concurrent actors.
    No archive paths, filenames, hash values, or underlying exception messages enter reports.
    """
    limits = limits or Limits()
    destination = Path(restore_to) if restore_to is not None else None
    created = False
    try:
        checked = _manifest_values(manifest)
        required = {normalize_name(name) for name in required}
        with open(path, 'rb') as raw:
            if os.fstat(raw.fileno()).st_size > limits.max_archive_bytes:
                raise SafetyError('archive_size_limit')
            result = _process(raw, limits, checked, required, None)
            if destination is not None:
                # mkdir without parents/exist_ok ensures no existing directory is adopted.
                destination.mkdir(mode=0o700)
                created = True
                _process(raw, limits, checked, required, destination)
                result['mode'] = 'restore'
        return result
    except BaseException as error:
        if created:
            try:
                shutil.rmtree(destination)
            except OSError:
                raise SafetyError('restore_cleanup_failed') from None
        if isinstance(error, SafetyError):
            raise
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise SafetyError('archive_or_destination_unavailable') from None
