# Backup Restore Doctor

Audit a ZIP or TAR backup by reading every regular-file payload, checking archive integrity, enforcing size limits and optionally verifying trusted SHA-256 hashes. A restore drill happens only with `--restore-to`; the destination must be new and its parent must already exist. The tool never restores over an existing directory.

Python 3.10+; standard-library runtime only. This repository contains synthetic examples and tests, with no real backups, keys, account data or service configuration.

## Install and try

From the repository directory:

```console
python -m venv .venv
python -m pip install .
python examples/make_demo.py
backup-restore-doctor examples/demo-backup.zip --manifest examples/demo-manifest.json --require config/demo.txt
backup-restore-doctor examples/demo-backup.zip --restore-to restore-drill --manifest examples/demo-manifest.json
```

Activate `.venv` before installing: `.venv\Scripts\Activate.ps1` in PowerShell, or `source .venv/bin/activate` on POSIX. Alternatively use the virtual environment's Python explicitly. `python -m backup_restore_doctor` is equivalent to the console command after installation. The demo generator refuses to overwrite existing demo outputs.

Default audit output is a JSON object with `status`, `mode`, entry/file counts, bytes read and hashes checked. No archive filename, member path, file content, digest or underlying exception text is reported. Exit `0` means the requested audit or restore finished; exit `2` means rejection or invalid input. An audit does not create a destination. A successful restore is a file-read exercise, not an application recovery or boot test.

## Integrity and required files

The optional manifest is an external JSON object mapping relative archive paths to expected SHA-256 hex digests:

```json
{"config/demo.txt": "<64 hexadecimal characters>"}
```

Every manifest entry must be a regular file in the archive. Extra archive files are permitted, so partial manifests do not verify every file against a known hash. `--require relative/file` can be repeated. Requirements are case-sensitive after NFC/path normalization. A manifest must be trusted separately; matching hashes establish consistency with that manifest, not provenance, safety or authenticity.

## Limits and restore policy

Defaults can be lowered or raised explicitly:

| Option | Default |
| --- | ---: |
| `--max-entries` | 10,000 |
| `--max-total-bytes` | 536,870,912 |
| `--max-file-bytes` | 67,108,864 |
| `--max-archive-bytes` | 134,217,728 |

The input file size, metadata sizes and actual streamed output bytes are checked. TAR decoding also has an envelope budget for headers and padding. No `extractall` is used. All payloads are audited before the destination is created; restore reads them again and repeats checks. On restore failure or interruption, cleanup targets only the directory created by that invocation. `restore_cleanup_failed` means manual cleanup of that new directory is necessary.

ZIP, uncompressed TAR, `.tar.gz`, `.tar.bz2` and `.tar.xz` are supported. Links, devices, FIFOs, encrypted ZIP entries, unsupported compression, duplicate paths, casefold/NFC collisions, file/directory collisions, traversal, absolute/drive/UNC paths and unsafe Windows filenames are rejected. For a small auditable parser surface, TAR extension headers (including PAX, GNU long-name and sparse formats) and dot-only root entries are rejected; some legitimate archives therefore need repacking first. Directory entries with payload data are rejected. Restored files get newly chosen permissions; archive ownership, executable bits, ACLs, timestamps and extended attributes are not applied.

Use a trusted destination parent inaccessible to hostile concurrent writers. This is not a hardened filesystem sandbox, malware scanner or parser-security guarantee. The archive must remain unchanged while the two passes run. OS resource limits or a disposable sandbox remain appropriate for hostile inputs; the standard ZIP parser loads its central directory before member-count checks. POSIX mode requests do not establish Windows ACL isolation. Restored contents remain private input data: do not publish the drill directory or generated reports.

## Development

```console
python -m pip install -e .
python -m unittest discover -s tests -v
```

Tests construct only temporary synthetic fixtures and cover traversal, links/devices, limits, collisions, both restore formats, trusted hashes, missing requirements, cleanup and safe diagnostics. CI is configured for Python 3.10, 3.12 and 3.13 on Linux and Windows; a configured workflow does not establish that remote CI has run.

See [SECURITY.md](SECURITY.md) for scope and reporting guidance and [CONTRIBUTING.md](CONTRIBUTING.md) for contribution rules.
