import argparse
import json

from .archive import inspect_archive, Limits, SafetyError


class _SafeParser(argparse.ArgumentParser):
    def error(self, message):
        print(json.dumps({'status': 'rejected', 'code': 'invalid_command_line'}))
        raise SystemExit(2)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SafetyError('invalid_manifest')
        result[key] = value
    return result


def main(argv=None):
    parser = _SafeParser(description='Audit ZIP/TAR payloads; restore only into a NEW isolated directory.')
    parser.add_argument('archive')
    parser.add_argument('--restore-to', metavar='NEW_DIRECTORY', help='Explicitly enable a restore drill; parent must exist.')
    parser.add_argument('--manifest', metavar='JSON', help='JSON object of relative paths to SHA-256 hex digests.')
    parser.add_argument('--require', action='append', default=[], metavar='RELATIVE_FILE')
    parser.add_argument('--max-entries', type=int, default=10_000)
    parser.add_argument('--max-total-bytes', type=int, default=512 * 1024 * 1024)
    parser.add_argument('--max-file-bytes', type=int, default=64 * 1024 * 1024)
    parser.add_argument('--max-archive-bytes', type=int, default=128 * 1024 * 1024)
    args = parser.parse_args(argv)
    try:
        manifest = None
        if args.manifest:
            with open(args.manifest, 'rb') as source:
                data = source.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise SafetyError('manifest_size_limit')
            manifest = json.loads(data, object_pairs_hook=_unique_object)
        result = inspect_archive(args.archive, restore_to=args.restore_to, manifest=manifest,
                                 required=args.require,
                                 limits=Limits(args.max_entries, args.max_total_bytes,
                                               args.max_file_bytes, args.max_archive_bytes))
    except SafetyError as error:
        result = {'status': 'rejected', 'code': str(error)}
    except Exception:
        result = {'status': 'rejected', 'code': 'invalid_input'}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'ok' else 2
