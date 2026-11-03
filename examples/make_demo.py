"""Generate a tiny synthetic backup and trusted manifest; refuse overwrites."""
import hashlib
import json
from pathlib import Path
import zipfile


def main():
    base = Path(__file__).resolve().parent
    archive_path = base / 'demo-backup.zip'
    manifest_path = base / 'demo-manifest.json'
    if archive_path.exists() or manifest_path.exists():
        raise SystemExit('Demo output already exists; choose a clean checkout.')
    content = b'Synthetic restore drill. No credentials or personal information.\n'
    with zipfile.ZipFile(archive_path, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('config/demo.txt', content)
    with manifest_path.open('x', encoding='utf-8') as target:
        json.dump({'config/demo.txt': hashlib.sha256(content).hexdigest()}, target, indent=2)
        target.write('\n')
    print('Created synthetic demo backup and manifest in examples/.')


if __name__ == '__main__':
    main()
