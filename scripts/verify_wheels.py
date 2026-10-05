"""Explicit setup: verify downloaded wheels against PyPI and write a hash lock.

Usage: python scripts/verify_wheels.py .tools/wheels requirements-dev.lock
Requires network only during this setup step; never used by the analysis runtime.
"""
import hashlib
import json
import sys
import urllib.request
import zipfile
from email.parser import Parser
from pathlib import Path


def main():
    wheel_root, lock, catalog = map(Path, sys.argv[1:4])
    selected = set(sys.argv[4:])
    records = []
    for wheel in sorted(wheel_root.glob('*.whl')):
        with zipfile.ZipFile(wheel) as archive:
            metadata_path = next(n for n in archive.namelist() if n.endswith('.dist-info/METADATA'))
            metadata = Parser().parsestr(archive.read(metadata_path).decode('utf-8'))
        name, version = metadata['Name'], metadata['Version']
        if selected and name.lower().replace('_', '-') not in selected:
            continue
        url = f'https://pypi.org/pypi/{name}/{version}/json'
        release = json.loads((catalog / f'{wheel.name.split("-")[0]}-{version}.json').read_text(encoding='utf-8-sig'))
        normalize = lambda value: value.lower().replace('_', '-').replace('.', '-')
        if normalize(release['info']['name']) != normalize(name) or release['info']['version'] != version:
            raise ValueError('Catalog identity mismatch')
        expected = next(item['digests']['sha256'] for item in release['urls'] if item['filename'] == wheel.name)
        with wheel.open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if expected != actual:
            raise ValueError(f'Publisher hash mismatch: {name}')
        records.append({'name': name, 'version': version, 'sha256': actual,
                        'filename': wheel.name, 'requirements': metadata.get_all('Requires-Dist', []),
                        'source': url})
        print(f'{name}=={version}: verified')
    lock.write_text(''.join(f"{r['name']}=={r['version']} --hash=sha256:{r['sha256']}\n" for r in records), encoding='utf-8')
    (wheel_root.parent / 'wheel-review.json').write_text(json.dumps(records, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
