"""Verify two test-only wheels against existing installed source before reuse.

Publisher catalog transport for these packages failed. This is local-equivalence
verification, not an independent publisher-digest claim. Runtime parsers use the
separate publisher-verified requirements.lock.
"""
import hashlib
import importlib.metadata
import json
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
records = []
for name in ('colorama', 'pygments'):
    distribution = importlib.metadata.distribution(name)
    wheel = next((root / '.tools/wheels').glob(f'{name}-{distribution.version}-*.whl'))
    checked = 0
    with zipfile.ZipFile(wheel) as archive:
        for entry in archive.infolist():
            # RECORD changes during installation. Package code, entry points,
            # metadata and licenses must match the existing local distribution.
            if entry.is_dir() or entry.filename.endswith('.dist-info/RECORD'):
                continue
            installed = Path(distribution.locate_file(entry.filename))
            if not installed.is_file() or installed.read_bytes() != archive.read(entry):
                raise ValueError('Installed source differs from downloaded test wheel')
            checked += 1
    with wheel.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    records.append({'name':name,'version':distribution.version,'sha256':digest,'files_compared':checked,
                    'verification':'equivalent_existing_local_source; publisher catalog unavailable'})
lock = root / 'requirements-test-local.lock'
lock.write_text(''.join(f"{r['name']}=={r['version']} --hash=sha256:{r['sha256']}\n" for r in records))
(root / '.tools/test-local-review.json').write_text(json.dumps(records,indent=2))
print('Test-only local source equivalence verified:', [(r['name'],r['files_compared']) for r in records])
