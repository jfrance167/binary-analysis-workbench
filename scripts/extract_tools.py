"""Extract explicitly prepared, hash-verified official archives into .tools.

No archives from analysis samples are accepted. Reject path traversal and links.
"""
import hashlib
import json
import stat
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
tool_root = root / '.tools'
records = []
for metadata in json.loads((root/'toolchain.lock.json').read_text(encoding='utf-8-sig')):
    kind,name,expected=metadata['kind'],metadata['archive'],metadata['sha256']
    archive_path = tool_root / 'downloads' / name
    with archive_path.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
            raise ValueError('Archive publisher hash mismatch')
    destination = tool_root / kind
    if destination.exists():
        raise ValueError('Refusing existing extraction directory')
    with zipfile.ZipFile(archive_path) as archive:
        if sum(i.file_size for i in archive.infolist()) > 3 * 1024**3:
            raise ValueError('Extraction size limit')
        for item in archive.infolist():
            path = Path(item.filename)
            if path.is_absolute() or '..' in path.parts or ':' in item.filename or '\\' in item.filename:
                raise ValueError('Unsafe archive path')
            if stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError('Archive link rejected')
        archive.extractall(destination)
    install = next(p for p in destination.iterdir() if p.is_dir())
    records.append(metadata)
    print(f'{kind}: extracted verified archive')
    if kind == 'ghidra':
        ghidra = str(install)
    elif kind == 'jdk':
        java, javac = str(install / 'bin/java.exe'), str(install / 'bin/javac.exe')
    else:
        zig = str(install / 'zig.exe')
(tool_root / 'paths.json').write_text(json.dumps(dict(ghidra=ghidra, java=java, javac=javac, zig=zig), indent=2), encoding='utf-8')
