"""Cross-compile included benign source; never execute the resulting samples.

Usage: python scripts/build_fixtures.py OUTPUT_DIRECTORY
Requires verified .tools/paths.json; output must be outside the synced project.
"""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
tools = json.loads((root / '.tools/paths.json').read_text())
destination = Path(sys.argv[1]).absolute()
if destination.is_relative_to(root.parent):
    raise ValueError('Fixture outputs must be outside the synced workspace')
destination.mkdir(parents=True, exist_ok=False)
source = root / 'fixtures/source/benign.c'
records = []
for format_name, architecture, target in [('PE', 'x64', 'x86_64-windows-gnu'),
                                         ('PE', 'x86', 'x86-windows-gnu'),
                                         ('ELF', 'x64', 'x86_64-linux-musl'),
                                         ('ELF', 'x86', 'x86-linux-musl')]:
    suffix = '.exe' if format_name == 'PE' else '.elf'
    output = destination / f'{format_name.lower()}-{architecture}{suffix}'
    entry = 'entry_fixture'
    argv = [tools['zig'], 'cc', '-target', target, '-O0', '-fno-sanitize=all', '-fno-stack-protector',
            '-fno-unwind-tables', '-fno-asynchronous-unwind-tables', '-nostdlib',
            '-ffile-prefix-map='+root.as_posix()+'=/fixture-source',
            '-fdebug-prefix-map='+root.as_posix()+'=/fixture-source',
            '-Wl,--entry,' + entry, str(source), '-o', str(output)]
    if format_name == 'ELF':
        argv.extend(['-static', '-fno-pie', '-no-pie'])
    else:
        argv.extend(['-Wl,--subsystem,console','-Wl,--strip-debug'])
    environment = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(destination / 'zig-cache'))
    result = subprocess.run(argv, capture_output=True, timeout=120, env=environment, shell=False)
    if result.returncode:
        raise RuntimeError(result.stderr.decode('utf-8', 'replace'))
    with output.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    records.append({'name': output.name, 'format': format_name, 'architecture': architecture,
                    'sha256': digest, 'argv': argv, 'executed': False})
    print(f'{output.name}: built, never executed')
(destination / 'manifest.json').write_text(json.dumps(records, indent=2), encoding='utf-8')
