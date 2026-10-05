"""Explicit fixed-version trusted-tool setup, never part of sample analysis.

Usage: python scripts/setup_tools.py [--download]
No paid services, version discovery, retries or fallback sources are used. Without
--download, prepared archive files are required. Preserve publisher license files.
"""
import argparse
import hashlib
import json
import runpy
import time
import urllib.request
from pathlib import Path

root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--download',action='store_true')
args=parser.parse_args()
records=json.loads((root/'toolchain.lock.json').read_text(encoding='utf-8-sig'))
downloads=root/'.tools/downloads';downloads.mkdir(parents=True,exist_ok=True)
for record in records:
    target=downloads/record['archive']
    if not target.exists():
        if not args.download:
            raise ValueError('Place the reviewed archives in .tools/downloads or explicitly pass --download')
        if not record['url'].startswith(('https://github.com/NationalSecurityAgency/ghidra/',
            'https://github.com/adoptium/temurin21-binaries/','https://ziglang.org/download/')):
            raise ValueError('Unreviewed tool publisher')
        start=time.monotonic();total=0
        with urllib.request.urlopen(record['url'],timeout=30) as response,target.open('xb') as stream:
            while chunk:=response.read(1024**2):
                total+=len(chunk)
                if total>1024**3 or time.monotonic()-start>180:
                    raise ValueError('Tool download limit; preserve failed file and investigate')
                stream.write(chunk)
    with target.open('rb') as stream:
        if hashlib.file_digest(stream,'sha256').hexdigest()!=record['sha256']:
            raise ValueError('Publisher archive hash mismatch; nothing is extracted')
    print(record['kind'],'archive verified')
runpy.run_path(str(root/'scripts/extract_tools.py'),run_name='__main__')
