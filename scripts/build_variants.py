"""Build benign imports/resources/PIE/stripped/optimized variants; never run them."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
tools=json.loads((root/'.tools/paths.json').read_text())
output=Path(sys.argv[1]).resolve()
if output.is_relative_to(root.parent) or 'onedrive' in str(output).lower():
    raise ValueError('Use private local output storage')
output.mkdir(parents=True,exist_ok=False)
environment=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(output/'zig-cache'))
records=[]
def run(arguments):
    result=subprocess.run([tools['zig'],*arguments],capture_output=True,timeout=120,env=environment,shell=False)
    if result.returncode:
        raise RuntimeError(result.stderr.decode('utf-8','replace'))
common=['cc','-O0','-fno-sanitize=all','-fno-stack-protector','-fno-unwind-tables',
    '-fno-asynchronous-unwind-tables','-nostdlib','-ffile-prefix-map='+str(root)+'=/fixture-source']
run(['rc','/nologo','/fo',str(output/'benign.res'),str(root/'fixtures/source/benign.rc')])
variants=[('pe-import-resource.exe',[*common,'-target','x86_64-windows-gnu',str(root/'fixtures/source/imports.c'),
    str(output/'benign.res'),'-lkernel32','-Wl,--entry,import_fixture','-Wl,--subsystem,console']),
    ('libfixture.so',[*common,'-target','x86_64-linux-musl','-shared','-fPIC',str(root/'fixtures/source/library.c'),'-Wl,-soname,libfixture.so']),
    ('elf-dynamic.so',[*common,'-target','x86_64-linux-musl','-shared','-fPIC',str(root/'fixtures/source/imports.c'),
        '-L'+str(output),'-lfixture','-Wl,--entry,import_fixture']),
    ('elf-pie.elf',[*common,'-target','x86_64-linux-musl','-fPIE','-pie',str(root/'fixtures/source/benign.c'),'-Wl,--entry,entry_fixture']),
    ('elf-stripped.elf',[*common,'-target','x86_64-linux-musl','-static','-fno-pie','-no-pie','-s',str(root/'fixtures/source/benign.c'),'-Wl,--entry,entry_fixture']),
    ('pe-optimized.exe',[*common,'-O2','-target','x86_64-windows-gnu',str(root/'fixtures/source/benign.c'),'-Wl,--entry,entry_fixture','-Wl,--subsystem,console'])]
for name,arguments in variants:
    target=output/name
    run([*arguments,'-o',str(target)])
    records.append({'name':name,'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'sample_executed':False})
    print(name,'built; never executed',flush=True)
(output/'manifest.json').write_text(json.dumps(records,indent=2))
