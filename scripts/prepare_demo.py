"""Export only our verified harmless fixture report after privacy review checks.

Usage: venv-python scripts/prepare_demo.py BENIGN_FIXTURE_DIRECTORY
Never use this on submitted samples. Normal reports stay in private runtime storage.
"""
import hashlib
import json
import re
import argparse
import uuid
import sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'src'))
from binary_workbench.reports import export
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('fixture_directory');parser.add_argument('--refresh',action='store_true',help='Archive and refresh this project\'s own checked benign example only')
args=parser.parse_args()
fixtures=Path(args.fixture_directory).resolve()
summary=json.loads((fixtures/'integration-summary.json').read_text())
pe=next(item for item in summary if item['fixture']=='pe-x64.exe')
assert hashlib.sha256((fixtures/'pe-x64.exe').read_bytes()).hexdigest()==pe['sha256']
report=json.loads((Path(pe['report_directory'])/'report.json').read_text())
assert report['status']=='complete' and report['sample']['sha256']==pe['sha256']
assert report['signatures']['matches'] and report['reverse_engineering']['details']
serialized=json.dumps(report,ensure_ascii=True)
if re.search(r'(?i)Jake|OneDrive|AppData|\.private|[A-Z]:[\\/]+Users[\\/]',serialized):
    raise ValueError('Demo privacy review failed')
output=root/'examples'/'benign-pe64'
if args.refresh and output.exists():
    if output.resolve()!=output or output.is_symlink() or output.is_junction():
        raise ValueError('Demo path redirection rejected')
    previous=json.loads((output/'report.json').read_text())
    if previous['sample']['sha256']!=pe['sha256']:
        raise ValueError('Refusing a different sample\'s existing example')
    expected={'report.json','report.html','report.png','verification.json','failure-verification.json'}
    if any(p.name not in expected or not p.is_file() for p in output.iterdir()):
        raise ValueError('Unexpected example files; do not overwrite')
    history=fixtures/'demo-history'/uuid.uuid4().hex;history.mkdir(parents=True,exist_ok=False)
    for source in output.iterdir():
        if source.is_symlink() or source.resolve().parent!=output:
            raise ValueError('Demo file redirection rejected')
        content=source.read_bytes()
        with (history/source.name).open('xb') as saved:saved.write(content)
        if (history/source.name).read_bytes()!=content:
            raise ValueError('Demo archive verification failed')
        source.unlink()
else:
    output.mkdir(parents=True,exist_ok=False)
export(report,output)
public=[{k:v for k,v in item.items() if k!='report_directory'} for item in summary]
(output/'verification.json').write_text(json.dumps(public,indent=2))
failures=json.loads((fixtures/'failure-summary.json').read_text())
(output/'failure-verification.json').write_text(json.dumps(failures,indent=2))
print('Reviewed benign PE64 JSON/HTML exported; no submitted sample or private runtime path included.')
