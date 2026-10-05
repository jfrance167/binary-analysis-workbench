"""Benign end-to-end missing/failing/timeout and stripped/optimized investigation checks."""
import json
import sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'src'))
from binary_workbench.core import analyze_file
from binary_workbench.cli import main
from jsonschema import Draft202012Validator
fixtures=Path(sys.argv[1]).resolve();variants=Path(sys.argv[2]).resolve()
tools=json.loads((root/'.tools/paths.json').read_text())
validator=Draft202012Validator(json.loads((root/'schema/report-1.0.0.json').read_text()))
records=[]
def check(name,source,expected,**kwargs):
    report,run=analyze_file(source,**kwargs)
    validator.validate(report)
    assert report['static']['status']=='complete'
    assert report['reverse_engineering']['status']==expected,(name,report['reverse_engineering']['status'])
    records.append({'check':name,'status':report['status'],'backend_status':expected,'sample_executed':False})
    print(name,'PASS',flush=True)
    return report,run
pe=fixtures/'pe-x64.exe'
check('missing-backend',pe,'unavailable')
check('failed-backend',pe,'failed',config={**tools,'java':sys.executable})
check('real-ghidra-timeout',pe,'timeout',config=tools,timeout=1)
stripped,run=check('stripped-recovery',variants/'elf-stripped.elf','complete',config=tools)
assert stripped['reverse_engineering']['details'] and all(x['pseudocode'] for x in stripped['reverse_engineering']['details'])
assert any(x['name_source']=='DEFAULT' for x in stripped['reverse_engineering']['functions'])
assert main(['inspect',str(run/'report.json'),'does-not-exist'])==5
optimized,run=check('optimized-recovery',variants/'pe-optimized.exe','complete',config=tools,selection='branch_fixture')
assert optimized['reverse_engineering']['details'][0]['pseudocode']
assert main(['inspect',str(run/'report.json'),'branch_fixture'])==0
imported,run=check('import-reference',variants/'pe-import-resource.exe','complete',config=tools,selection='import_fixture')
assert any(identifier.startswith('import:') for d in imported['reverse_engineering']['details'] for r in d['references'] for identifier in r['evidence_ids'])
(fixtures/'failure-summary.json').write_text(json.dumps(records,indent=2))
