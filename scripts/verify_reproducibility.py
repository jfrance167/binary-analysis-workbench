"""Compare semantic reports from fixed-version repeat analysis of our harmless fixture."""
import json
import sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'src'))
from binary_workbench.core import analyze_file
fixtures=Path(sys.argv[1]).resolve()
summary=json.loads((fixtures/'integration-summary.json').read_text())
old=json.loads((Path(summary[0]['report_directory'])/'report.json').read_text())
new,run=analyze_file(fixtures/'pe-x64.exe',config=json.loads((root/'.tools/paths.json').read_text()),
    selection='branch_fixture,string_fixture,entry_fixture',rules=root/'rules/benign-demo.yar')
assert new['metadata']['generated_at']!=old['metadata']['generated_at']
old['metadata'].pop('generated_at');new['metadata'].pop('generated_at')
assert old==new,'Same-version semantic repeat differed; investigate instead of claiming reproducibility'
(fixtures/'repeat-verification.json').write_text(json.dumps({'same_version_semantic_repeat':'PASS',
    'excluded':['metadata.generated_at'],'cross_version_identity_claimed':False}))
print('Same-version semantic repeat PASS; variable generation timestamp excluded')
