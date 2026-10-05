"""Focused prospective-file/schema/workflow hygiene checks; never prints sensitive matches.

Not an exhaustive secret scanner. GitHub eligibility and remote checks remain separate.
"""
import ast
import json
import re
import sys
from pathlib import Path
# Review helper only: reuse the base interpreter's installed PyYAML (also used
# by the already installed Bandit). Venv dependencies remain first in resolution.
sys.path.append(str(Path(sys.base_prefix)/'Lib/site-packages'))
import yaml
from jsonschema import Draft202012Validator
root=Path(__file__).resolve().parents[1]
ignore={'.tools','.venv','.git','.playwright-cli','__pycache__','.pytest_cache','.hypothesis'}
files=[p for p in root.rglob('*') if p.is_file() and not any(x in ignore for x in p.relative_to(root).parts)]
patterns={
    'private_key':r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    'github_token':r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b',
    'aws_access_key':r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',
    'openai_style_key':r'\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b',
    'machine_private_path':r'(?i)[A-Z]:[\\/]+Users[\\/]+Jake[\\/]|OneDrive - Alfred State College|\.private[\\/]'
}
counts={name:0 for name in patterns}
locations=[]
for path in files:
    if path.suffix=='.png':continue
    content=path.read_text(encoding='utf-8-sig')
    if path.suffix=='.py':ast.parse(content,filename=path.name)
    if path.suffix=='.json':json.loads(content)
    # This scanner's literal patterns are definitions, not detected credentials.
    if path.resolve()==Path(__file__).resolve():continue
    for name,pattern in patterns.items():
        matches=list(re.finditer(pattern,content));counts[name]+=len(matches)
        locations.extend({'file':str(path.relative_to(root)),'line':content[:m.start()].count('\n')+1,'pattern':name} for m in matches)
if any(counts.values()):
    print(json.dumps({'status':'FAIL','match_counts':counts,'redacted_locations':locations}));raise SystemExit(1)
schema=json.loads((root/'schema/report-1.0.0.json').read_text())
Draft202012Validator.check_schema(schema)
Draft202012Validator(schema).validate(json.loads((root/'examples/benign-pe64/report.json').read_text()))
workflows=[]
for path in (root/'.github/workflows').glob('*.yml'):
    data=yaml.load(path.read_text(),Loader=yaml.BaseLoader)
    assert data['on']['push']['branches']==['main'] and 'workflow_dispatch' in data['on']
    for job in data['jobs'].values():
        for step in job['steps']:
            if 'uses' in step:
                assert re.fullmatch(r'[^@]+@[0-9a-f]{40}',step['uses'])
                if step['uses'].startswith('actions/checkout@'):
                    assert step['with']['persist-credentials']=='false'
    workflows.append(path.name)
print(json.dumps({'status':'PASS','prospective_files':len(files),'match_counts':counts,
                  'schema':'PASS','workflow_syntax_and_pins':workflows,'github_execution':'NOT RUN'}))
