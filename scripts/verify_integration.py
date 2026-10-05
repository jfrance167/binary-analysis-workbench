"""Verify all capabilities against included benign source; no sample execution.

Usage: venv-python scripts/verify_integration.py FIXTURE_DIRECTORY
Raw reports remain private. The workspace summary contains aggregate test results.
"""
import hashlib
import json
import struct
import re
import sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'src'))
from binary_workbench.core import analyze_file
from jsonschema import Draft202012Validator

fixture_root=Path(sys.argv[1]).resolve()
manifest=json.loads((fixture_root/'manifest.json').read_text())
tools=json.loads((root/'.tools/paths.json').read_text())
schema=json.loads((root/'schema/report-1.0.0.json').read_text())
validator=Draft202012Validator(schema)
records=[]
for fixture in manifest:
    source=fixture_root/fixture['name']
    original=source.read_bytes()
    assert hashlib.sha256(original).hexdigest()==fixture['sha256']
    report,run=analyze_file(source,config=tools,selection='branch_fixture,string_fixture,entry_fixture',rules=root/'rules/benign-demo.yar')
    validator.validate(report)
    assert source.read_bytes()==original
    assert report['status']=='complete', {k:report[k].get('status') for k in ('static','reverse_engineering','signatures')}
    static=report['static'];backend=report['reverse_engineering']
    assert static['format']==fixture['format'] and static['architecture']==fixture['architecture']
    assert static['sha256']==fixture['sha256']==backend['sha256'].lower()
    if fixture['format']=='PE':
        pe_offset=struct.unpack_from('<I',original,0x3c)[0]
        entry_rva=struct.unpack_from('<I',original,pe_offset+24+16)[0]
        assert int(static['entry_rva'],16)==entry_rva
        assert struct.unpack_from('<H',original,pe_offset+4)[0]==static['headers']['Machine']
    else:
        fmt='<Q' if fixture['architecture']=='x64' else '<I'
        assert struct.unpack_from(fmt,original,24)[0]==int(static['entry_va'],16)
    marker=b'BINARY_WORKBENCH_BENIGN_FIXTURE'
    offset=original.index(marker)
    assert any(s['file_offset']==offset and s['text'].startswith(marker.decode()) for s in static['strings'])
    assert any(m['file_offset']==offset and m['rule']=='BinaryWorkbenchBenignMarker' for m in report['signatures']['matches'])
    names={x['name'] for x in backend['details']}
    # x86 PE symbol decoration is a legitimate toolchain difference.
    assert any('branch_fixture' in n for n in names)
    for detail in backend['details']:
        assert detail['instructions'] and detail['pseudocode'] and detail['blocks']
        for instruction in detail['instructions']:
            start=instruction['file_offset']
            if start is not None:
                encoded=bytes.fromhex(instruction['bytes'])
                assert original[start:start+len(encoded)]==encoded
    branch=next(x for x in backend['details'] if 'branch_fixture' in x['name'])
    assert len(branch['blocks'])>=3
    assert re.search(r'(?:0x7|\b7\b)',branch['pseudocode'])
    assert re.search(r'(?:-\s*(?:0x3|3)\b|0xfffffffd)',branch['pseudocode'])
    assert any(x['references'] for x in backend['details'])
    assert any(r['evidence_ids'] for x in backend['details'] for r in x['references'])
    records.append({'fixture':fixture['name'],'status':report['status'],'sha256':fixture['sha256'],
        'functions':len(backend['functions']),'selected':len(backend['details']),
        'instructions':sum(len(x['instructions']) for x in backend['details']),
        'joined_string_or_import_references':sum(bool(r['evidence_ids']) for x in backend['details'] for r in x['references']),
        'signature_matches':len(report['signatures']['matches']),'report_directory':str(run),
        'sample_executed':False})
    print(fixture['name'],'PASS',flush=True)
(fixture_root/'integration-summary.json').write_text(json.dumps(records,indent=2))
