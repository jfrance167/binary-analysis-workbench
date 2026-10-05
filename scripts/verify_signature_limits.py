"""Exercise native scan and outer worker deadlines using only synthetic benign bytes."""
import json
import sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'src'))
from binary_workbench.core import parser_worker
from binary_workbench.safeio import new_run
run=new_run()
sample=run/'benign.bin';sample.write_bytes(b'A'*1024)
rules=run/'expensive.yar'
rules.write_text('rule expensive { condition: for all i in (1..1000000000000) : (uint8(i % filesize) == 0x41) }')
wall=run/'wall';wall.mkdir()
result=parser_worker('signatures',sample,wall,rules,timeout=0.5)
assert result['status']=='timeout',result
engine=run/'engine';engine.mkdir()
result=parser_worker('signatures',sample,engine,rules,timeout=15)
assert result['status']=='failed' and result['reason'] in ('ScanError','TimeoutError'),result
print('signature supervisor timeout PASS; native scan deadline PASS; no sample execution')
(run/'verification.json').write_text(json.dumps({'wall_status':'timeout','engine_status':result['status'],
    'engine_reason':result['reason'],'sample_executed':False},indent=2))
