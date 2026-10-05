"""Presentation-independent orchestration of immutable, local static analysis."""
import hashlib
import json
import platform
import sys
from datetime import datetime,timezone
from pathlib import Path
from . import __version__
from .backend import ROOT, CAP, ghidra, read_json
from .reports import SCHEMA_VERSION, JSON_CAP,HTML_CAP,export
from .safeio import collect, new_run, MAX_INPUT, write_new
from .supervisor import run_worker
from .triage import findings


def parser_worker(mode,snapshot,directory,rules=None,timeout=30):
    output=directory/'evidence.json'
    argv=[sys.executable,'-I',str(ROOT/'src/binary_workbench/worker.py'),mode,str(snapshot),str(output)]
    if rules:
        argv.append(str(rules))
    result=run_worker(argv,directory,timeout=timeout,watched=[(output,CAP)])
    if result.status!='complete' or not output.exists():
        return {'status':result.status if result.status!='complete' else 'failed','reason':'worker_did_not_complete'}
    return read_json(output)


def analyze_file(source,*,runtime_root=None,config=None,selection='',static_only=False,rules=None,timeout=180):
    run=new_run(runtime_root)
    report={'schema_version':SCHEMA_VERSION,'tool':{'name':'binary-workbench','version':__version__},
        'metadata':{'generated_at':datetime.now(timezone.utc).isoformat(),'host':platform.system(),
                    'host_machine':platform.machine(),'python':platform.python_version()},
        'sample':{},'static':{},'reverse_engineering':{},'signatures':{},'findings':[],'warnings':[],
        'limits':{'input_bytes':MAX_INPUT,'parser_wall_seconds':30,'parser_memory_bytes':1024**3,
            'parser_processes':2,'strings':20000,'string_characters':4096,'retained_string_bytes':8*1024**2,
            'backend_output_bytes':CAP,'json_output_bytes':JSON_CAP,'html_output_bytes':HTML_CAP,'diagnostic_bytes':1024**2,
            'sampled_worker_disk_bytes':256*1024**2,'disk_enforcement':'sampled; overshoot possible',
            'network_enforcement':'no network feature; OS network isolation is external',
            'isolation':'resource containment, not a malware security boundary'}}
    with collect(source,run) as (snapshot,identity):
        report['sample']=identity
        work=run/'static';work.mkdir()
        static=parser_worker('static',snapshot,work)
        if static.get('sha256')!=identity['sha256'] or static.get('size')!=identity['size']:
            report.update(status='failed',static={'status':'failed','reason':'static_worker_failed_or_identity_mismatch'},
                reverse_engineering={'status':'skipped','reason':'static_failed'},signatures={'status':'skipped','reason':'static_failed'})
            export(report,run)
            return report,run
        report['static']=static
        signature={'status':'skipped','reason':'no_local_rules_requested','matches':[]}
        if rules:
            rulework=run/'signatures';rulework.mkdir()
            with collect(rules,rulework,max_size=4*1024**2) as (rule_snapshot,rule_identity):
                signature=parser_worker('signatures',snapshot,rulework,rule_snapshot,timeout=15)
                if signature.get('status')=='complete' and signature.get('sha256')!=identity['sha256']:
                    signature={'status':'failed','reason':'signature_identity_mismatch','matches':[]}
                signature['rules_sha256']=rule_identity['sha256']
            signature['includes']='disabled'
        report['signatures']=signature
        backend={'status':'skipped','reason':'static_only_requested','functions':[],'details':[]}
        if not static_only:
            if static.get('architecture') not in ('x86','x64') or static.get('status')!='complete' or static.get('managed'):
                backend={'status':'unsupported','reason':'requires_complete_native_x86_or_x64','functions':[],'details':[]}
            else:
                rework=run/'reverse-engineering';rework.mkdir()
                try:
                    backend=ghidra(snapshot,identity['sha256'],static,rework,config,selection,timeout)
                except (OSError,ValueError,KeyError) as error:
                    backend={'status':'unavailable','reason':type(error).__name__,'functions':[],'details':[]}
        report['reverse_engineering']=backend
        report['findings']=findings(static,signature)
        if len(report['findings'])==10000:
            report['warnings'].append('finding_limit_reached')
        statuses=[static['status'],backend['status'],signature['status']]
        report['status']='unsupported' if static['status']=='unsupported' else 'complete'
        if report['status']=='complete' and any(s not in ('complete','skipped') for s in statuses):
            report['status']='partial'
        if static.get('strings_truncated') or static.get('indicators_truncated') or signature.get('truncated') or report['warnings']:
            report['status']='partial';report['warnings'].append('evidence_truncated')
        for row in static['sections']+static['segments']+static['regions']:
            if isinstance(row['va'],int):
                row['va']=hex(row['va'])
        export(report,run)
    return report,run
