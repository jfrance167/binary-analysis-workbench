"""Direct bounded Ghidra invocation and strict normalization of its output."""
import hashlib
import json
import re
from bisect import bisect_right
from pathlib import Path
from .safeio import local_path
from .static import AddressMap
from .supervisor import run_worker

ROOT = Path(__file__).resolve().parents[2]
CAP = 32*1024**2


def read_json(path, cap=CAP):
    with Path(path).open('rb') as stream:
        raw = stream.read(cap+1)
    if len(raw)>cap:
        raise ValueError('JSON output limit')
    return json.loads(raw)


def validate_backend(data, digest):
    if not isinstance(data,dict) or not isinstance(data.get('sha256'),str) or data['sha256'].lower()!=digest:
        raise ValueError('backend_hash_mismatch')
    if data.get('backend')!='ghidra' or data.get('version')!='12.1.4':
        raise ValueError('backend_identity_mismatch')
    if not isinstance(data.get('language'),str) or len(data['language'])>128:
        raise ValueError('backend_language_invalid')
    for key, limit in (('functions',50000),('details',20),('warnings',100)):
        if not isinstance(data.get(key),list) or len(data[key])>limit:
            raise ValueError('backend_list_invalid')
    def check_address(value):
        if not isinstance(value,dict) or not isinstance(value.get('space'),str) or len(value['space'])>128:
            raise ValueError('backend_address_invalid')
        if not isinstance(value.get('value'),str) or not re.fullmatch(r'0x[0-9a-fA-F]{1,16}',value['value']):
            raise ValueError('backend_address_invalid')
    for row in data['functions']+data['details']:
        if not isinstance(row,dict) or not isinstance(row.get('name'),str) or len(row['name'])>4096:
            raise ValueError('backend_function_invalid')
        if row.get('boundary_source')!='ghidra_analysis' or not isinstance(row.get('name_source'),str):
            raise ValueError('backend_function_provenance_invalid')
        check_address(row.get('address'));check_address(row.get('end'))
    totals={'references':0,'callers':0,'blocks':0,'edges':0}
    for row in data['details']:
        for key, limit in (('instructions',10000),('references',100000),('callers',100000),('blocks',10000)):
            if not isinstance(row.get(key),list) or len(row[key])>limit:
                raise ValueError('backend_detail_invalid')
        if not isinstance(row.get('pseudocode'),str) or len(row['pseudocode'])>1024**2:
            raise ValueError('backend_pseudocode_invalid')
        if row.get('decompilation_status') not in ('complete','unavailable') or not isinstance(row.get('instructions_truncated'),bool):
            raise ValueError('backend_detail_state_invalid')
        for instruction in row['instructions']:
            if not isinstance(instruction,dict):raise ValueError('backend_instruction_invalid')
            check_address(instruction.get('address'))
            if not re.fullmatch(r'(?:[0-9a-f]{2}){1,15}',instruction.get('bytes','')) or not isinstance(instruction.get('text'),str):
                raise ValueError('backend_instruction_invalid')
        for key in ('references','callers','blocks'):
            totals[key]+=len(row[key])
        for reference in row['references']:
            if not isinstance(reference,dict):raise ValueError('backend_reference_invalid')
            check_address(reference.get('from'));check_address(reference.get('to'))
        for reference in row['callers']:
            if not isinstance(reference,dict):raise ValueError('backend_reference_invalid')
            check_address(reference.get('from'))
        for block in row['blocks']:
            if not isinstance(block,dict):raise ValueError('backend_block_invalid')
            check_address(block.get('start'));check_address(block.get('end'))
            if not isinstance(block.get('edges'),list) or len(block['edges'])>1000:
                raise ValueError('backend_edges_invalid')
            totals['edges']+=len(block['edges'])
            for edge in block['edges']:
                if not isinstance(edge,dict):raise ValueError('backend_edge_invalid')
                check_address(edge.get('to'))
    if totals['references']+totals['callers']>100000 or totals['edges']>100000 or totals['blocks']>200000:
        raise ValueError('backend_total_limit')


def join_evidence(data, static):
    """Ghidra addresses refer to its loaded program. Join only known RAM mappings."""
    strings=sorted(static['strings'],key=lambda s:s['file_offset'])
    starts=[s['file_offset'] for s in strings]
    imports={}
    mappings=AddressMap(static['regions'],static['size'])
    for item in static['imports']:
        if item.get('va'):
            imports.setdefault(int(item['va'],16),[]).append(item['id'])
    def offset(address):
        return mappings.offset(int(address['value'],16)) if address['space']=='ram' else None
    for function in data['functions']+data['details']:
        function['file_offset']=offset(function['address'])
    for detail in data['details']:
        for instruction in detail['instructions']:
            instruction['file_offset']=offset(instruction['address'])
        for reference in detail['references']:
            reference['file_offset']=offset(reference['from'])
            target=offset(reference['to'])
            reference['target_file_offset']=target
            reference['evidence_ids']=[]
            if target is not None:
                # All retained runs span at most 8192 bytes. Bisect avoids a full
                # strings scan for every reference in maximum-sized backends.
                left=bisect_right(starts,target-8192)
                right=bisect_right(starts,target)
                reference['evidence_ids'] += [s['id'] for s in strings[left:right] if target<s['file_offset']+s['length']][:20]
            if reference['to']['space']=='ram':
                reference['evidence_ids'] += imports.get(int(reference['to']['value'],16),[])[:20]


def ghidra(snapshot, digest, static, directory, config, selection='', timeout=180):
    if not config:
        return {'status':'unavailable','reason':'backend_not_configured','functions':[],'details':[]}
    installation=local_path(config['ghidra']); java=local_path(config['java'])
    props=(installation/'Ghidra/application.properties').read_text(encoding='utf-8')
    if 'application.version=12.1.4' not in props.splitlines():
        return {'status':'unavailable','reason':'unreviewed_backend_version','functions':[],'details':[]}
    output=directory/'backend.json'
    utility=installation/'Ghidra/Framework/Utility/lib/Utility.jar'
    argv=[str(java),'-Xmx2G','-Xshare:off','-Djava.system.class.loader=ghidra.GhidraClassLoader',
        '-Dfile.encoding=UTF8','-Duser.language=en','-Duser.country=US','-Duser.home='+str(directory),
        '-Djava.io.tmpdir='+str(directory),'-Dapplication.settingsdir='+str(directory/'settings'),
        '-Dapplication.cachedir='+str(directory/'cache'),'-Djavax.xml.accessExternalDTD=',
        '-Djavax.xml.accessExternalSchema=','--enable-native-access=ALL-UNNAMED','-cp',str(utility),
        'ghidra.Ghidra','ghidra.app.util.headless.AnalyzeHeadless',str(directory),'analysis',
        '-import',str(snapshot),'-scriptPath',str(ROOT/'ghidra_scripts'),'-preScript','WorkbenchPolicy.java',
        '-postScript','WorkbenchExport.java',str(output),selection,'-analysisTimeoutPerFile','90',
        '-max-cpu','2','-deleteProject','-log',str(directory/'ghidra.log'),'-scriptlog',str(directory/'scripts.log')]
    result=run_worker(argv,directory,timeout=timeout,memory=4*1024**3,processes=4,watched=[(output,CAP)])
    if result.status!='complete' or not output.exists():
        return {'status':result.status if result.status!='complete' else 'failed','reason':'backend_did_not_complete',
                'functions':[],'details':[]}
    try:
        data=read_json(output)
        validate_backend(data,digest)
        join_evidence(data,static)
    except (ValueError,KeyError,TypeError):
        return {'status':'failed','reason':'invalid_backend_output','functions':[],'details':[]}
    data['status']='complete'
    if not data['details'] or any(x['decompilation_status']!='complete' or x['instructions_truncated'] for x in data['details']) or data['warnings']:
        data['status']='partial'
    data['selection']=selection or 'first_three_functions'
    data['provenance']={name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in
        [('launcher',java),('utility',utility),('policy',ROOT/'ghidra_scripts/WorkbenchPolicy.java'),
         ('exporter',ROOT/'ghidra_scripts/WorkbenchExport.java')]}
    data['limits']={'wall_seconds':timeout,'analysis_seconds':90,'decompile_seconds_per_function':15,
                    'memory_bytes':4*1024**3,'processes':4,'cpu_threads':2,'output_bytes':CAP}
    return data
