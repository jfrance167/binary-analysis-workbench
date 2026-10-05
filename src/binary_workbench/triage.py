"""Explain observations without issuing a verdict or an uncalibrated score."""
import hashlib
from .static import mapped_offset


def findings(static, signatures):
    result = []
    def add(kind, evidence, priority, explanation, uncertainty, locations):
        if len(result)>=10000:
            return
        identity = kind+':'+','.join(sorted(evidence))
        result.append({'id':kind+':'+hashlib.sha256(identity.encode()).hexdigest()[:16],
            'kind':kind,'priority':priority,'explanation':explanation,'evidence_ids':evidence,
            'locations':locations,'uncertainty':uncertainty,'classification':'heuristic_interpretation'})
    for row in static.get('sections',[]):
        if 'w' in row['permissions'] and 'x' in row['permissions']:
            add('writable_executable',[row['id']],'high','Section is writable and executable.',
                'JIT runtimes, loader stubs and unusual legitimate toolchains can use these permissions.',
                [{'file_offset':row['offset'],'length':row['file_size']}])
        if row['valid'] and row['file_size']>=1024 and row['entropy'] is not None and row['entropy']>=7.2:
            add('high_entropy',[row['id']],'medium','Section entropy is at least 7.2 bits per byte; inspect possible packing.',
                'Compression, encryption and ordinary assets can produce the same observation; this does not detect a packer.',
                [{'file_offset':row['offset'],'length':row['file_size']}])
    imports = static.get('imports',[])
    allocation = [x for x in imports if x['name'].lower() in ('virtualallocex','ntallocatevirtualmemory')]
    writing = [x for x in imports if x['name'].lower() in ('writeprocessmemory','ntwritevirtualmemory')]
    launching = [x for x in imports if x['name'].lower() in ('createremotethread','ntcreatethreadex')]
    if allocation and writing and launching:
        rows = [allocation[0],writing[0],launching[0]]
        add('remote_process_api_combination',[x['id'] for x in rows],'high',
            'Imports include remote allocation, memory writing and thread creation APIs.',
            'Debuggers, accessibility tools and security products can use these APIs; imports do not prove calls occurred.',
            [{'file_offset':x.get('file_offset'),'va':x.get('va')} for x in rows])
    if static.get('entry_va') and static.get('status')!='unsupported':
        address = int(static['entry_va'],16)
        regions = static.get('regions',[])
        containing = [r for r in regions if r['valid'] and r['va']<=address<r['va']+r['memory_size']]
        if address and (len(containing)!=1 or 'x' not in containing[0]['permissions']):
            add('entry_point_anomaly',['entry_point'],'medium','Entry point has an ambiguous or non-executable mapping.',
                'Malformed headers, overlapping layouts, unusual loaders or analysis limitations can explain this.',
                [{'va':static['entry_va'],'file_offset':mapped_offset(regions,address,static['size'])}])
    if static.get('indicators'):
        rows=static['indicators'][:100]
        add('embedded_indicators',[x['id'] for x in rows],'low',
            f"Observed {len(static['indicators'])} candidate network indicators; the first 100 support this finding.",
            'Strings may be documentation, resources, unused code or deliberately misleading data. No indicator was contacted.',
            [{'file_offset':x['file_offset'],'length':x['length']} for x in rows])
    for index, match in enumerate(signatures.get('matches',[])):
        add('signature_match',[f'signature:{index}'],'medium',f"Local rule {match['rule']} matched.",
            'A rule match is only as reliable as its source and condition; harmless demonstration rules are not malware detection.',
            [{'file_offset':match['file_offset'],'length':match['length']}])
    return result
