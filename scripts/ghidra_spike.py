"""Real decompilation feasibility check of an included benign fixture only."""
import json
import hashlib
import sys
import tempfile
from pathlib import Path
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / 'src'))
from binary_workbench.supervisor import run_worker
tools = json.loads((root / '.tools/paths.json').read_text())
fixture = Path(sys.argv[1]).resolve()
record = next(x for x in json.loads((fixture.parent/'manifest.json').read_text()) if x['name']==fixture.name)
if hashlib.sha256(fixture.read_bytes()).hexdigest()!=record['sha256'] or record.get('executed') is not False:
    raise ValueError('Only a source-built, never-executed benign fixture is accepted')
with tempfile.TemporaryDirectory(prefix='binary-ghidra-spike-') as temporary:
    working = Path(temporary)
    output = working / 'backend.json'
    ghidra = Path(tools['ghidra'])
    argv = [tools['java'], '-Xmx2G', '-Xshare:off', '-Djava.system.class.loader=ghidra.GhidraClassLoader',
            '-Dfile.encoding=UTF8', '-Duser.language=en', '-Duser.country=US',
            '-Duser.home=' + str(working), '-Djava.io.tmpdir=' + str(working),
            '-Dapplication.settingsdir=' + str(working / 'settings'),
            '-Dapplication.cachedir=' + str(working / 'cache'),
            '-Djavax.xml.accessExternalDTD=', '-Djavax.xml.accessExternalSchema=',
            '--enable-native-access=ALL-UNNAMED',
            '-cp', str(ghidra / 'Ghidra/Framework/Utility/lib/Utility.jar'),
            'ghidra.Ghidra', 'ghidra.app.util.headless.AnalyzeHeadless',
            str(working), 'benign', '-import', str(Path(sys.argv[1]).resolve()),
            '-scriptPath', str(root / 'ghidra_scripts'), '-preScript', 'WorkbenchPolicy.java',
            '-postScript', 'WorkbenchExport.java', str(output), 'branch_fixture,string_fixture,entry_fixture',
            '-analysisTimeoutPerFile', '90', '-max-cpu', '2', '-deleteProject',
            '-log', str(working / 'ghidra.log'), '-scriptlog', str(working / 'scripts.log')]
    result = run_worker(argv, working, timeout=180, memory=4*1024**3, processes=4,
                        watched=[(output,32*1024**2)])
    print('worker status:',result.status, 'exit:',result.returncode)
    if output.exists():
        data = json.loads(output.read_text())
        print('functions:', len(data['functions']), 'selected:',len(data['details']))
        for detail in data['details']:
            print(detail['name'], 'instructions:',len(detail['instructions']), 'pseudocode:',bool(detail['pseudocode']))
        assert any(x['name']=='branch_fixture' and x['pseudocode'] for x in data['details'])
        (root / '.tools/spike-result.json').write_text(json.dumps({'status':result.status,'backend':data['version'],
            'functions':len(data['functions']), 'selected':[{k:x[k] for k in ['name','decompilation_status']} for x in data['details']]}), encoding='utf-8')
    else:
        print('Benign backend produced no output; inspect its private diagnostics locally.')
        raise SystemExit(1)
