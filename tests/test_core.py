import hashlib
import json
import sys
from pathlib import Path
import pytest
from binary_workbench.core import analyze_file
from binary_workbench.backend import validate_backend
from binary_workbench.supervisor import WorkerResult
from binary_workbench.cli import main


def test_unsupported_private_report_and_missing_backend(tmp_path):
    from jsonschema import Draft202012Validator
    source=tmp_path/'unknown';source.write_bytes(b'harmless https://example.invalid')
    report,run=analyze_file(source,runtime_root=tmp_path/'runtime')
    assert report['status']=='unsupported' and report['reverse_engineering']['status']=='unsupported'
    schema=json.loads((Path(__file__).resolve().parents[1]/'schema/report-1.0.0.json').read_text())
    Draft202012Validator(schema).validate(report)
    serialized=(run/'report.json').read_text()
    assert str(source) not in serialized and source.read_bytes().startswith(b'harmless')


def test_worker_failure_explicit_and_no_uncontained_fallback(tmp_path,monkeypatch):
    from binary_workbench import core
    source=tmp_path/'sample';source.write_bytes(b'harmless')
    monkeypatch.setattr(core,'run_worker',lambda *args,**kwargs:WorkerResult(124,'timeout','','',0,1))
    report,run=analyze_file(source,runtime_root=tmp_path/'runtime')
    assert report['status']=='failed' and report['static']['status']=='failed'
    assert report['reverse_engineering']['status']=='skipped' and (run/'report.json').exists()


def test_backend_identity_and_structure():
    with pytest.raises(ValueError):validate_backend({'sha256':'wrong'},'a'*64)
    with pytest.raises(ValueError):validate_backend({'sha256':'a'*64,'backend':'ghidra','version':'12.1.4',
        'functions':[{'name':'test','address':{'space':'ram','value':'javascript:bad'}}],
        'details':[],'warnings':[]},'a'*64)


def test_terminal_text_escaped(tmp_path,capsys):
    from test_reports import sample_report
    report=sample_report()
    report['reverse_engineering']={'status':'complete','functions':[{'name':'evil\x1b[31m\nline'}],'details':[]}
    path=tmp_path/'report.json';path.write_text(json.dumps(report))
    assert main(['functions',str(path)])==0
    output=capsys.readouterr().out
    assert '\x1b' not in output and '\\u001b' in output and '\\nline' in output
