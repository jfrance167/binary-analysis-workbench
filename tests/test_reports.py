import hashlib
import json
import pytest
from binary_workbench.reports import html_text,json_text,validate_report,export


def sample_report():
    return {'schema_version':'1.0.0','tool':{'name':'binary-workbench','version':'0.1.0'},
        'status':'complete','metadata':{},'sample':{'sha256':hashlib.sha256(b'').hexdigest(),'size':0},
        'static':{'strings':[{'id':'string:ascii:0','text':'</script><script>alert(1)</script>\x1b[31m',
            'encoding':'ascii','file_offset':0,'length':1,'truncated':False}]},
        'reverse_engineering':{'status':'skipped','functions':[],'details':[]},
        'signatures':{'status':'skipped','matches':[]},'findings':[],'limits':{},'warnings':[]}


def test_html_evidence_is_inert_and_assets_bundled():
    text=html_text(sample_report())
    assert '<script>alert(1)</script>' not in text
    assert '&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;' in text
    assert "connect-src &#x27;none&#x27;" in text
    assert text.count('<script>')==1
    assert '<script src=' not in text
    assert json.loads(json_text(sample_report()))['static']['strings'][0]['text'].endswith('\x1b[31m')


def test_schema_and_no_overwrite(tmp_path):
    report=sample_report();export(report,tmp_path)
    original=(tmp_path/'report.json').read_bytes()
    with pytest.raises(FileExistsError):export(report,tmp_path)
    assert (tmp_path/'report.json').read_bytes()==original
    report['schema_version']='99'
    with pytest.raises(ValueError):validate_report(report)


def test_oversized_reports_fail_before_commit(tmp_path,monkeypatch):
    from binary_workbench import reports
    monkeypatch.setattr(reports,'JSON_CAP',100)
    with pytest.raises(ValueError):export(sample_report(),tmp_path)
    assert not list(tmp_path.iterdir())
