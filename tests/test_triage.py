from binary_workbench.static import analyze
from binary_workbench.triage import findings
from binary_workbench.worker import signatures


def test_local_signatures_offsets_and_disabled_includes():
    result=signatures(b'xxx marker xxx','rule demo { strings: $a = "marker" condition: $a }')
    assert result['matches']==[{'rule':'demo','pattern':'$a','file_offset':4,'length':6}]
    assert not signatures(b'negative','rule demo { strings: $a = "marker" condition: $a }')['matches']
    import pytest
    with pytest.raises(Exception):
        signatures(b'negative','include "not-allowed.yar"')
    capped=signatures(b'X'*200,'rule many { strings: $a = "X" condition: $a }')
    assert capped['pattern_cap_reached'] and capped['truncated'] and len(capped['matches'])==100


def test_explained_positive_and_benign_negative():
    static=analyze(b'hello harmless')
    assert not findings(static,{'matches':[]})
    static['sections']=[{'id':'section:0','permissions':'rwx','offset':0,'file_size':2048,
                        'valid':True,'entropy':7.8}]
    result=findings(static,{'matches':[]})
    assert {x['kind'] for x in result}=={'writable_executable','high_entropy'}
    assert all(x['uncertainty'] and x['locations'] and x['evidence_ids'] for x in result)
    assert result==findings(static,{'matches':[]})


def test_import_combination_requires_all_three_classes():
    static=analyze(b'harmless')
    static['imports']=[{'name':name,'id':f'import:{i}','file_offset':i,'va':hex(0x1000+i)} for i,name in enumerate(
        ('VirtualAllocEx','WriteProcessMemory','CreateRemoteThread'))]
    result=findings(static,{'matches':[]})
    assert result[0]['kind']=='remote_process_api_combination' and 'Debuggers' in result[0]['uncertainty']
    static['imports'].pop()
    assert not findings(static,{'matches':[]})
