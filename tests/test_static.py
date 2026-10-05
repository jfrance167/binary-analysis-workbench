import hashlib
from hypothesis import given, settings, strategies as st
from binary_workbench.static import entropy,extract_strings,analyze,mapped_offset,AddressMap


def test_entropy_known_values():
    assert entropy(b'') is None
    assert entropy(b'aaaa') == 0
    assert entropy(bytes(range(256))) == 8


def test_strings_offsets_and_indicators():
    # Two NULs prevent the final ASCII byte + NUL joining the wide run.
    data=b'\x00HELLO https://example.invalid\x00\x00'+ 'WIDE_TEST'.encode('utf-16le')+b'\x00\x00'
    result=analyze(data)
    assert result['sha256']==hashlib.sha256(data).hexdigest()
    assert any(s['encoding']=='utf-16le' and s['text']=='WIDE_TEST' for s in result['strings'])
    assert any(i['kind']=='url' and i['value']=='https://example.invalid' for i in result['indicators'])


@settings(max_examples=100,deadline=None)
@given(st.binary(max_size=4096))
def test_malformed_data_bounded(data):
    result=analyze(data)
    assert result['status'] in ('unsupported','partial','complete')
    assert all(0<=s['file_offset']<len(data) for s in result['strings'])


def test_ambiguous_and_zero_fill_mapping():
    region={'va':0x1000,'offset':0,'file_size':4,'memory_size':8,'valid':True}
    assert mapped_offset([region],0x1003,4)==3
    assert mapped_offset([region],0x1004,4) is None
    assert mapped_offset([region,region],0x1001,4) is None
    mapper=AddressMap([region],4)
    assert mapper.offset(0x1003)==3 and mapper.offset(0x1004) is None
    overlapping={**region,'va':0x1002,'offset':1,'file_size':2}
    mapper=AddressMap([region,overlapping],4)
    assert mapper.offset(0x1001)==1 and mapper.offset(0x1002) is None


def test_unicode_bmp_wide_strings_and_ip_candidates():
    content='中文字符串'.encode('utf-16le')
    strings,_=extract_strings(b'\0\0'+content+b'\0\0')
    assert any(x['text']=='中文字符串' and x['file_offset']==2 for x in strings)
    odd,_=extract_strings(b'\0\0\0'+content+b'\0\0')
    assert any(x['text']=='中文字符串' and x['file_offset']==3 for x in odd)
    result=analyze(b'192.0.2.1 2001:db8::1 https://example.invalid')
    assert {'192.0.2.1','2001:db8::1'} <= {x['value'] for x in result['indicators'] if x['kind']=='ip'}


def test_string_limits_explicit():
    strings,limited=extract_strings(b'ABCD\0'*20001)
    assert limited and len(strings)==20000
    strings,_=extract_strings(b'A'*5000)
    assert strings[0]['truncated'] and len(strings[0]['text'])==4096
