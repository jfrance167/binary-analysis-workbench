"""Optional benign-format integration expectations, independent of report generation."""
import hashlib
import os
import struct
from pathlib import Path
import pytest
from hypothesis import given,settings,strategies as st
from binary_workbench.static import analyze


@pytest.fixture
def variants():
    path=os.environ.get('WB_VARIANTS')
    if not path:
        pytest.skip('Set WB_VARIANTS to the source-built benign variants directory')
    import json
    root=Path(path)
    for record in json.loads((root/'manifest.json').read_text()):
        assert hashlib.sha256((root/record['name']).read_bytes()).hexdigest()==record['sha256']
    return root


def test_imports_resources_and_dynamic_dependency(variants):
    pe=analyze((variants/'pe-import-resource.exe').read_bytes())
    assert pe['status']=='complete'
    assert any(x['name']=='GetCurrentProcessId' and x['library'].lower()=='kernel32.dll' for x in pe['imports'])
    assert pe['resources'] and all(x['valid'] for x in pe['resources'])
    elf=analyze((variants/'elf-dynamic.so').read_bytes())
    assert elf['status']=='complete' and 'libfixture.so' in elf['dependencies']
    assert any(x['name']=='fixture_sink' for x in elf['imports'])


def test_stripped_pie_and_sectionless(variants):
    stripped=analyze((variants/'elf-stripped.elf').read_bytes())
    assert stripped['status']=='complete' and not stripped['symbols']
    pie=analyze((variants/'elf-pie.elf').read_bytes())
    assert pie['headers']['e_type']=='ET_DYN'
    source=bytearray((variants/'elf-stripped.elf').read_bytes())
    struct.pack_into('<Q',source,40,0)  # ELF64 e_shoff.
    struct.pack_into('<H',source,60,0);struct.pack_into('<H',source,62,0)
    sectionless=analyze(source)
    assert sectionless['status']=='complete' and not sectionless['sections'] and sectionless['segments']


def test_certificates_overlay_managed_unsupported_and_truncation(variants):
    original=(variants/'pe-import-resource.exe').read_bytes()
    pe_offset=struct.unpack_from('<I',original,0x3c)[0]
    directories=pe_offset+24+112  # Independent PE32+ layout expectation.
    certificate=bytearray(original)
    struct.pack_into('<II',certificate,directories+4*8,len(certificate),8)
    certificate.extend(struct.pack('<IHH',8,0x200,2))
    result=analyze(certificate)
    assert result['certificates'][0]['file_offset']==len(original)
    assert result['certificates'][0]['valid'] and result['overlay']
    assert result['certificates'][0]['verification']=='not_performed'
    unsupported=bytearray(original);struct.pack_into('<H',unsupported,pe_offset+4,0xaa64)
    assert analyze(unsupported)['status']=='unsupported'
    oversized=bytearray(original)
    struct.pack_into('<II',oversized,pe_offset+4+8,4,50001)
    huge_symbols=analyze(oversized)
    assert huge_symbols['status']=='partial' and huge_symbols['symbol_table']['status']=='invalid_or_limit'
    overflow=bytearray(original);struct.pack_into('<Q',overflow,pe_offset+24+24,2**64-1)
    assert analyze(overflow)['status']=='partial'
    assert all(not s['valid'] for s in analyze(overflow)['sections'])
    managed=bytearray(original);struct.pack_into('<II',managed,directories+14*8,0x2000,72)
    assert analyze(managed)['managed']
    for length in (1,2,64,256):
        assert analyze(original[:length])['status'] in ('partial','unsupported')


@settings(max_examples=60,deadline=None,derandomize=True)
@given(st.sampled_from((b'MZ',b'\x7fELF')),st.binary(max_size=4096))
def test_malformed_format_headers(prefix,data):
    result=analyze(prefix+data)
    assert result['status'] in ('complete','partial','unsupported')
    assert result['size']==len(prefix)+len(data)
