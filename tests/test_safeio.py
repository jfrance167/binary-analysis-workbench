import os
from pathlib import Path
from binary_workbench.safeio import collect, locked_file, write_new, local_path,new_run


def test_collection_immutability(tmp_path):
    sample = tmp_path / 'unicode-学习.bin'
    sample.write_bytes(b'benign source')
    run = tmp_path / 'run'
    run.mkdir()
    import hashlib
    with collect(sample, run) as (snapshot, identity):
        assert identity['sha256'] == hashlib.sha256(b'benign source').hexdigest()
        assert snapshot.read_bytes() == b'benign source'
        try:
            snapshot.write_bytes(b'changed')
        except PermissionError:
            pass
        else:
            raise AssertionError('Snapshot was writable while locked')
    assert sample.read_bytes() == b'benign source'


def test_locked_source_and_limits(tmp_path):
    import pytest
    source = tmp_path / 'source'
    source.write_bytes(b'abcd')
    with locked_file(source):
        with pytest.raises(PermissionError):
            source.write_bytes(b'x')
    run = tmp_path / 'run'
    run.mkdir()
    with pytest.raises(ValueError):
        with collect(source, run, max_size=3):
            pass


def test_no_overwrite_or_alternate_stream(tmp_path):
    import pytest
    path = tmp_path / 'report.json'
    write_new(path, '{}', 100)
    with pytest.raises(FileExistsError):
        write_new(path, 'changed', 100)
    with pytest.raises(ValueError):
        local_path(str(path) + ':stream')
    assert path.read_text() == '{}'


def test_private_runtime_rejects_sync_and_links(tmp_path):
    import pytest
    with pytest.raises(ValueError):new_run(tmp_path/'OneDrive'/'runs')
    target=tmp_path/'target';target.mkdir()
    link=tmp_path/'link'
    try:
        link.symlink_to(target,target_is_directory=True)
    except OSError:
        pytest.skip('Windows symlink privilege unavailable')
    with pytest.raises(ValueError):local_path(link/'anything')


def test_redirected_appdata_is_canonical(tmp_path):
    import ctypes
    from binary_workbench import winapi as api
    sample=tmp_path/'canonical.bin';sample.write_bytes(b'harmless')
    canonical=local_path(sample)
    with locked_file(sample) as stream:
        import msvcrt
        buffer=ctypes.create_unicode_buffer(32768)
        api.final_path(msvcrt.get_osfhandle(stream.fileno()),buffer,len(buffer),0)
        assert os.path.normcase(str(canonical))==os.path.normcase(buffer.value.removeprefix('\\\\?\\'))
