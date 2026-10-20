import ctypes
import sys
from pathlib import Path
from binary_workbench.supervisor import run_worker


def test_complete_and_nonzero(tmp_path):
    result = run_worker([sys.executable, '-I', '-c', "print('benign worker')"], tmp_path)
    assert result.status == 'complete' and result.stdout.strip() == 'benign worker'
    other = tmp_path / 'other'
    other.mkdir()
    result = run_worker([sys.executable, '-I', '-c', 'raise SystemExit(7)'], other)
    assert result.status == 'failed' and result.returncode == 7


def test_timeout_cleans_descendant(tmp_path):
    script = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(60)']);print(p.pid,flush=True);time.sleep(60)"
    # Windows venv launchers spawn base Python: two launcher/interpreter pairs.
    result = run_worker([sys.executable, '-I', '-c', script], tmp_path, timeout=1, processes=4)
    assert result.status == 'timeout' and result.elapsed_seconds < 8
    child = int(result.stdout.strip())
    from binary_workbench import winapi as api
    open_process = api.bind('OpenProcess', ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
    handle = open_process(0x100000, False, child)
    if handle:
        try:
            assert api.wait(handle, 3000) == 0
        finally:
            api.close(handle)


def test_output_limit(tmp_path):
    result = run_worker([sys.executable, '-I', '-c', "import time;print('x'*200000,flush=True);time.sleep(5)"],
                        tmp_path, diagnostic_cap=4096)
    assert result.status == 'output_limit' and len(result.stdout) <= 4096


def test_reject_shell(tmp_path):
    try:
        run_worker(['untrusted.bat'], tmp_path)
    except ValueError:
        return
    raise AssertionError('Batch launcher was accepted')


def test_memory_and_process_limits(tmp_path):
    memory_dir=tmp_path/'memory';memory_dir.mkdir()
    memory_script="try:\n x=bytearray(256*1024**2)\n print('unexpected')\nexcept MemoryError:\n print('limited')"
    result=run_worker([sys.executable,'-I','-c',memory_script],memory_dir,memory=96*1024**2)
    assert 'unexpected' not in result.stdout and ('limited' in result.stdout or result.status=='failed')
    process_dir=tmp_path/'process';process_dir.mkdir()
    script="import subprocess,sys\ntry:\n subprocess.run([sys.executable,'-I','-c',\"print('unexpected')\"],check=True)\nexcept (OSError,subprocess.CalledProcessError):\n print('limited')"
    # Use the base interpreter so a venv launcher cannot consume a process slot.
    # With one slot, the worker runs but its child must be rejected by the job.
    interpreter = str(Path(sys._base_executable).resolve())
    result=run_worker([interpreter,'-I','-c',script],process_dir,processes=1)
    assert 'unexpected' not in result.stdout and 'limited' in result.stdout


def test_mandatory_job_failure_prevents_execution(tmp_path,monkeypatch):
    from binary_workbench import winapi as api
    import pytest
    monkeypatch.setattr(api,'set_job',lambda *args:False)
    with pytest.raises(OSError):
        run_worker([sys.executable,'-I','-c',"print('must not run')"],tmp_path)
    assert not (tmp_path/'worker.stdout').exists()


def test_watched_output_and_disk_limit(tmp_path):
    output=tmp_path/'large.bin'
    script="from pathlib import Path;import time;Path('large.bin').write_bytes(b'x'*100000);time.sleep(3)"
    result=run_worker([sys.executable,'-I','-c',script],tmp_path,watched=[(output,1000)])
    assert result.status=='output_limit'
    other=tmp_path/'disk';other.mkdir()
    result=run_worker([sys.executable,'-I','-c',script],other,disk_cap=1000)
    assert result.status=='output_limit'
