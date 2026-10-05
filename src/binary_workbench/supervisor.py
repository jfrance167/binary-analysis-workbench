"""Launch trusted executables suspended and contain their process tree in a job."""
import ctypes as C
import os
# Only list2cmdline quoting; process creation uses mandatory suspended Job Object setup.
import subprocess  # nosec B404
import time
from dataclasses import dataclass
from pathlib import Path
from ctypes import wintypes as W
from . import winapi as api


@dataclass(frozen=True)
class WorkerResult:
    returncode: int
    status: str
    stdout: str
    stderr: str
    pid: int
    elapsed_seconds: float


def run_worker(argv, cwd, *, timeout=30, memory=1024**3, processes=2,
               diagnostic_cap=1024**2, watched=None, disk_cap=256*1024**2):
    """Run argv without a shell; mandatory job setup fails before any code runs.

    Diagnostic/temp disk limits are sampled, so brief overshoot is possible.
    Only the executable and explicit safe arguments chosen by the controller enter here.
    """
    executable = Path(argv[0])
    if not executable.is_absolute() or executable.suffix.lower() != '.exe':
        raise ValueError('Worker must use an explicit executable path')
    cwd = Path(cwd)
    output_path, error_path = cwd / 'worker.stdout', cwd / 'worker.stderr'
    handles = []
    job = api.checked(api.create_job(None, None))
    info = api.PROCESS_INFORMATION()
    started = False
    attribute_storage = None
    try:
        limits = api.EXTENDED_LIMIT()
        # KILL_ON_JOB_CLOSE | JOB_MEMORY | ACTIVE_PROCESS. No breakaway permission.
        limits.BasicLimitInformation.LimitFlags = 0x2000 | 0x200 | 0x8
        limits.BasicLimitInformation.ActiveProcessLimit = processes
        limits.JobMemoryLimit = memory
        api.checked(api.set_job(job, 9, C.byref(limits), C.sizeof(limits)))
        security = api.SECURITY_ATTRIBUTES(C.sizeof(api.SECURITY_ATTRIBUTES), None, True)
        for path in (output_path, error_path):
            handles.append(api.checked(api.create_file(str(path), 0x40000000, 1,
                                                       C.byref(security), 1, 0x80, None)))
        stdin = api.checked(api.create_file('NUL', 0x80000000, 3, C.byref(security), 3, 0, None))
        handles.append(stdin)
        startup = api.STARTUPINFOEX()
        startup.StartupInfo.cb, startup.StartupInfo.dwFlags = C.sizeof(startup), 0x100
        startup.StartupInfo.hStdInput, startup.StartupInfo.hStdOutput, startup.StartupInfo.hStdError = stdin, handles[0], handles[1]
        attribute_size = api.SIZE_T()
        api.initialize_attributes(None, 1, 0, C.byref(attribute_size))
        attribute_storage = C.create_string_buffer(attribute_size.value)
        api.checked(api.initialize_attributes(attribute_storage, 1, 0, C.byref(attribute_size)))
        startup.lpAttributeList = C.cast(attribute_storage, W.LPVOID)
        inherited = (W.HANDLE * len(handles))(*handles)
        api.checked(api.update_attributes(attribute_storage, 0, 0x20002, inherited, C.sizeof(inherited), None, None))
        # Environment is deliberately minimal; no inherited JAVA_TOOL_OPTIONS/PYTHONPATH.
        environment = {k: os.environ[k] for k in ('SystemRoot', 'WINDIR') if k in os.environ}
        environment.update({'TEMP': str(cwd), 'TMP': str(cwd), 'USERPROFILE': str(cwd),
                            'PYTHONIOENCODING': 'utf-8', 'PYTHONUTF8': '1'})
        block = C.create_unicode_buffer('\0'.join(f'{k}={v}' for k, v in sorted(environment.items())) + '\0\0')
        command = C.create_unicode_buffer(subprocess.list2cmdline([str(x) for x in argv]))
        api.checked(api.create_process(str(executable), command, None, None, True,
                                      0x4 | 0x400 | 0x08000000 | 0x80000, block, str(cwd),
                                      C.cast(C.byref(startup), C.POINTER(api.STARTUPINFO)), C.byref(info)))
        started = True
        api.checked(api.assign_job(job, info.hProcess))
        if api.resume(info.hThread) == 0xFFFFFFFF:
            api.checked(False)
        start = time.monotonic()
        status = 'complete'
        next_disk_check = start
        while True:
            wait_result = api.wait(info.hProcess, 25)
            if wait_result == 0:
                break
            if wait_result != 258:
                raise RuntimeError('Worker wait failed')
            if time.monotonic() - start >= timeout:
                status = 'timeout'
                break
            if any(p.stat().st_size > diagnostic_cap for p in (output_path, error_path)):
                status = 'output_limit'
                break
            if watched and any(p.exists() and p.stat().st_size > cap for p, cap in watched):
                status = 'output_limit'
                break
            if time.monotonic() >= next_disk_check:
                # Trusted workers must not create links. Quota is sampled, not an OS disk boundary.
                size = 0
                for directory, subdirs, files in os.walk(cwd, followlinks=False):
                    subdirs[:] = [name for name in subdirs if not ((Path(directory)/name).is_symlink() or (Path(directory)/name).is_junction())]
                    for name in files:
                        item = Path(directory)/name
                        if not item.is_symlink():
                            try:
                                size += item.stat().st_size
                            except FileNotFoundError:
                                pass
                if size > disk_cap:
                    status = 'output_limit'; break
                next_disk_check = time.monotonic()+0.25
        # Kill descendants even when the parent exits normally; no pipe EOF dependency.
        api.checked(api.terminate_job(job, 124))
        api.wait(info.hProcess, 5000)
        cleanup_deadline = time.monotonic() + 5
        while True:
            accounting = api.BASIC_ACCOUNTING()
            api.checked(api.query_job(job, 1, C.byref(accounting), C.sizeof(accounting), None))
            if not accounting.ActiveProcesses:
                break
            if time.monotonic() >= cleanup_deadline:
                raise RuntimeError('Worker tree cleanup could not be verified')
            time.sleep(0.025)
        code = W.DWORD()
        api.checked(api.exit_code(info.hProcess, C.byref(code)))
        for handle in handles:
            api.close(handle)
        handles.clear()
        with output_path.open('rb') as stream:
            stdout = stream.read(diagnostic_cap).decode('utf-8', 'replace')
        with error_path.open('rb') as stream:
            stderr = stream.read(diagnostic_cap).decode('utf-8', 'replace')
        if status == 'complete' and (output_path.stat().st_size > diagnostic_cap or error_path.stat().st_size > diagnostic_cap):
            status = 'output_limit'
        if status == 'complete' and code.value:
            status = 'failed'
        if watched and any(p.exists() and p.stat().st_size > cap for p, cap in watched):
            status = 'output_limit'
        return WorkerResult(code.value, status, stdout, stderr, info.dwProcessId, time.monotonic() - start)
    finally:
        if started:
            # Also handles failures assigning the suspended process to its job.
            terminate = api.bind('TerminateProcess', W.BOOL, W.HANDLE, W.UINT)
            terminate(info.hProcess, 124)
            api.close(info.hThread)
            api.close(info.hProcess)
        for handle in handles:
            api.close(handle)
        if attribute_storage is not None:
            api.delete_attributes(attribute_storage)
        api.close(job)
