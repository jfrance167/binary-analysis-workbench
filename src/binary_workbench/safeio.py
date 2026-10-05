"""Guarded immutable collection and private per-run storage on local Windows disks."""
import ctypes as C
import hashlib
import msvcrt
import os
import uuid
from contextlib import contextmanager
from pathlib import Path
from ctypes import wintypes as W
from . import winapi as api

MAX_INPUT = 64 * 1024**2


def local_path(path):
    """Reject reparse points and nonlocal/device/alternate-stream paths."""
    path = Path(os.path.abspath(path))
    text = str(path)
    if not path.drive or text.startswith('\\\\') or ':' in text[2:] or '\x00' in text:
        raise ValueError('Only regular local drive paths are accepted')
    for part in [path, *path.parents]:
        if part.exists() or part.is_symlink():
            attributes = api.attributes(str(part))
            if attributes == 0xFFFFFFFF:
                raise OSError('Path attributes unavailable')
            if attributes & 0x400:
                raise ValueError('Reparse-point paths are rejected')
    # Windows packaged applications can redirect AppData without a reparse point.
    # Canonicalize only after rejecting links, then validate the physical path too.
    canonical = path.resolve()
    if str(canonical).startswith('\\\\') or ':' in str(canonical)[2:]:
        raise ValueError('Nonlocal resolved path rejected')
    for part in [canonical, *canonical.parents]:
        if part.exists() and api.attributes(str(part)) & 0x400:
            raise ValueError('Resolved reparse-point path rejected')
    return canonical


def protect_directory(path, *, create=False):
    """Set a protected DACL for the current token's SID and SYSTEM only."""
    advapi = C.WinDLL('advapi32', use_last_error=True)
    open_token = advapi.OpenProcessToken
    open_token.argtypes,open_token.restype = [W.HANDLE,W.DWORD,C.POINTER(W.HANDLE)],W.BOOL
    token_info = advapi.GetTokenInformation
    token_info.argtypes,token_info.restype = [W.HANDLE,C.c_int,W.LPVOID,W.DWORD,C.POINTER(W.DWORD)],W.BOOL
    sid_string = advapi.ConvertSidToStringSidW
    sid_string.argtypes,sid_string.restype = [W.LPVOID,C.POINTER(W.LPWSTR)],W.BOOL
    free = api.bind('LocalFree', W.LPVOID, W.LPVOID)
    token = W.HANDLE()
    api.checked(open_token(api.bind('GetCurrentProcess',W.HANDLE)(),0x8,C.byref(token)))
    sid_pointer = W.LPWSTR()
    try:
        needed=W.DWORD()
        token_info(token,1,None,0,C.byref(needed))
        if not 0 < needed.value <= 65536:
            raise RuntimeError('Cannot establish token information size')
        buffer=C.create_string_buffer(needed.value)
        api.checked(token_info(token,1,buffer,len(buffer),C.byref(needed)))
        sid_address=C.cast(buffer,C.POINTER(W.LPVOID))[0]
        api.checked(sid_string(sid_address,C.byref(sid_pointer)))
        sid=sid_pointer.value
    finally:
        if sid_pointer:
            free(C.cast(sid_pointer,W.LPVOID))
        api.close(token)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes, convert.restype = [W.LPCWSTR, W.DWORD, C.POINTER(W.LPVOID), W.LPVOID], W.BOOL
    set_security = advapi.SetFileSecurityW
    set_security.argtypes, set_security.restype = [W.LPCWSTR, W.DWORD, W.LPVOID], W.BOOL
    descriptor = W.LPVOID()
    api.checked(convert(f'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})', 1, C.byref(descriptor), None))
    try:
        if create:
            # Install the DACL at creation; a world-writable custom parent must
            # not expose the run between mkdir and a later permission change.
            security=api.SECURITY_ATTRIBUTES(C.sizeof(api.SECURITY_ATTRIBUTES),descriptor,False)
            mkdir=api.bind('CreateDirectoryW',W.BOOL,W.LPCWSTR,C.POINTER(api.SECURITY_ATTRIBUTES))
            api.checked(mkdir(str(path),C.byref(security)))
        else:
            api.checked(set_security(str(path), 0x4 | 0x80000000, descriptor))
    finally:
        free(descriptor)


def new_run(root=None):
    root = local_path(root or Path(os.environ['LOCALAPPDATA']) / 'BinaryWorkbench/runs')
    for variable in ('OneDrive', 'OneDriveCommercial', 'OneDriveConsumer'):
        synced = os.environ.get(variable)
        if synced and root.is_relative_to(Path(synced).absolute()):
            raise ValueError('Runtime storage cannot be in OneDrive')
    if 'onedrive' in str(root).lower():
        raise ValueError('Runtime storage cannot be in OneDrive')
    existed = root.exists()
    if not existed:
        root.parent.mkdir(parents=True,exist_ok=True)
        protect_directory(root,create=True)
    run = root / uuid.uuid4().hex
    protect_directory(run,create=True)
    return run


@contextmanager
def locked_file(path):
    path = local_path(path)
    handle = api.checked(api.create_file(str(path), 0x80000000, 1, None, 3, 0x200000 | 0x8000000, None))
    try:
        if api.file_type(handle) != 1:
            raise ValueError('Nonregular input rejected')
        buffer = C.create_unicode_buffer(32768)
        count = api.final_path(handle, buffer, len(buffer), 0)
        if not count or count >= len(buffer):
            raise OSError('Final file path unavailable')
        final = buffer.value.removeprefix('\\\\?\\')
        if os.path.normcase(final) != os.path.normcase(str(path)):
            raise ValueError('File resolution changed during collection')
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        handle = None  # fd owns it from this point.
        with os.fdopen(fd, 'rb') as stream:
            if not os.path.isfile(path):
                raise ValueError('Nonregular input rejected')
            yield stream
    finally:
        if handle:
            api.close(handle)


@contextmanager
def collect(source, run, max_size=MAX_INPUT):
    """Hash exactly the copied bytes; hold deny-write/delete snapshot throughout analysis."""
    snapshot = local_path(run) / 'input.bin'
    digest, count = hashlib.sha256(), 0
    with locked_file(source) as original, snapshot.open('xb') as destination:
        initial = os.fstat(original.fileno())
        if initial.st_size > max_size:
            raise ValueError('Input exceeds size limit')
        while chunk := original.read(min(1024**2, max_size - count + 1)):
            count += len(chunk)
            if count > max_size:
                raise ValueError('Input exceeds size limit')
            destination.write(chunk)
            digest.update(chunk)
        after = os.fstat(original.fileno())
        if (initial.st_size, initial.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or count != initial.st_size:
            raise ValueError('Input changed during collection')
    with locked_file(snapshot) as stable:
        if hashlib.file_digest(stable, 'sha256').hexdigest() != digest.hexdigest():
            raise ValueError('Snapshot changed before locking')
        yield snapshot, {'sha256': digest.hexdigest(), 'size': count}


def write_new(path, content, cap):
    path = local_path(path)
    encoded = content.encode('utf-8')
    if len(encoded) > cap:
        raise ValueError('Report output limit exceeded')
    with path.open('xb') as stream:
        stream.write(encoded)
