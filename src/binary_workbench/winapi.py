"""Small typed Windows API surface for collection and worker availability controls.

Jobs limit resources and process lifetime. They are not a malware security boundary.
"""
import ctypes as C
import os
from ctypes import wintypes as W

if os.name != 'nt' or C.sizeof(C.c_void_p)!=8:
    raise RuntimeError('This release requires Windows x64')

K = C.WinDLL('kernel32', use_last_error=True)
SIZE_T = C.c_size_t


class SECURITY_ATTRIBUTES(C.Structure):
    _fields_ = [('nLength', W.DWORD), ('lpSecurityDescriptor', W.LPVOID), ('bInheritHandle', W.BOOL)]


class STARTUPINFO(C.Structure):
    _fields_ = [('cb', W.DWORD), ('lpReserved', W.LPWSTR), ('lpDesktop', W.LPWSTR),
                ('lpTitle', W.LPWSTR), ('dwX', W.DWORD), ('dwY', W.DWORD),
                ('dwXSize', W.DWORD), ('dwYSize', W.DWORD), ('dwXCountChars', W.DWORD),
                ('dwYCountChars', W.DWORD), ('dwFillAttribute', W.DWORD),
                ('dwFlags', W.DWORD), ('wShowWindow', W.WORD), ('cbReserved2', W.WORD),
                ('lpReserved2', C.POINTER(C.c_byte)), ('hStdInput', W.HANDLE),
                ('hStdOutput', W.HANDLE), ('hStdError', W.HANDLE)]


class PROCESS_INFORMATION(C.Structure):
    _fields_ = [('hProcess', W.HANDLE), ('hThread', W.HANDLE),
                ('dwProcessId', W.DWORD), ('dwThreadId', W.DWORD)]


class STARTUPINFOEX(C.Structure):
    _fields_ = [('StartupInfo', STARTUPINFO), ('lpAttributeList', W.LPVOID)]


class BASIC_ACCOUNTING(C.Structure):
    _fields_ = [(n, C.c_int64) for n in ('TotalUserTime', 'TotalKernelTime', 'ThisPeriodTotalUserTime', 'ThisPeriodTotalKernelTime')] + [
        (n, W.DWORD) for n in ('TotalPageFaultCount', 'TotalProcesses', 'ActiveProcesses', 'TotalTerminatedProcesses')]


class BASIC_LIMIT(C.Structure):
    _fields_ = [('PerProcessUserTimeLimit', C.c_int64), ('PerJobUserTimeLimit', C.c_int64),
                ('LimitFlags', W.DWORD), ('MinimumWorkingSetSize', SIZE_T),
                ('MaximumWorkingSetSize', SIZE_T), ('ActiveProcessLimit', W.DWORD),
                ('Affinity', SIZE_T), ('PriorityClass', W.DWORD), ('SchedulingClass', W.DWORD)]


class IO_COUNTERS(C.Structure):
    _fields_ = [(n, C.c_uint64) for n in ['ReadOperationCount', 'WriteOperationCount',
                'OtherOperationCount', 'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount']]


class EXTENDED_LIMIT(C.Structure):
    _fields_ = [('BasicLimitInformation', BASIC_LIMIT), ('IoInfo', IO_COUNTERS),
                ('ProcessMemoryLimit', SIZE_T), ('JobMemoryLimit', SIZE_T),
                ('PeakProcessMemoryUsed', SIZE_T), ('PeakJobMemoryUsed', SIZE_T)]


def bind(name, restype, *args):
    function = getattr(K, name)
    function.restype, function.argtypes = restype, list(args)
    return function


create_file = bind('CreateFileW', W.HANDLE, W.LPCWSTR, W.DWORD, W.DWORD,
                   C.POINTER(SECURITY_ATTRIBUTES), W.DWORD, W.DWORD, W.HANDLE)
close = bind('CloseHandle', W.BOOL, W.HANDLE)
create_job = bind('CreateJobObjectW', W.HANDLE, W.LPVOID, W.LPCWSTR)
set_job = bind('SetInformationJobObject', W.BOOL, W.HANDLE, C.c_int, W.LPVOID, W.DWORD)
assign_job = bind('AssignProcessToJobObject', W.BOOL, W.HANDLE, W.HANDLE)
terminate_job = bind('TerminateJobObject', W.BOOL, W.HANDLE, W.UINT)
create_process = bind('CreateProcessW', W.BOOL, W.LPCWSTR, W.LPWSTR, W.LPVOID, W.LPVOID,
                      W.BOOL, W.DWORD, W.LPVOID, W.LPCWSTR,
                      C.POINTER(STARTUPINFO), C.POINTER(PROCESS_INFORMATION))
resume = bind('ResumeThread', W.DWORD, W.HANDLE)
wait = bind('WaitForSingleObject', W.DWORD, W.HANDLE, W.DWORD)
exit_code = bind('GetExitCodeProcess', W.BOOL, W.HANDLE, C.POINTER(W.DWORD))
final_path = bind('GetFinalPathNameByHandleW', W.DWORD, W.HANDLE, W.LPWSTR, W.DWORD, W.DWORD)
attributes = bind('GetFileAttributesW', W.DWORD, W.LPCWSTR)
file_type = bind('GetFileType', W.DWORD, W.HANDLE)
initialize_attributes = bind('InitializeProcThreadAttributeList', W.BOOL, W.LPVOID, W.DWORD, W.DWORD, C.POINTER(SIZE_T))
update_attributes = bind('UpdateProcThreadAttribute', W.BOOL, W.LPVOID, W.DWORD, SIZE_T, W.LPVOID, SIZE_T, W.LPVOID, W.LPVOID)
delete_attributes = bind('DeleteProcThreadAttributeList', None, W.LPVOID)
query_job = bind('QueryInformationJobObject', W.BOOL, W.HANDLE, C.c_int, W.LPVOID, W.DWORD, W.LPVOID)
INVALID = C.c_void_p(-1).value


def checked(value):
    if not value or value == INVALID:
        raise C.WinError(C.get_last_error())
    return value
