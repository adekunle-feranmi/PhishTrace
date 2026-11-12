"""Windows job-object helper: make an external tool and its children killable.

``os.killpg``/``setsid`` do not exist on Windows, and ``TerminateProcess`` only
stops the direct child -- a ``.cmd`` shim or a Python tool that shells out
(theharvester, spiderfoot) would leave its grandchildren running.  A job object
created with ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` solves both problems:

* the whole tree dies when the job is terminated, and
* the tree dies if this process disappears without cleaning up.

The module is import-safe on POSIX; :func:`assign` simply returns ``None`` and
the runner falls back to process groups.
"""

from __future__ import annotations

import ctypes
import os

IS_WINDOWS = os.name == "nt"

_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_PROCESS_TERMINATE = 0x0001
_PROCESS_SET_QUOTA = 0x0100
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    ]


class _ExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class Job:
    """Handle to a kill-on-close job object holding one tool's process tree."""

    def __init__(self, handle: int, kernel32) -> None:
        self._handle = handle
        self._api = kernel32

    @property
    def active(self) -> bool:
        return bool(self._handle)

    def terminate(self) -> bool:
        """Kill every process in the job.  Returns ``True`` when the call ran."""
        if not self._handle:
            return False
        return bool(self._api.TerminateJobObject(self._handle, 1))

    def close(self) -> None:
        if self._handle:
            self._api.CloseHandle(self._handle)
            self._handle = None

    def __del__(self) -> None:  # pragma: no cover - interpreter shutdown noise
        try:
            self.close()
        except Exception:
            pass


def assign(pid: int) -> Job | None:
    """Create a job, put ``pid`` in it, and return it.

    ``None`` means the platform is POSIX or the assignment failed (for example
    when the caller is already inside a non-nestable job); callers must then
    fall back to ``Process.terminate``/``kill``.
    """
    if not IS_WINDOWS:
        return None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except (AttributeError, OSError):  # pragma: no cover - non-Windows ctypes
        return None

    kernel32.CreateJobObjectW.restype = ctypes.c_void_p
    kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p)
    kernel32.SetInformationJobObject.argtypes = (
        ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
    kernel32.AssignProcessToJobObject.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    kernel32.TerminateJobObject.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.OpenProcess.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel32.CloseHandle.restype = ctypes.c_int

    handle = kernel32.CreateJobObjectW(None, None)
    if not handle:
        return None
    try:
        limits = _ExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            handle, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits), ctypes.sizeof(limits),
        ):
            kernel32.CloseHandle(handle)
            return None
        rights = _PROCESS_SET_QUOTA | _PROCESS_TERMINATE | _PROCESS_QUERY_LIMITED_INFORMATION
        proc_handle = kernel32.OpenProcess(rights, 0, int(pid))
        if not proc_handle:
            kernel32.CloseHandle(handle)
            return None
        assigned = kernel32.AssignProcessToJobObject(handle, proc_handle)
        kernel32.CloseHandle(proc_handle)
        if not assigned:
            kernel32.CloseHandle(handle)
            return None
        return Job(handle, kernel32)
    except OSError:  # pragma: no cover - defensive
        kernel32.CloseHandle(handle)
        return None
