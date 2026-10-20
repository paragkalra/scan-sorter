"""A small seccomp filter for sandboxed parsers: no metadata changes.

Landlock stops a parser from writing, truncating, creating or deleting
files, but not from changing permissions, ownership, timestamps or extended
attributes of files it can reach. This filter makes those system calls fail
with EPERM. Everything else is allowed; the filter only removes abilities a
parser never needs.
"""

from __future__ import annotations

import ctypes
import errno
import platform
import struct

_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2

_BPF_LD_W_ABS = 0x20
_BPF_JEQ_K = 0x15
_BPF_JGE_K = 0x35
_BPF_RET_K = 0x06
_RET_ALLOW = 0x7FFF0000
_RET_ERRNO = 0x00050000
_RET_KILL_PROCESS = 0x80000000

_OFF_NR = 0
_OFF_ARCH = 4

_X32_SYSCALL_BIT = 0x40000000

# Per architecture: audit arch, and the syscalls to deny by name.
_ARCHES = {
    "x86_64": (
        0xC000003E,
        {
            "chmod": 90,
            "fchmod": 91,
            "fchmodat": 268,
            "fchmodat2": 452,
            "chown": 92,
            "fchown": 93,
            "lchown": 94,
            "fchownat": 260,
            "setxattr": 188,
            "lsetxattr": 189,
            "fsetxattr": 190,
            "removexattr": 197,
            "lremovexattr": 198,
            "fremovexattr": 199,
            "setxattrat": 463,
            "removexattrat": 466,
            "utime": 132,
            "utimes": 235,
            "futimesat": 261,
            "utimensat": 280,
        },
    ),
    "aarch64": (
        0xC00000B7,
        {
            "fchmod": 52,
            "fchmodat": 53,
            "fchmodat2": 452,
            "fchownat": 54,
            "fchown": 55,
            "setxattr": 5,
            "lsetxattr": 6,
            "fsetxattr": 7,
            "removexattr": 14,
            "lremovexattr": 15,
            "fremovexattr": 16,
            "setxattrat": 463,
            "removexattrat": 466,
            "utimensat": 88,
        },
    ),
}


class SeccompUnavailable(OSError):
    pass


def supported() -> bool:
    return platform.system() == "Linux" and platform.machine() in _ARCHES


def _insn(code: int, jt: int, jf: int, k: int) -> bytes:
    return struct.pack("=HBBI", code, jt, jf, k)


def program() -> bytes:
    arch, by_name = _ARCHES[platform.machine()]
    denied = sorted(by_name.values())
    insns = [
        _insn(_BPF_LD_W_ABS, 0, 0, _OFF_ARCH),
        _insn(_BPF_JEQ_K, 1, 0, arch),
        _insn(_BPF_RET_K, 0, 0, _RET_KILL_PROCESS),  # foreign ABI: no bypass
        _insn(_BPF_LD_W_ABS, 0, 0, _OFF_NR),
    ]
    if platform.machine() == "x86_64":
        # x32 system calls carry this bit: refuse them all.
        insns.append(_insn(_BPF_JGE_K, 0, 1, _X32_SYSCALL_BIT))
        insns.append(_insn(_BPF_RET_K, 0, 0, _RET_ERRNO | errno.EPERM))
    for i, nr in enumerate(denied):
        # Jump to the deny return at the end when equal.
        to_deny = len(denied) - i
        insns.append(_insn(_BPF_JEQ_K, to_deny, 0, nr))
    insns.append(_insn(_BPF_RET_K, 0, 0, _RET_ALLOW))
    insns.append(_insn(_BPF_RET_K, 0, 0, _RET_ERRNO | errno.EPERM))
    return b"".join(insns)


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def deny_metadata_changes() -> None:
    """Install the filter on the calling process (inherited by its children)."""
    if not supported():
        raise SeccompUnavailable(errno.ENOSYS, "seccomp filter not supported here")
    libc = ctypes.CDLL(None, use_errno=True)
    code = program()
    buf = ctypes.create_string_buffer(code, len(code))
    prog = _SockFprog(len(code) // 8, ctypes.addressof(buf))
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise SeccompUnavailable(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0) != 0:
        raise SeccompUnavailable(ctypes.get_errno(), "seccomp filter refused")
