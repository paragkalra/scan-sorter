"""A small seccomp filter for sandboxed parsers.

Landlock stops a parser from writing, truncating, creating or deleting
files, but not from changing permissions, ownership, timestamps or extended
attributes of files it can reach, and (before Landlock ABI 6) not from
signalling other processes of the same user. This filter makes those system
calls, and io_uring (which can do the same asynchronously), fail with EPERM;
signals are allowed only to the parser itself or its own process group.
Everything else is allowed: the filter only removes abilities a parser never
needs.
"""

from __future__ import annotations

import ctypes
import errno
import os
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
            "tkill": 200,  # thread id cannot be checked against our own
            "pidfd_send_signal": 424,
            # io_uring can perform the calls above (e.g. IORING_OP_SETXATTR)
            # without entering them; parsers never need it.
            "io_uring_setup": 425,
            "io_uring_enter": 426,
            "io_uring_register": 427,
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
            "tkill": 130,
            "pidfd_send_signal": 424,
            # io_uring can perform the calls above (e.g. IORING_OP_SETXATTR)
            # without entering them; parsers never need it.
            "io_uring_setup": 425,
            "io_uring_enter": 426,
            "io_uring_register": 427,
        },
    ),
}


# Signal syscalls whose first argument names the target process (or, for
# kill, a negated process group): allowed only for the parser itself.
_SIGNAL_TARGETED = {
    "x86_64": {"kill": 62, "tgkill": 234, "rt_sigqueueinfo": 129, "rt_tgsigqueueinfo": 297},
    "aarch64": {"kill": 129, "tgkill": 131, "rt_sigqueueinfo": 138, "rt_tgsigqueueinfo": 240},
}
_OFF_ARG0_LOW = 16  # seccomp_data.args[0], low 32 bits (little endian)


class SeccompUnavailable(OSError):
    pass


def supported() -> bool:
    return platform.system() == "Linux" and platform.machine() in _ARCHES


def program(pid: int) -> bytes:
    """BPF for a parser whose own PID (and process group, a new session) is pid."""
    machine = platform.machine()
    arch, by_name = _ARCHES[machine]
    signals = _SIGNAL_TARGETED[machine]
    me, my_group = pid & 0xFFFFFFFF, (-pid) & 0xFFFFFFFF
    # (code, jump-if-true label, jump-if-false label, k); labels resolve below.
    prog: list[tuple[int, str | int, str | int, int]] = [
        (_BPF_LD_W_ABS, 0, 0, _OFF_ARCH),
        (_BPF_JEQ_K, 0, "kill", arch),  # foreign ABI: no bypass
        (_BPF_LD_W_ABS, 0, 0, _OFF_NR),
    ]
    if machine == "x86_64":
        prog.append((_BPF_JGE_K, "deny", 0, _X32_SYSCALL_BIT))  # x32 syscalls
    for nr in sorted(by_name.values()):
        prog.append((_BPF_JEQ_K, "deny", 0, nr))
    prog.append((_BPF_JEQ_K, "check_kill", 0, signals["kill"]))
    for name in ("tgkill", "rt_sigqueueinfo", "rt_tgsigqueueinfo"):
        prog.append((_BPF_JEQ_K, "check_self", 0, signals[name]))
    # Classic BPF only jumps forward: the shared returns come last.
    prog.append((_BPF_RET_K, 0, 0, _RET_ALLOW))  # every other syscall
    labels = {"check_kill": len(prog)}  # kill(pid): self, own group (0 or -pid)
    prog += [
        (_BPF_LD_W_ABS, 0, 0, _OFF_ARG0_LOW),
        (_BPF_JEQ_K, "allow", 0, me),
        (_BPF_JEQ_K, "allow", 0, 0),
        (_BPF_JEQ_K, "allow", "deny", my_group),
    ]
    labels["check_self"] = len(prog)  # tgkill & co: thread group must be us
    prog += [
        (_BPF_LD_W_ABS, 0, 0, _OFF_ARG0_LOW),
        (_BPF_JEQ_K, "allow", "deny", me),
    ]
    labels["allow"] = len(prog)
    prog.append((_BPF_RET_K, 0, 0, _RET_ALLOW))
    labels["deny"] = len(prog)
    prog.append((_BPF_RET_K, 0, 0, _RET_ERRNO | errno.EPERM))
    labels["kill"] = len(prog)
    prog.append((_BPF_RET_K, 0, 0, _RET_KILL_PROCESS))
    out = []
    for i, (code, jt, jf, k) in enumerate(prog):
        jt = labels[jt] - i - 1 if isinstance(jt, str) else jt
        jf = labels[jf] - i - 1 if isinstance(jf, str) else jf
        if not (0 <= jt <= 255 and 0 <= jf <= 255):
            raise ValueError("seccomp program jump out of range")
        out.append(struct.pack("=HBBI", code, jt, jf, k))
    return b"".join(out)


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def deny_metadata_changes() -> None:
    """Install the filter on the calling process (inherited by its children).

    The caller must lead its own session (start_new_session) so its process
    group ID equals its PID.
    """
    if not supported():
        raise SeccompUnavailable(errno.ENOSYS, "seccomp filter not supported here")
    libc = ctypes.CDLL(None, use_errno=True)
    code = program(os.getpid())
    buf = ctypes.create_string_buffer(code, len(code))
    prog = _SockFprog(len(code) // 8, ctypes.addressof(buf))
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise SeccompUnavailable(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0) != 0:
        raise SeccompUnavailable(ctypes.get_errno(), "seccomp filter refused")
