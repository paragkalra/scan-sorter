"""Landlock: drop the ability to change the filesystem or use the network.

Called in a sandboxed child before it execs a parser. The child keeps the
worker's user ID (no root needed), but after this it cannot write, truncate,
create, delete or rename anything, cannot make TCP connections, and cannot
signal processes outside its own sandbox. Reads are untouched, so the parser
can load its libraries and read the input it was handed.
"""

from __future__ import annotations

import ctypes
import os
import platform

# Syscall numbers are the same on x86_64 and aarch64 (generic table).
_SYS_CREATE_RULESET = 444
_SYS_RESTRICT_SELF = 446
_CREATE_RULESET_VERSION = 1 << 0
_PR_SET_NO_NEW_PRIVS = 38

_FS_WRITE_FILE = 1 << 1
_FS_REMOVE_DIR = 1 << 4
_FS_REMOVE_FILE = 1 << 5
_FS_MAKE_ALL = sum(1 << b for b in range(6, 13))  # char, dir, reg, sock, fifo, block, sym
_FS_REFER = 1 << 13  # ABI 2
_FS_TRUNCATE = 1 << 14  # ABI 3
_NET_BIND_TCP = 1 << 0  # ABI 4
_NET_CONNECT_TCP = 1 << 1
_SCOPE_ABSTRACT_UNIX_SOCKET = 1 << 0  # ABI 6
_SCOPE_SIGNAL = 1 << 1


class LandlockUnavailable(OSError):
    pass


class _RulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
        ("scoped", ctypes.c_uint64),
    ]


def _libc():
    return ctypes.CDLL(None, use_errno=True)


def abi_version() -> int:
    """Landlock ABI version, or 0 when unavailable."""
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "aarch64"):
        return 0
    v = _libc().syscall(_SYS_CREATE_RULESET, None, 0, _CREATE_RULESET_VERSION)
    return max(v, 0)


# ABI 3 is the first that can stop truncation (open with O_TRUNC); below it
# a parser could empty any file it can reach, so we refuse to rely on it.
MIN_ABI = 3


def deny_writes_and_network() -> None:
    """Restrict the calling process (and its future children) for good."""
    libc = _libc()
    abi = abi_version()
    if abi < MIN_ABI:
        raise LandlockUnavailable(0, f"Landlock ABI {abi} is too old (need {MIN_ABI})")
    fs = _FS_WRITE_FILE | _FS_REMOVE_DIR | _FS_REMOVE_FILE | _FS_MAKE_ALL
    if abi >= 2:
        fs |= _FS_REFER
    if abi >= 3:
        fs |= _FS_TRUNCATE
    attr = _RulesetAttr(handled_access_fs=fs)
    size = 8
    if abi >= 4:
        attr.handled_access_net = _NET_BIND_TCP | _NET_CONNECT_TCP
        size = 16
    if abi >= 6:
        attr.scoped = _SCOPE_ABSTRACT_UNIX_SOCKET | _SCOPE_SIGNAL
        size = 24
    # Handled rights with no rules granting them are denied everywhere.
    fd = libc.syscall(_SYS_CREATE_RULESET, ctypes.byref(attr), size, 0)
    if fd < 0:
        raise LandlockUnavailable(ctypes.get_errno(), "landlock_create_ruleset failed")
    try:
        if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise LandlockUnavailable(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
        if libc.syscall(_SYS_RESTRICT_SELF, fd, 0) != 0:
            raise LandlockUnavailable(ctypes.get_errno(), "landlock_restrict_self failed")
    finally:
        os.close(fd)
