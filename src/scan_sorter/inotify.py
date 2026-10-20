"""Minimal Linux inotify binding (stdlib only, via ctypes).

Used only as a hint that a writer closed a file; the transfer gate also
requires the file to stay unchanged for a while, and works without inotify.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import struct

IN_MODIFY = 0x00000002
IN_CLOSE_WRITE = 0x00000008
IN_CLOSE_NOWRITE = 0x00000010
IN_OPEN = 0x00000020
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
WATCH_MASK = (
    IN_MODIFY
    | IN_CLOSE_WRITE
    | IN_CLOSE_NOWRITE
    | IN_OPEN
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
)
IN_Q_OVERFLOW = 0x00004000
IN_NONBLOCK = 0o4000
IN_CLOEXEC = 0o2000000

_HEADER = struct.Struct("iIII")


class Inotify:
    """Watches one directory's entries: opens, writes, closes, creates, moves
    and deletes, in the order they happened."""

    def __init__(self, dir_fd: int):
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        fd = libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")
        self._fd = fd
        # Watch the directory we already hold open, never a re-resolved path.
        path = f"/proc/self/fd/{dir_fd}".encode()
        wd = libc.inotify_add_watch(fd, path, WATCH_MASK)
        if wd < 0:
            err = ctypes.get_errno()
            os.close(fd)
            raise OSError(err, "inotify_add_watch failed")
        self.overflowed = False

    def fileno(self) -> int:
        return self._fd

    def read(self) -> list[tuple[bytes, int]]:
        """(name, mask) for every event since the last read, oldest first."""
        events: list[tuple[bytes, int]] = []
        while True:
            try:
                buf = os.read(self._fd, 64 * 1024)
            except BlockingIOError:
                return events
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                raise
            pos = 0
            while pos < len(buf):
                _wd, mask, _cookie, length = _HEADER.unpack_from(buf, pos)
                pos += _HEADER.size
                name = buf[pos : pos + length].rstrip(b"\0")
                pos += length
                if mask & IN_Q_OVERFLOW:
                    self.overflowed = True
                elif name and mask & WATCH_MASK:
                    events.append((name, mask & WATCH_MASK))

    def close(self) -> None:
        os.close(self._fd)


def try_inotify(dir_fd: int) -> Inotify | None:
    try:
        return Inotify(dir_fd)
    except (OSError, AttributeError):
        return None
