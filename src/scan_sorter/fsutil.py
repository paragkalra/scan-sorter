"""Symlink-safe filesystem helpers (docs/PLAN.md, "Job lifecycle").

Everything here works relative to directory file descriptors with
O_NOFOLLOW, so a symlink planted in the inbox or spool can never redirect a
read, rename or fsync outside the directory we opened.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def open_dir(path: str | os.PathLike, *, dir_fd: int | None = None) -> int:
    """Open a directory without following a symlink at its last component."""
    return os.open(path, _DIR_FLAGS, dir_fd=dir_fd)


def make_dir(name: str, *, dir_fd: int, mode: int = 0o700) -> int:
    """Create (if needed) and open a private subdirectory of dir_fd."""
    try:
        os.mkdir(name, mode, dir_fd=dir_fd)
    except FileExistsError:
        pass
    fd = open_dir(name, dir_fd=dir_fd)
    try:
        os.fchmod(fd, mode)
    except BaseException:
        os.close(fd)
        raise
    return fd


def fsync_dir(fd: int) -> None:
    os.fsync(fd)


@dataclass(frozen=True)
class Identity:
    """What makes an inbox entry the same entry: survives rename, changes on rewrite."""

    dev: int
    ino: int
    size: int
    mtime_ns: int
    mode: int

    @classmethod
    def of(cls, st: os.stat_result) -> Identity:
        return cls(st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_mode)

    @property
    def is_regular(self) -> bool:
        return stat.S_ISREG(self.mode)

    def same_file(self, other: Identity) -> bool:
        return (self.dev, self.ino) == (other.dev, other.ino)

    def as_dict(self) -> dict[str, int]:
        return {
            "dev": self.dev,
            "ino": self.ino,
            "size": self.size,
            "mtime_ns": self.mtime_ns,
            "mode": self.mode,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Identity:
        return cls(d["dev"], d["ino"], d["size"], d["mtime_ns"], d["mode"])


def lstat_at(name: str | bytes, dir_fd: int) -> Identity | None:
    try:
        return Identity.of(os.stat(name, dir_fd=dir_fd, follow_symlinks=False))
    except FileNotFoundError:
        return None


def open_regular(name: str | bytes, dir_fd: int) -> int:
    """Open a regular file for reading; refuse symlinks, FIFOs and devices.

    O_NONBLOCK keeps a planted FIFO from blocking the open; the fstat check
    then rejects it.
    """
    fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise IsADirectoryError(f"not a regular file: {name!r}")
        os.set_blocking(fd, True)
    except BaseException:
        os.close(fd)
        raise
    return fd


def fsync_file(name: str | bytes, dir_fd: int) -> Identity:
    fd = open_regular(name, dir_fd)
    try:
        os.fsync(fd)
        return Identity.of(os.fstat(fd))
    finally:
        os.close(fd)


def sha256_file(name: str | bytes, dir_fd: int, *, chunk: int = 1 << 20) -> str:
    fd = open_regular(name, dir_fd)
    try:
        h = hashlib.sha256()
        while block := os.read(fd, chunk):
            h.update(block)
        return h.hexdigest()
    finally:
        os.close(fd)


def display_name(name: bytes) -> str:
    """A printable, storable version of a raw filename (never used to open it)."""
    text = name.decode("utf-8", "backslashreplace")
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in text)[:255]
