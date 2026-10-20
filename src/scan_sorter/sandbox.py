"""Run untrusted-file parsers in a constrained subprocess (docs/PLAN.md, "Components").

Parsers (PDF, images, OCR) run as separate processes with a structured argv
(never a shell), a minimal environment, resource limits, their own process
group, and a wall-clock timeout that kills the whole group. A parser that
crashes, hangs or balloons takes down only itself.
"""

from __future__ import annotations

import os
import resource
import selectors
import signal
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass

from scan_sorter import landlock


@dataclass(frozen=True)
class Limits:
    timeout_seconds: float = 60
    cpu_seconds: int = 60
    memory_bytes: int = 1 << 30  # address space
    max_file_bytes: int = 0  # files the child may write (0: none)
    max_open_files: int = 64
    max_output_bytes: int = 1 << 20  # stdout kept


DEFAULT_LIMITS = Limits()


@dataclass(frozen=True)
class Result:
    returncode: int | None  # None: killed (timeout or too much output)
    stdout: bytes
    stderr_tail: bytes
    timed_out: bool = False
    output_exceeded: bool = False


class SandboxUnavailable(RuntimeError):
    """The kernel cannot provide the filesystem/network isolation we require."""


def _limit(limits: Limits, isolate: bool):
    def apply() -> None:
        resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
        resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
        resource.setrlimit(resource.RLIMIT_FSIZE, (limits.max_file_bytes, limits.max_file_bytes))
        resource.setrlimit(resource.RLIMIT_NOFILE, (limits.max_open_files, limits.max_open_files))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        # Exceeding RLIMIT_FSIZE raises SIGXFSZ; make it an EFBIG error instead.
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        if isolate:
            # No writes, truncation, deletion or TCP anywhere: a compromised
            # parser cannot touch the spool, the database or the network.
            landlock.deny_writes_and_network()

    return apply


def run(
    argv: Sequence[str],
    *,
    stdin_fd: int | None = None,
    limits: Limits = DEFAULT_LIMITS,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    isolate: bool = True,
) -> Result:
    """Run argv with limits; stdin_fd (if given) becomes the child's fd 0.

    isolate (default) applies Landlock and refuses to run without it.
    Output is read incrementally: past max_output_bytes on stdout the child
    is killed, and only the last 4 KiB of stderr is ever kept.
    """
    if isinstance(argv, str):
        raise TypeError("argv must be a sequence, never a shell string")
    if isolate and landlock.abi_version() < 1:
        raise SandboxUnavailable("Landlock is required to run parsers")
    base_env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C.UTF-8"}
    proc = subprocess.Popen(  # noqa: S603  (structured argv, no shell)
        list(argv),
        stdin=stdin_fd if stdin_fd is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env={**base_env, **(env or {})},
        close_fds=True,
        start_new_session=True,
        preexec_fn=_limit(limits, isolate),  # noqa: PLW1509
    )
    out = bytearray()
    err = bytearray()
    timed_out = exceeded = False
    deadline = time.monotonic() + limits.timeout_seconds
    with selectors.DefaultSelector() as sel:
        sel.register(proc.stdout, selectors.EVENT_READ, "out")
        sel.register(proc.stderr, selectors.EVENT_READ, "err")
        while sel.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in sel.select(remaining):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    sel.unregister(key.fileobj)
                elif key.data == "out":
                    out += chunk
                    if len(out) > limits.max_output_bytes:
                        exceeded = True
                else:
                    err += chunk
                    del err[:-4096]
            if exceeded:
                break
    if not (timed_out or exceeded):
        try:
            # The pipes can close while the child keeps running.
            proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
    if timed_out or exceeded:
        os.killpg(proc.pid, signal.SIGKILL)
    proc.stdout.close()
    proc.stderr.close()
    code = proc.wait()
    return Result(
        None if (timed_out or exceeded) else code,
        bytes(out[: limits.max_output_bytes]),
        bytes(err),
        timed_out=timed_out,
        output_exceeded=exceeded,
    )


def python_module(module: str, *args: str) -> list[str]:
    """argv running one of our modules in isolated mode (-I: no env/user paths)."""
    return [sys.executable, "-I", "-m", module, *args]
