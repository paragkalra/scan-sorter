"""Run untrusted-file parsers in a constrained subprocess (docs/PLAN.md, "Components").

Parsers (PDF, images, OCR) run as separate processes with a structured argv
(never a shell), a minimal environment, resource limits, their own process
group, and a wall-clock timeout that kills the whole group. A parser that
crashes, hangs or balloons takes down only itself.
"""

from __future__ import annotations

import os
import resource
import signal
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass


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
    returncode: int | None  # None: killed for exceeding the timeout
    stdout: bytes
    stderr_tail: bytes

    @property
    def timed_out(self) -> bool:
        return self.returncode is None


def _limit(limits: Limits):
    def apply() -> None:
        resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
        resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
        resource.setrlimit(resource.RLIMIT_FSIZE, (limits.max_file_bytes, limits.max_file_bytes))
        resource.setrlimit(resource.RLIMIT_NOFILE, (limits.max_open_files, limits.max_open_files))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        # Exceeding RLIMIT_FSIZE raises SIGXFSZ; make it an EFBIG error instead.
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)

    return apply


def run(
    argv: Sequence[str],
    *,
    stdin_fd: int | None = None,
    limits: Limits = DEFAULT_LIMITS,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> Result:
    """Run argv with limits; stdin_fd (if given) becomes the child's fd 0."""
    if isinstance(argv, str):
        raise TypeError("argv must be a sequence, never a shell string")
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
        preexec_fn=_limit(limits),  # noqa: PLW1509
    )
    try:
        out, err = proc.communicate(timeout=limits.timeout_seconds)
        code: int | None = proc.returncode
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        out, err = proc.communicate()
        code = None
    return Result(code, out[: limits.max_output_bytes], err[-4096:])


def python_module(module: str, *args: str) -> list[str]:
    """argv running one of our modules in isolated mode (-I: no env/user paths)."""
    return [sys.executable, "-I", "-m", module, *args]
