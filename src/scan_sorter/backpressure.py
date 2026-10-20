"""Intake backpressure (docs/PLAN.md, "Job lifecycle").

When the queue is full or the spool disk is low, the watcher stops adopting
new files. They stay in the inbox untouched and are picked up later, so
pausing intake never loses a scan.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from scan_sorter.jobs import Job, JobStore, QueueFullError


@dataclass(frozen=True)
class Limits:
    max_active_jobs: int = 50
    min_free_bytes: int = 1 << 30  # 1 GiB


@dataclass(frozen=True)
class Admission:
    job: Job | None
    reason: str | None = None  # "queue_full" or "disk_low" when not admitted


def admit(
    store: JobStore, spool: Path, source_name: str, limits: Limits, *, disk_usage=shutil.disk_usage
) -> Admission:
    """Create a job for a new inbox file, or say why intake is paused.

    The queue bound is enforced inside the job store's write transaction, so
    concurrent intake processes cannot overfill it.
    """
    if disk_usage(spool).free < limits.min_free_bytes:
        return Admission(None, "disk_low")
    try:
        return Admission(store.create(source_name, max_active=limits.max_active_jobs))
    except QueueFullError:
        return Admission(None, "queue_full")
