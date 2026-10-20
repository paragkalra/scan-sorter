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

DEFAULT_MIN_FREE_BYTES = 1 << 30  # 1 GiB


@dataclass(frozen=True)
class Admission:
    job: Job | None
    reason: str | None = None  # "queue_full" or "disk_low" when not admitted


def disk_has_room(spool: Path, min_free_bytes: int, disk_usage=shutil.disk_usage) -> bool:
    return disk_usage(spool).free >= min_free_bytes


def admit(
    store: JobStore,
    spool: Path,
    source_name: str,
    *,
    min_free_bytes: int = DEFAULT_MIN_FREE_BYTES,
    disk_usage=shutil.disk_usage,
) -> Admission:
    """Create a job for a new inbox file, or say why intake is paused.

    The queue bound is the store's max_active, enforced inside its write
    transaction, so concurrent intake processes cannot overfill it.
    """
    if not disk_has_room(spool, min_free_bytes, disk_usage):
        return Admission(None, "disk_low")
    try:
        return Admission(store.create(source_name))
    except QueueFullError:
        return Admission(None, "queue_full")
