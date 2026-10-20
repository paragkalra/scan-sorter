"""Intake backpressure (docs/PLAN.md, "Job lifecycle").

When the queue is full or the spool disk is low, the watcher stops adopting
new files. They stay in the inbox untouched and are picked up later, so
pausing intake never loses a scan.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from scan_sorter.jobs import JobStore


@dataclass(frozen=True)
class Limits:
    max_active_jobs: int = 50
    min_free_bytes: int = 1 << 30  # 1 GiB


@dataclass(frozen=True)
class IntakeDecision:
    accept: bool
    reason: str | None = None  # "queue_full" or "disk_low" when not accepting


def check_intake(store: JobStore, spool: Path, limits: Limits, *, disk_usage=shutil.disk_usage):
    if store.count_active() >= limits.max_active_jobs:
        return IntakeDecision(False, "queue_full")
    if disk_usage(spool).free < limits.min_free_bytes:
        return IntakeDecision(False, "disk_low")
    return IntakeDecision(True)
