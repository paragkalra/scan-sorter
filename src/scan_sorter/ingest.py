"""Inbox watching and durable adoption into the spool (docs/PLAN.md, "Job lifecycle").

Two separate gates decide when a scan leaves the printer's share:

1. Transfer completion (TransferGate): the file stopped changing for a while,
   and, when inotify is available, its writer closed it. Content is not
   inspected here; validation does that later.
2. Admission (backpressure.admit): there is room in the queue and on disk.

Adoption is ordered so a crash at any point is recoverable by reconcile():
the job row (with the inbox entry's identity) commits first, then the file is
fsynced, renamed into ``jobs/<doc_id>/original``, the directories fsynced, and
finally the source hash recorded.
"""

from __future__ import annotations

import logging
import os
import select
import shutil
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from scan_sorter import fsutil
from scan_sorter.backpressure import DEFAULT_MIN_FREE_BYTES, disk_has_room
from scan_sorter.fsutil import Identity
from scan_sorter.inotify import try_inotify
from scan_sorter.jobs import (
    FailureKind,
    Job,
    JobNotFoundError,
    JobStore,
    QueueFullError,
    Stage,
    State,
)

log = logging.getLogger(__name__)

ORIGINAL = "original"


# -- transfer gate ---------------------------------------------------------------


@dataclass
class _Seen:
    ident: Identity
    first_seen: float
    last_change: float
    closed: bool = False


@dataclass(frozen=True)
class GateResult:
    ready: list[str]
    overdue: list[str]


class TransferGate:
    """Decides when an inbox entry has finished arriving.

    A file is ready once unchanged for `stable_seconds` after its writer closed
    it, or for `fallback_stable_seconds` when no close was seen (no inotify, a
    file already present at startup, or an inotify queue overflow). A file that
    never settles within `max_wait_seconds` of first being seen is overdue.
    """

    def __init__(
        self,
        *,
        stable_seconds: float = 10,
        fallback_stable_seconds: float = 60,
        max_wait_seconds: float = 30 * 60,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.stable_seconds = stable_seconds
        self.fallback_stable_seconds = fallback_stable_seconds
        self.max_wait_seconds = max_wait_seconds
        self._clock = clock
        self._seen: dict[str, _Seen] = {}

    def observe(self, entries: Mapping[str, Identity], closed: Iterable[str] = ()) -> GateResult:
        now = self._clock()
        for name in list(self._seen):
            if name not in entries:
                del self._seen[name]
        for name, ident in entries.items():
            seen = self._seen.get(name)
            if seen is None or not seen.ident.same_file(ident):
                self._seen[name] = _Seen(ident, now, now)
            elif seen.ident != ident:
                seen.ident, seen.last_change, seen.closed = ident, now, False
        # Close events are applied after the scan: a close reported now covers
        # the state we just observed.
        for name in closed:
            if name in self._seen:
                self._seen[name].closed = True
        ready, overdue = [], []
        for name, seen in self._seen.items():
            quiet = now - seen.last_change
            if not seen.ident.is_regular:
                ready.append(name)  # quarantined on adoption; nothing to wait for
            elif (seen.closed and quiet >= self.stable_seconds) or (
                quiet >= self.fallback_stable_seconds
            ):
                ready.append(name)
            elif now - seen.first_seen >= self.max_wait_seconds:
                overdue.append(name)
        return GateResult(sorted(ready), sorted(overdue))

    def forget_closed(self) -> None:
        """After lost inotify events, stop trusting earlier close marks."""
        for seen in self._seen.values():
            seen.closed = False


# -- spool -------------------------------------------------------------------------


class SourceMissingError(Exception):
    """The inbox entry a job was created for is gone, replaced, or changed."""


class SourceChangedError(Exception):
    """The inbox entry changed since the gate passed it; try again later."""


class Spool:
    """The printer's inbox and the private job spool, opened as directory fds.

    Both must be on the same filesystem so adoption is a rename.
    """

    def __init__(self, inbox: str | Path, spool: str | Path):
        self.inbox_fd = fsutil.open_dir(inbox)
        try:
            self.spool_fd = fsutil.open_dir(spool)
            try:
                os.fchmod(self.spool_fd, 0o700)
                self.jobs_fd = fsutil.make_dir("jobs", dir_fd=self.spool_fd)
                if os.fstat(self.inbox_fd).st_dev != os.fstat(self.jobs_fd).st_dev:
                    raise ValueError("inbox and spool must be on the same filesystem")
            except BaseException:
                os.close(self.spool_fd)
                raise
        except BaseException:
            os.close(self.inbox_fd)
            raise
        self.spool_path = Path(spool)

    def close(self) -> None:
        for fd in (self.jobs_fd, self.spool_fd, self.inbox_fd):
            os.close(fd)

    def __enter__(self) -> Spool:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def inbox_entries(self) -> dict[str, Identity]:
        """Inbox entries by name, skipping dotfiles (temporary names during upload)."""
        entries = {}
        for name in os.listdir(self.inbox_fd):
            if name.startswith("."):
                continue
            ident = fsutil.lstat_at(name, self.inbox_fd)
            if ident is not None:
                entries[name] = ident
        return entries

    def open_job_dir(self, doc_id: str, *, create: bool = False) -> int | None:
        if create:
            return fsutil.make_dir(doc_id, dir_fd=self.jobs_fd)
        try:
            return fsutil.open_dir(doc_id, dir_fd=self.jobs_fd)
        except FileNotFoundError:
            return None

    # -- adoption --------------------------------------------------------------------

    def adopt(
        self,
        store: JobStore,
        name: str,
        ident: Identity,
        *,
        quarantine_code: str | None = None,
        ignore_capacity: bool = False,
    ) -> Job:
        """Register an inbox entry as a job and move it into the spool.

        Raises QueueFullError or SourceChangedError, with nothing changed, when
        the queue has no room or the entry no longer matches what the gate saw.
        """
        if fsutil.lstat_at(name, self.inbox_fd) != ident:
            raise SourceChangedError(name)
        intake = {"inbox_name_hex": os.fsencode(name).hex(), **ident.as_dict()}
        job = store.create(
            fsutil.display_name(os.fsencode(name)),
            intake=intake,
            ignore_capacity=ignore_capacity,
        )
        log.info("job %s received", job.doc_id)
        try:
            return self._move_in(store, job, name, ident, quarantine_code)
        except SourceMissingError:
            return store.fail(job, FailureKind.PERMANENT, "source_missing")

    def _move_in(
        self,
        store: JobStore,
        job: Job,
        name: str,
        expected: Identity,
        quarantine_code: str | None,
    ) -> Job:
        current = fsutil.lstat_at(name, self.inbox_fd)
        # Full identity, not just the inode: inode numbers are reused, so a
        # new scan under the same name can share one with a deleted file.
        if current != expected:
            raise SourceMissingError(name)
        if current.is_regular:
            # Make the bytes durable before the rename makes the entry durable.
            fsutil.fsync_file(name, self.inbox_fd)
        job_fd = self.open_job_dir(job.doc_id, create=True)
        try:
            os.fsync(self.jobs_fd)
            if fsutil.lstat_at(ORIGINAL, job_fd) is None:
                os.rename(name, ORIGINAL, src_dir_fd=self.inbox_fd, dst_dir_fd=job_fd)
            os.fsync(self.inbox_fd)
            os.fsync(job_fd)
            os.fsync(self.jobs_fd)
            return self._record(store, job, job_fd, expected, quarantine_code)
        finally:
            os.close(job_fd)

    def _record(
        self,
        store: JobStore,
        job: Job,
        job_fd: int,
        expected: Identity | None,
        quarantine_code: str | None,
    ) -> Job:
        moved = fsutil.lstat_at(ORIGINAL, job_fd)
        if moved is None:
            raise SourceMissingError(job.doc_id)
        code = quarantine_code
        if not moved.is_regular:
            code = "not_regular_file"
        elif expected is not None and (
            not moved.same_file(expected)
            or (moved.size, moved.mtime_ns) != (expected.size, expected.mtime_ns)
        ):
            # Still being written, or swapped, after the gate passed it.
            code = "changed_during_adoption"
        if code is not None:
            log.info("job %s quarantined: %s", job.doc_id, code)
            return store.advance(job, State.QUARANTINED, code=code)
        job = store.set_source_hash(job, fsutil.sha256_file(ORIGINAL, job_fd))
        log.info("job %s adopted", job.doc_id)
        return job

    # -- crash recovery ----------------------------------------------------------------

    def reconcile(self, store: JobStore) -> list[str]:
        """Finish or repair adoptions interrupted by a crash. Returns touched doc ids."""
        touched = []
        for job in store.jobs_in(State.RECEIVED):
            if job.source_hash is not None:
                continue
            touched.append(job.doc_id)
            job_fd = self.open_job_dir(job.doc_id)
            try:
                if job_fd is not None and fsutil.lstat_at(ORIGINAL, job_fd) is not None:
                    # Renamed before the crash; only the hash is missing.
                    self._record(store, job, job_fd, self._intake_identity(store, job), None)
                    continue
            finally:
                if job_fd is not None:
                    os.close(job_fd)
            intake = store.stage_result(job.doc_id, Stage.INTAKE)
            if intake is None:
                store.fail(job, FailureKind.PERMANENT, "source_missing")
                continue
            name = os.fsdecode(bytes.fromhex(intake["inbox_name_hex"]))
            try:
                self._move_in(store, job, name, Identity.from_dict(intake), None)
            except SourceMissingError:
                store.fail(job, FailureKind.PERMANENT, "source_missing")
        touched += self._adopt_orphan_dirs(store)
        return touched

    @staticmethod
    def _intake_identity(store: JobStore, job: Job) -> Identity | None:
        intake = store.stage_result(job.doc_id, Stage.INTAKE)
        return None if intake is None else Identity.from_dict(intake)

    def _adopt_orphan_dirs(self, store: JobStore) -> list[str]:
        """Spool directories with no job row (the row was lost): register them."""
        touched = []
        for name in os.listdir(self.jobs_fd):
            try:
                store.get(name)
                continue
            except JobNotFoundError:
                pass
            try:
                job_fd = fsutil.open_dir(name, dir_fd=self.jobs_fd)
            except OSError:
                log.warning("spool entry that is not a job directory left alone")
                continue
            try:
                if fsutil.lstat_at(ORIGINAL, job_fd) is None:
                    if not os.listdir(job_fd):
                        os.rmdir(name, dir_fd=self.jobs_fd)
                        os.fsync(self.jobs_fd)
                    continue
                try:
                    job = store.create("recovered", doc_id=name, ignore_capacity=True)
                except ValueError:
                    log.warning("spool directory with an invalid job id left alone")
                    continue
                touched.append(job.doc_id)
                self._record(store, job, job_fd, None, None)
            finally:
                os.close(job_fd)
        return touched


# -- watcher -----------------------------------------------------------------------


@dataclass
class PollReport:
    adopted: list[str] = field(default_factory=list)
    quarantined: list[str] = field(default_factory=list)
    paused: str | None = None


class Watcher:
    def __init__(
        self,
        store: JobStore,
        spool: Spool,
        gate: TransferGate | None = None,
        *,
        min_free_bytes: int = DEFAULT_MIN_FREE_BYTES,
        use_inotify: bool = True,
        disk_usage=shutil.disk_usage,
    ):
        self.store = store
        self.spool = spool
        self.gate = gate or TransferGate()
        self.min_free_bytes = min_free_bytes
        self.disk_usage = disk_usage
        self.inotify = try_inotify(spool.inbox_fd) if use_inotify else None

    def close(self) -> None:
        if self.inotify is not None:
            self.inotify.close()

    def poll_once(self) -> PollReport:
        report = PollReport()
        closed: list[str] = []
        if self.inotify is not None:
            closed = [os.fsdecode(n) for n in self.inotify.read()]
            if self.inotify.overflowed:
                self.gate.forget_closed()
                self.inotify.overflowed = False
                closed = []
        entries = self.spool.inbox_entries()
        result = self.gate.observe(entries, closed)
        for name in result.overdue:
            # Quarantined straight away, so it never occupies a queue slot.
            try:
                job = self.spool.adopt(
                    self.store,
                    name,
                    entries[name],
                    quarantine_code="incomplete_transfer",
                    ignore_capacity=True,
                )
            except SourceChangedError:
                # Moving it while it changes would still be safe, but the next
                # poll takes a consistent snapshot first.
                continue
            report.quarantined.append(job.doc_id)
        for name in result.ready:
            if not disk_has_room(self.spool.spool_path, self.min_free_bytes, self.disk_usage):
                report.paused = "disk_low"
            else:
                try:
                    job = self.spool.adopt(self.store, name, entries[name])
                except QueueFullError:
                    report.paused = "queue_full"
                except SourceChangedError:
                    continue  # still changing; the gate sees it on the next poll
            if report.paused:
                # The file stays in the inbox and is picked up on a later poll.
                log.info("intake paused: %s", report.paused)
                break
            (report.quarantined if job.state is State.QUARANTINED else report.adopted).append(
                job.doc_id
            )
        return report

    def run(self, stop: threading.Event, *, interval: float = 2.0) -> None:
        self.spool.reconcile(self.store)
        while not stop.is_set():
            try:
                self.poll_once()
            except QueueFullError:
                pass
            if self.inotify is not None:
                select.select([self.inotify], [], [], interval)
            else:
                stop.wait(interval)
