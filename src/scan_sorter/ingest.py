"""Inbox watching and durable adoption into the spool (docs/PLAN.md, "Job lifecycle").

Two separate gates decide when a scan leaves the printer's share:

1. Transfer completion (TransferGate): the writer closed the file and it then
   stayed unchanged for a while. Content is not inspected here; validation
   does that later.
2. Admission: there is room on disk and in the queue.

Adoption never trusts the inode the printer wrote. It is moved out of the
share, then copied into a new file only the worker owns; hardlinks or a
still-open SMB handle can change the moved inode but never the copy, and the
recorded hash always describes the copy. Each step is ordered so a crash
anywhere is finished by reconcile():

    1. job row + intake (name, identity, quarantine intent)   [DB commit]
    2. rename inbox/<name> -> jobs/<id>/g<gen>/incoming          [fsync dirs]
    3. copy incoming -> original.tmp, rename -> original         [fsync file, dir]
    4. unlink incoming                                           [fsync dir]
    5. source hash                                               [DB commit]

``gen`` counts input generations, so a replacement input never shares a
directory with the original it replaces.
"""

from __future__ import annotations

import errno
import fcntl
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
from scan_sorter.inotify import (
    IN_CLOSE_NOWRITE,
    IN_CLOSE_WRITE,
    IN_CREATE,
    IN_DELETE,
    IN_MODIFY,
    IN_MOVED_FROM,
    IN_MOVED_TO,
    IN_OPEN,
    try_inotify,
)
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

INCOMING = "incoming"
ORIGINAL = "original"
_TMP = "original.tmp"


def generation_dir(gen: int) -> str:
    return f"g{gen}"


# -- transfer gate ---------------------------------------------------------------


@dataclass
class _Seen:
    ident: Identity
    first_seen: float
    last_change: float
    # True when we watched this file arrive with working inotify: then only a
    # close event proves the writer is done, however long it pauses.
    needs_close: bool
    # From inotify: handles open on this file, and whether a writer closed it
    # after the last write (both reset when a new file takes the name).
    closed: bool = False
    opens: int = 0

    def apply(self, mask: int) -> None:
        if mask & (IN_CREATE | IN_DELETE | IN_MOVED_FROM):
            self.opens, self.closed = 0, False
        if mask & IN_MOVED_TO:
            self.opens, self.closed = 0, True
        if mask & IN_OPEN:
            self.opens += 1
        if mask & IN_MODIFY:
            self.closed = False
        if mask & (IN_CLOSE_WRITE | IN_CLOSE_NOWRITE):
            # Clamped: handles opened before we started watching are unknown.
            self.opens = max(0, self.opens - 1)
        if mask & IN_CLOSE_WRITE:
            self.closed = True


@dataclass(frozen=True)
class GateResult:
    ready: list[str]
    overdue: list[str]


class TransferGate:
    """Decides when an inbox entry has finished arriving.

    With reliable events, a file is ready once a writer closed it, no handle
    is open on it any more, and it stayed unchanged for `stable_seconds`. A
    file whose arrival we could not watch (no inotify, already there at
    startup, or present during an event-queue overflow) is ready after
    `fallback_stable_seconds` unchanged.
    A file that never becomes ready within `max_wait_seconds` is overdue.
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
        self._started = False

    def observe(
        self,
        entries: Mapping[str, Identity],
        events: Iterable[tuple[str, int]] = (),
        *,
        events_reliable: bool = False,
    ) -> GateResult:
        """`events` are the inotify (name, mask) pairs since the previous call,
        oldest first."""
        now = self._clock()
        # Files present at the very first scan arrived while nobody watched.
        watching = events_reliable and self._started
        self._started = True
        for name in list(self._seen):
            if name not in entries:
                del self._seen[name]
        for name, ident in entries.items():
            seen = self._seen.get(name)
            if seen is None or not seen.ident.same_file(ident):
                self._seen[name] = _Seen(ident, now, now, needs_close=watching)
            elif seen.ident != ident:
                seen.ident, seen.last_change, seen.closed = ident, now, False
        # Events are applied after the scan, in order: a close reported now
        # covers the state we just observed, while a later create, open or
        # write under the same name cancels it.
        for name, mask in events:
            if name in self._seen:
                self._seen[name].apply(mask)
        ready, overdue = [], []
        for name, seen in self._seen.items():
            quiet = now - seen.last_change
            if not seen.ident.is_regular:
                ready.append(name)  # quarantined on adoption; nothing to wait for
            elif seen.opens:
                pass  # someone still has it open
            elif seen.closed and quiet >= self.stable_seconds:
                ready.append(name)
            elif not seen.needs_close and quiet >= self.fallback_stable_seconds:
                ready.append(name)
            if name not in ready and now - seen.first_seen >= self.max_wait_seconds:
                overdue.append(name)
        return GateResult(sorted(ready), sorted(overdue))

    def forget_closed(self) -> None:
        """After lost inotify events, fall back to the stability window."""
        for seen in self._seen.values():
            seen.closed, seen.opens, seen.needs_close = False, 0, False


# -- spool -------------------------------------------------------------------------


class SourceMissingError(Exception):
    """The inbox entry a job was created for is gone or was replaced."""


class SourceChangedError(Exception):
    """The inbox entry changed since the gate passed it; try again later."""


class SpoolBusyError(Exception):
    """Another process already owns this spool."""


def _intake(name: str, ident: Identity, gen: int, quarantine: str | None) -> dict:
    return {
        "inbox_name_hex": os.fsencode(name).hex(),
        "gen": gen,
        "quarantine": quarantine,
        **ident.as_dict(),
    }


class Spool:
    """The printer's inbox and the private job spool, opened as directory fds.

    Both must be on the same filesystem so leaving the share is a rename.
    One process at a time owns a spool (an exclusive lock on spool/.lock):
    adoption steps are file operations no database check can serialize.
    """

    def __init__(self, inbox: str | Path, spool: str | Path):
        self.inbox_fd = fsutil.open_dir(inbox)
        try:
            self.spool_fd = fsutil.open_dir(spool)
            try:
                self._lock_fd = os.open(
                    ".lock",
                    os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=self.spool_fd,
                )
                try:
                    fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise SpoolBusyError(str(spool)) from None
                os.fchmod(self.spool_fd, 0o700)
                self.jobs_fd = fsutil.make_dir("jobs", dir_fd=self.spool_fd)
                # The new "jobs" entry is only durable once its parent is synced.
                os.fsync(self.spool_fd)
                if os.fstat(self.inbox_fd).st_dev != os.fstat(self.jobs_fd).st_dev:
                    raise ValueError("inbox and spool must be on the same filesystem")
            except BaseException:
                if hasattr(self, "_lock_fd"):
                    os.close(self._lock_fd)
                os.close(self.spool_fd)
                raise
        except BaseException:
            os.close(self.inbox_fd)
            raise
        self.spool_path = Path(spool)

    def close(self) -> None:
        for fd in (self.jobs_fd, self._lock_fd, self.spool_fd, self.inbox_fd):
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

    def open_input_dir(self, doc_id: str, gen: int, *, create: bool = False) -> int | None:
        """The directory holding one input generation of a job."""
        if create:
            job_fd = fsutil.make_dir(doc_id, dir_fd=self.jobs_fd)
            try:
                os.fsync(self.jobs_fd)
                gen_fd = fsutil.make_dir(generation_dir(gen), dir_fd=job_fd)
                os.fsync(job_fd)
                return gen_fd
            finally:
                os.close(job_fd)
        try:
            job_fd = fsutil.open_dir(doc_id, dir_fd=self.jobs_fd)
        except FileNotFoundError:
            return None
        try:
            return fsutil.open_dir(generation_dir(gen), dir_fd=job_fd)
        except FileNotFoundError:
            return None
        finally:
            os.close(job_fd)

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
        A file being quarantined (overdue) may still be growing: only its
        identity has to match.
        """
        current = fsutil.lstat_at(name, self.inbox_fd)
        if current is None or not (
            current.same_file(ident) if quarantine_code else current == ident
        ):
            raise SourceChangedError(name)
        job = store.create(
            fsutil.display_name(os.fsencode(name)),
            intake=_intake(name, current, 0, quarantine_code),
            ignore_capacity=ignore_capacity,
        )
        log.info("job %s received", job.doc_id)
        return self.resume(store, job)

    def resume(self, store: JobStore, job: Job) -> Job:
        """Carry a RECEIVED job without a hash through whatever steps remain."""
        intake = store.stage_result(job.doc_id, Stage.INTAKE)
        if intake is None:
            return store.fail(job, FailureKind.PERMANENT, "source_missing")
        gen = intake.get("gen", 0)
        # Recovered orphans have no inbox identity: only a finished copy counts.
        expected = Identity.from_dict(intake) if "dev" in intake else None
        quarantine = intake.get("quarantine")
        gen_fd = self.open_input_dir(job.doc_id, gen, create=True)
        try:
            have_original = fsutil.lstat_at(ORIGINAL, gen_fd) is not None
            have_incoming = fsutil.lstat_at(INCOMING, gen_fd) is not None
            if expected is None and not have_original and not (have_incoming and quarantine):
                return store.fail(job, FailureKind.PERMANENT, "source_missing")
            if not have_original and not have_incoming:
                try:
                    self._take_from_inbox(intake, expected, quarantine, gen_fd)
                except SourceMissingError:
                    return store.fail(job, FailureKind.PERMANENT, "source_missing")
            if not have_original:
                code = self._make_private_copy(gen_fd, expected, quarantine)
                if code is not None:
                    # Make the moved input durable before the row says where it is.
                    self._barrier(job.doc_id, gen_fd, INCOMING)
                    log.info("job %s quarantined: %s", job.doc_id, code)
                    return store.advance(job, State.QUARANTINED, code=code)
            return self._finish(store, job, gen_fd)
        finally:
            os.close(gen_fd)

    def _take_from_inbox(
        self, intake: dict, expected: Identity, quarantine: str | None, gen_fd: int
    ) -> None:
        name = os.fsdecode(bytes.fromhex(intake["inbox_name_hex"]))
        current = fsutil.lstat_at(name, self.inbox_fd)
        # Full identity unless quarantining a growing file: inode numbers get
        # reused, so a new scan under the same name can share one.
        if current is None or not (
            current.same_file(expected) if quarantine else current.same_content(expected)
        ):
            raise SourceMissingError(name)
        if current.is_regular:
            # The printer's bytes must be durable before the entry leaves the
            # inbox durably; quarantined files are never copied, so this is
            # their only barrier.
            try:
                fsutil.fsync_file(name, self.inbox_fd)
            except FileNotFoundError:
                raise SourceMissingError(name) from None
        try:
            os.rename(name, INCOMING, src_dir_fd=self.inbox_fd, dst_dir_fd=gen_fd)
        except FileNotFoundError:
            # Deleted, or taken by another adopter, after the check above.
            raise SourceMissingError(name) from None
        os.fsync(self.inbox_fd)
        os.fsync(gen_fd)

    @staticmethod
    def _make_private_copy(
        gen_fd: int, expected: Identity | None, quarantine: str | None
    ) -> str | None:
        """Copy INCOMING to ORIGINAL; return a quarantine code instead if needed."""
        if quarantine:
            return quarantine
        incoming = fsutil.lstat_at(INCOMING, gen_fd)
        if incoming is None or not incoming.is_regular:
            return "not_regular_file"
        if expected is None or not incoming.same_content(expected):
            return "changed_during_adoption"
        if incoming.nlink > 1:
            # Another name still points at this inode, possibly in the share.
            return "multiple_links"
        try:
            src = fsutil.open_regular(INCOMING, gen_fd)
        except OSError:
            return "not_regular_file"
        try:
            try:
                os.unlink(_TMP, dir_fd=gen_fd)
            except FileNotFoundError:
                pass
            _, stable = fsutil.private_copy(src, _TMP, gen_fd)
        finally:
            os.close(src)
        if not stable:
            os.unlink(_TMP, dir_fd=gen_fd)
            return "changed_during_adoption"
        os.rename(_TMP, ORIGINAL, src_dir_fd=gen_fd, dst_dir_fd=gen_fd)
        os.fsync(gen_fd)
        return None

    def _finish(self, store: JobStore, job: Job, gen_fd: int) -> Job:
        """Drop the printer's inode, re-establish durability, record the hash."""
        try:
            os.unlink(INCOMING, dir_fd=gen_fd)
        except FileNotFoundError:
            pass
        self._barrier(job.doc_id, gen_fd, ORIGINAL)
        job = store.set_source_hash(job, fsutil.sha256_file(ORIGINAL, gen_fd))
        log.info("job %s adopted", job.doc_id)
        return job

    def _barrier(self, doc_id: str, gen_fd: int, name: str) -> None:
        """fsync the input file and every directory on its path, and the inbox.

        Run before any commit that records where an input lives, even when
        resuming after a crash: the earlier process may have died before (or
        while) running its own fsyncs.
        """
        try:
            fsutil.fsync_file(name, gen_fd)
        except OSError:
            pass  # not a regular file (quarantined); its directory entry is enough
        os.fsync(gen_fd)
        job_fd = fsutil.open_dir(doc_id, dir_fd=self.jobs_fd)
        try:
            os.fsync(job_fd)
        finally:
            os.close(job_fd)
        os.fsync(self.jobs_fd)
        os.fsync(self.inbox_fd)

    # -- crash recovery ----------------------------------------------------------------

    def reconcile(self, store: JobStore) -> list[str]:
        """Finish or repair adoptions interrupted by a crash. Returns touched doc ids."""
        touched = []
        for job in store.jobs_in(State.RECEIVED):
            if job.source_hash is None:
                touched.append(job.doc_id)
                self.resume(store, job)
        touched += self._adopt_orphan_dirs(store)
        return touched

    def _adopt_orphan_dirs(self, store: JobStore) -> list[str]:
        """Spool directories with no job row (the row was lost): register them."""
        touched = []
        for name in os.listdir(self.jobs_fd):
            try:
                store.get(name)
                continue
            except JobNotFoundError:
                pass
            gen_fd = None
            try:
                gen_fd = self.open_input_dir(name, 0)
            except OSError:
                pass
            if gen_fd is None:
                self._remove_if_empty(name)
                continue
            try:
                if fsutil.lstat_at(ORIGINAL, gen_fd) is not None:
                    quarantine = None  # a finished private copy: carry on normally
                elif fsutil.lstat_at(INCOMING, gen_fd) is not None:
                    quarantine = "orphaned_input"  # never verified: a person decides
                else:
                    log.warning("orphan spool directory without an input left alone")
                    continue
                try:
                    job = store.create(
                        "recovered",
                        doc_id=name,
                        ignore_capacity=True,
                        intake={"gen": 0, "quarantine": quarantine, "recovered": True},
                    )
                except ValueError:
                    log.warning("spool directory with an invalid job id left alone")
                    continue
                touched.append(job.doc_id)
                self.resume(store, job)
            finally:
                os.close(gen_fd)
        return touched

    def _remove_if_empty(self, name: str) -> None:
        try:
            job_fd = fsutil.open_dir(name, dir_fd=self.jobs_fd)
        except OSError:
            log.warning("spool entry that is not a job directory left alone")
            return
        try:
            empty = not os.listdir(job_fd)
        finally:
            os.close(job_fd)
        if empty:
            os.rmdir(name, dir_fd=self.jobs_fd)
            os.fsync(self.jobs_fd)


# -- watcher -----------------------------------------------------------------------


@dataclass
class PollReport:
    adopted: list[str] = field(default_factory=list)
    quarantined: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
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
        events: list[tuple[str, int]] = []
        reliable = self.inotify is not None
        if self.inotify is not None:
            events = [(os.fsdecode(n), mask) for n, mask in self.inotify.read()]
            if self.inotify.overflowed:
                # Events were lost: nothing seen this poll can rely on them.
                self.gate.forget_closed()
                self.inotify.overflowed = False
                events, reliable = [], False
        self._resume_pending(report)
        entries = self.spool.inbox_entries()
        result = self.gate.observe(entries, events, events_reliable=reliable)
        # Overdue files are quarantined straight away, so they never take a
        # queue slot; they still need disk for the move's metadata.
        work = [(n, "incomplete_transfer") for n in result.overdue]
        work += [(n, None) for n in result.ready]
        for name, quarantine in work:
            if not disk_has_room(self.spool.spool_path, self.min_free_bytes, self.disk_usage):
                report.paused = "disk_low"
                break
            try:
                job = self.spool.adopt(
                    self.store,
                    name,
                    entries[name],
                    quarantine_code=quarantine,
                    ignore_capacity=quarantine is not None,
                )
            except QueueFullError:
                report.paused = "queue_full"
                break
            except SourceChangedError:
                continue  # still changing; the gate sees it on the next poll
            except OSError as exc:
                # One bad entry must not stop intake for everything else.
                log.warning("adoption error %s", errno.errorcode.get(exc.errno, "unknown"))
                continue
            if job.state is State.QUARANTINED:
                report.quarantined.append(job.doc_id)
            elif job.state is State.FAILED:
                report.failed.append(job.doc_id)
            else:
                report.adopted.append(job.doc_id)
        if report.paused:
            # Files stay in the inbox and are picked up on a later poll.
            log.info("intake paused: %s", report.paused)
        return report

    def _resume_pending(self, report: PollReport) -> None:
        """Retry adoptions that a transient error (e.g. a full disk) cut short."""
        if not disk_has_room(self.spool.spool_path, self.min_free_bytes, self.disk_usage):
            return
        for job in self.store.jobs_in(State.RECEIVED):
            if job.source_hash is not None:
                continue
            try:
                self.spool.resume(self.store, job)
            except OSError as exc:
                log.warning("resume error %s", errno.errorcode.get(exc.errno, "unknown"))

    def run(self, stop: threading.Event, *, interval: float = 2.0) -> None:
        self.spool.reconcile(self.store)
        while not stop.is_set():
            self.poll_once()
            if self.inotify is not None:
                select.select([self.inotify], [], [], interval)
            else:
                stop.wait(interval)
