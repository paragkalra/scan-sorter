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

import contextlib
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


@dataclass
class _Handles:
    """What inotify told us about one file, kept by name and carried across
    renames inside the inbox (so a temp file renamed into place keeps its
    open writers)."""

    watched: bool  # we saw it created here, so we know all its handles
    opens: int = 0
    closed: bool = False  # a writer closed it after its last write

    def apply(self, mask: int) -> None:
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
        self._handles: dict[str, _Handles] = {}
        # Renames in progress, by inotify cookie, with the poll they started in.
        self._moving: dict[int, tuple[_Handles, int]] = {}
        self._polls = 0
        self._started = False

    def observe(
        self,
        entries: Mapping[str, Identity],
        events: Iterable[tuple[str, int] | tuple[str, int, int]] = (),
        *,
        events_reliable: bool = False,
    ) -> GateResult:
        """`events` are the inotify (name, mask[, cookie]) tuples since the
        previous call, oldest first."""
        now = self._clock()
        # Files present at the very first scan arrived while nobody watched.
        watching = events_reliable and self._started
        self._started = True
        for name in list(self._seen):
            if name not in entries:
                del self._seen[name]
        # Handle state is not pruned here: a file listed last poll may have
        # been renamed since, and its IN_MOVED_FROM (processed below) must
        # still find it. DELETE and MOVED_FROM remove entries; an overflow
        # clears everything.
        for name, ident in entries.items():
            seen = self._seen.get(name)
            if seen is None or not seen.ident.same_file(ident):
                self._seen[name] = _Seen(ident, now, now, needs_close=watching)
            elif seen.ident != ident:
                seen.ident, seen.last_change = ident, now
                # Written to since any close we saw (in case its event was lost).
                if name in self._handles:
                    self._handles[name].closed = False
        # Events are applied after the scan, in order: a close reported now
        # covers the state we just observed, while a later create, open or
        # write under the same name cancels it.
        self._polls += 1
        for event in events:
            self._apply(*event)
        self._moving = {c: v for c, v in self._moving.items() if v[1] >= self._polls - 1}
        ready, overdue = [], []
        for name, seen in self._seen.items():
            quiet = now - seen.last_change
            if not seen.ident.is_regular:
                ready.append(name)  # quarantined on adoption; nothing to wait for
            handles = self._handles.get(name)
            needs_close = handles.watched if handles else seen.needs_close
            if handles and handles.opens:
                pass  # someone still has it open
            elif handles and handles.closed and quiet >= self.stable_seconds:
                ready.append(name)
            elif not needs_close and quiet >= self.fallback_stable_seconds:
                ready.append(name)
            if name not in ready and now - seen.first_seen >= self.max_wait_seconds:
                overdue.append(name)
        return GateResult(sorted(ready), sorted(overdue))

    def _apply(self, name: str, mask: int, cookie: int = 0) -> None:
        if mask & IN_CREATE:
            self._handles[name] = _Handles(watched=True)
        elif mask & IN_DELETE:
            self._handles.pop(name, None)
        elif mask & IN_MOVED_FROM:
            moved = self._handles.pop(name, None)
            if moved is not None and cookie:
                self._moving[cookie] = (moved, self._polls)
        elif mask & IN_MOVED_TO:
            moved = self._moving.pop(cookie, (None, 0))[0] if cookie else None
            # Moved in from elsewhere: we never saw its handles, so it gets the
            # stability fallback, not a close it may never send.
            self._handles[name] = moved or _Handles(watched=False)
        else:
            if name not in self._handles:
                seen = self._seen.get(name)
                self._handles[name] = _Handles(watched=seen.needs_close if seen else False)
            self._handles[name].apply(mask)

    def forget_closed(self) -> None:
        """After lost inotify events, fall back to the stability window."""
        self._handles.clear()
        self._moving.clear()
        for seen in self._seen.values():
            seen.needs_close = False


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

    def __init__(
        self,
        inbox: str | Path,
        spool: str | Path,
        *,
        require_no_writers: bool = True,
        stable_seconds: float = 10,
        wall_clock: Callable[[], float] = time.time,
    ):
        """require_no_writers: refuse to adopt a file while any process has it
        open for writing. This needs read leases, i.e. the worker must run as
        the inbox files' owner (the scanner UID); disable it only where leases
        are unavailable, accepting the stability window as the only guard."""
        self.require_no_writers = require_no_writers
        # A registered input that changes before it is moved must then stay
        # unchanged this long again (wall clock: the wait spans restarts).
        self.stable_seconds = stable_seconds
        self.wall_clock = wall_clock
        if require_no_writers:
            fsutil.ignore_lease_signals()
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
        if not quarantine_code and current.is_regular and self.require_no_writers:
            # inotify open/close counts are hints (the kernel merges repeated
            # events); the lease is the authority on open writers. This probe
            # avoids registering a job for a file still being written; resume()
            # holds a lease for real while moving and copying.
            try:
                if fsutil.has_writers(name, self.inbox_fd):
                    raise SourceChangedError(name)
            except FileNotFoundError:
                raise SourceChangedError(name) from None
        job = store.create(
            fsutil.display_name(os.fsencode(name)),
            intake=_intake(name, current, 0, quarantine_code),
            ignore_capacity=ignore_capacity,
        )
        log.info("job %s received", job.doc_id)
        return self.resume(store, job)

    def resume(self, store: JobStore, job: Job) -> Job:
        """Carry a RECEIVED job without a hash through whatever steps remain.

        If a writer still has the input open, the job is left as it is (still
        RECEIVED, no hash) and the watcher retries it on a later poll.
        """
        intake = store.stage_result(job.doc_id, Stage.INTAKE)
        if intake is None:
            return store.fail(job, FailureKind.PERMANENT, "source_missing")
        gen = intake.get("gen", 0)
        # Recovered orphans have no inbox identity: only a finished copy counts.
        expected = Identity.from_dict(intake) if "dev" in intake else None
        quarantine = intake.get("quarantine")
        name = (
            os.fsdecode(bytes.fromhex(intake["inbox_name_hex"]))
            if "inbox_name_hex" in intake
            else None
        )
        gen_fd = self.open_input_dir(job.doc_id, gen, create=True)
        try:
            if fsutil.lstat_at(ORIGINAL, gen_fd) is not None:
                return self._finish(store, job, gen_fd)
            have_incoming = fsutil.lstat_at(INCOMING, gen_fd) is not None
            if not have_incoming and (expected is None or name is None):
                return store.fail(job, FailureKind.PERMANENT, "source_missing")
            try:
                if have_incoming:
                    code = self._adopt_incoming(gen_fd, expected, quarantine)
                else:
                    job, code = self._adopt_from_inbox(
                        store, job, name, gen_fd, expected, quarantine
                    )
            except SourceMissingError:
                return store.fail(job, FailureKind.PERMANENT, "source_missing")
            except fsutil.WriterActiveError:
                log.info("job %s waits for its input to settle", job.doc_id)
                return store.get(job.doc_id)
            if code is not None:
                # Make the moved input durable before the row says where it is.
                self._barrier(job.doc_id, gen_fd, INCOMING)
                log.info("job %s quarantined: %s", job.doc_id, code)
                return store.advance(job, State.QUARANTINED, code=code)
            return self._finish(store, job, gen_fd)
        finally:
            os.close(gen_fd)

    def _adopt_from_inbox(
        self,
        store: JobStore,
        job: Job,
        name: str,
        gen_fd: int,
        expected: Identity,
        quarantine: str | None,
    ) -> tuple[Job, str | None]:
        """Move the inbox entry to INCOMING and, unless quarantining, copy it.

        For a normal adoption the read lease is taken before the move and held
        until the copy is done, so no writer can be active at any point in
        between. Returns the (possibly updated) job and a quarantine code, or
        None once ORIGINAL exists.
        """
        current = fsutil.lstat_at(name, self.inbox_fd)
        if current is None or not current.same_file(expected):
            raise SourceMissingError(name)
        if quarantine or not current.is_regular:
            if current.is_regular:
                # Quarantined files are never copied: this is their only barrier.
                self._fsync_or_missing(name)
            self._move_to_incoming(name, gen_fd)
            return job, quarantine or "not_regular_file"
        try:
            fd = fsutil.open_regular(name, self.inbox_fd)
        except FileNotFoundError:
            raise SourceMissingError(name) from None
        try:
            if not Identity.of(os.fstat(fd)).same_file(expected):
                raise SourceMissingError(name)  # swapped between lstat and open
            with self._exclusion(fd) as lease:
                now = Identity.of(os.fstat(fd))
                intake = store.stage_result(job.doc_id, Stage.INTAKE)
                if not now.same_content(expected):
                    # Written to since registration (a writer came back): record
                    # the new state and wait for it to settle again, as the
                    # transfer gate would have.
                    intake = {**intake, **now.as_dict(), "changed_at": self.wall_clock()}
                    store.update_intake(job, intake)
                    raise fsutil.WriterActiveError
                changed_at = intake.get("changed_at")
                if changed_at is not None and self.wall_clock() - changed_at < self.stable_seconds:
                    raise fsutil.WriterActiveError
                # The printer's bytes must be durable before the entry leaves
                # the inbox durably.
                os.fsync(fd)
                self._move_to_incoming(name, gen_fd)
                moved = fsutil.lstat_at(INCOMING, gen_fd)
                if moved is None or not moved.same_file(Identity.of(os.fstat(fd))):
                    # The name was pointed at another file between our open and
                    # the rename: we moved that one. Keep it (never delete an
                    # input we did not copy) and let a person look.
                    return job, "changed_during_adoption"
                return job, self._copy(fd, gen_fd, expected, lease)
        finally:
            os.close(fd)

    def _adopt_incoming(
        self, gen_fd: int, expected: Identity | None, quarantine: str | None
    ) -> str | None:
        """Finish an adoption whose input was already moved (crash recovery)."""
        if quarantine:
            return quarantine
        incoming = fsutil.lstat_at(INCOMING, gen_fd)
        if incoming is None or not incoming.is_regular:
            return "not_regular_file"
        try:
            fd = fsutil.open_regular(INCOMING, gen_fd)
        except OSError:
            return "not_regular_file"
        try:
            with self._exclusion(fd) as lease:
                return self._copy(fd, gen_fd, expected, lease)
        finally:
            os.close(fd)

    def _exclusion(self, fd: int):
        return fsutil.ReadLease(fd) if self.require_no_writers else contextlib.nullcontext()

    def _fsync_or_missing(self, name: str) -> None:
        try:
            fsutil.fsync_file(name, self.inbox_fd)
        except FileNotFoundError:
            raise SourceMissingError(name) from None

    def _move_to_incoming(self, name: str, gen_fd: int) -> None:
        try:
            os.rename(name, INCOMING, src_dir_fd=self.inbox_fd, dst_dir_fd=gen_fd)
        except FileNotFoundError:
            # Deleted, or taken by another adopter, after the checks.
            raise SourceMissingError(name) from None
        os.fsync(self.inbox_fd)
        os.fsync(gen_fd)

    @staticmethod
    def _copy(
        fd: int, gen_fd: int, expected: Identity | None, lease: fsutil.ReadLease | None
    ) -> str | None:
        """Copy the open input into ORIGINAL; return a quarantine code instead if needed."""
        st = Identity.of(os.fstat(fd))
        if expected is None or not st.same_content(expected):
            return "changed_during_adoption"
        if st.nlink > 1:
            # Another name still points at this inode, possibly in the share.
            return "multiple_links"
        try:
            os.unlink(_TMP, dir_fd=gen_fd)
        except FileNotFoundError:
            pass
        _, stable = fsutil.private_copy(fd, _TMP, gen_fd)
        if not stable or (lease is not None and not lease.intact()):
            # Written to, or a writer opened it and is waiting on our lease.
            os.unlink(_TMP, dir_fd=gen_fd)
            return "changed_during_adoption" if not stable else "writer_during_adoption"
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
        entry = fsutil.lstat_at(name, gen_fd)
        if entry is not None and entry.is_regular:
            # Errors propagate: the job stays resumable instead of committing
            # over a file whose bytes may not be durable.
            fsutil.fsync_file(name, gen_fd)
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
        """Finish or repair adoptions interrupted by a crash. Returns touched doc ids.

        A job that hits an OS error (e.g. a full disk) is left RECEIVED for the
        watcher's per-poll retry; the others still get recovered.
        """
        touched = []
        for job in store.jobs_in(State.RECEIVED):
            if job.source_hash is None:
                touched.append(job.doc_id)
                try:
                    self.resume(store, job)
                except OSError as exc:
                    log.warning("recovery error %s", errno.errorcode.get(exc.errno, "unknown"))
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
        events: list[tuple[str, int, int]] = []
        reliable = self.inotify is not None
        if self.inotify is not None:
            events = [(os.fsdecode(n), mask, c) for n, mask, c in self.inotify.read()]
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
            elif job.source_hash is not None:
                report.adopted.append(job.doc_id)
            # else: registered, waiting for a writer; resumed on a later poll
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
        # Recovery needs disk like any adoption; without it, polling retries
        # the unfinished jobs once space is back.
        if disk_has_room(self.spool.spool_path, self.min_free_bytes, self.disk_usage):
            try:
                self.spool.reconcile(self.store)
            except OSError as exc:
                log.warning("recovery error %s", errno.errorcode.get(exc.errno, "unknown"))
        while not stop.is_set():
            self.poll_once()
            if self.inotify is not None:
                select.select([self.inotify], [], [], interval)
            else:
                stop.wait(interval)
