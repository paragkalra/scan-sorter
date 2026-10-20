"""Durable job store: every scan is a persisted state machine (docs/PLAN.md, "Job lifecycle").

A job's state names the last stage that finished, so after a crash the next
action is derived from the state alone. Every write is a compare-and-set on
the job's revision, which increases with each change: work based on an older
view of the job (even one in the same state, e.g. after a retry or a
replaced input) is rejected instead of silently overwriting newer data.

Advancing into a state requires the data that state promises (a stage result,
the output hash, the reserved destination), committed in the same transaction.

The database never stores document text in transition codes, and errors never
echo rejected input back.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
import unicodedata
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any


class State(StrEnum):
    RECEIVED = "received"
    VALIDATED = "validated"
    OCR_DONE = "ocr_done"
    CLASSIFIED = "classified"
    NEEDS_REVIEW = "needs_review"
    READY = "ready"
    UPLOADING = "uploading"
    VERIFIED = "verified"
    COMPLETE = "complete"
    QUARANTINED = "quarantined"
    FAILED = "failed"
    DISCARDED = "discarded"


class FailureKind(StrEnum):
    RETRYABLE = "retryable"
    PERMANENT = "permanent"


class Stage(StrEnum):
    INTAKE = "intake"  # recorded by create(): where the file came from
    VALIDATE = "validate"
    OCR = "ocr"
    CLASSIFY = "classify"
    VERIFY = "verify"


# States in which the pipeline still owes the job work. Review, quarantine and
# failure wait for a person (or a retry), so recovery does not pick them up.
ACTIVE_STATES = frozenset(
    {
        State.RECEIVED,
        State.VALIDATED,
        State.OCR_DONE,
        State.CLASSIFIED,
        State.READY,
        State.UPLOADING,
        State.VERIFIED,
    }
)
TERMINAL_STATES = frozenset({State.COMPLETE, State.DISCARDED})

# Edges usable through advance(). FAILED is entered through fail() and left
# through retry() or discard(). QUARANTINED -> RECEIVED happens only through
# replace(), which also clears everything derived from the old input.
TRANSITIONS: Mapping[State, frozenset[State]] = {
    State.RECEIVED: frozenset({State.VALIDATED, State.QUARANTINED}),
    State.VALIDATED: frozenset({State.OCR_DONE, State.QUARANTINED}),
    # Review is only offered once OCR has run (e.g. it found no text).
    State.OCR_DONE: frozenset({State.CLASSIFIED, State.NEEDS_REVIEW}),
    State.CLASSIFIED: frozenset({State.READY, State.NEEDS_REVIEW}),
    State.NEEDS_REVIEW: frozenset({State.CLASSIFIED}),
    State.READY: frozenset({State.UPLOADING}),
    # UPLOADING -> READY: the remote object did not match, so upload again.
    State.UPLOADING: frozenset({State.VERIFIED, State.READY}),
    State.VERIFIED: frozenset({State.COMPLETE}),
    State.QUARANTINED: frozenset(),
    State.FAILED: frozenset(),
    State.COMPLETE: frozenset(),
    State.DISCARDED: frozenset(),
}

# Stage result that must exist (supplied now or already stored) to enter a state.
REQUIRED_RESULT: Mapping[State, Stage] = {
    State.VALIDATED: Stage.VALIDATE,
    State.OCR_DONE: Stage.OCR,
    State.CLASSIFIED: Stage.CLASSIFY,
    State.VERIFIED: Stage.VERIFY,
}
# Edges where a stored result is not enough: a review approval is a new decision.
FRESH_RESULT_REQUIRED = frozenset({(State.NEEDS_REVIEW, State.CLASSIFIED)})
# Edges that must say why they happened.
CODE_REQUIRED = frozenset(
    {
        (State.RECEIVED, State.QUARANTINED),
        (State.VALIDATED, State.QUARANTINED),
        (State.OCR_DONE, State.NEEDS_REVIEW),
        (State.CLASSIFIED, State.NEEDS_REVIEW),
        (State.UPLOADING, State.READY),
    }
)

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE jobs (
    doc_id        TEXT PRIMARY KEY,
    revision      INTEGER NOT NULL,
    state         TEXT NOT NULL,
    source_name   TEXT NOT NULL,
    source_hash   TEXT,
    output_hash   TEXT,
    dest_path     TEXT,
    dest_key      TEXT UNIQUE,
    remote_id     TEXT,
    upload_started_at REAL,
    failure_kind  TEXT,
    failure_code  TEXT,
    failed_from   TEXT,
    attempts      INTEGER NOT NULL DEFAULT 0,
    created_at    REAL NOT NULL,
    updated_at    REAL NOT NULL
);
CREATE INDEX jobs_state ON jobs(state);
CREATE INDEX jobs_source_hash ON jobs(source_hash);

CREATE TABLE stage_results (
    doc_id       TEXT NOT NULL REFERENCES jobs(doc_id),
    stage        TEXT NOT NULL,
    data         TEXT NOT NULL,
    recorded_at  REAL NOT NULL,
    PRIMARY KEY (doc_id, stage)
);

CREATE TABLE transitions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    doc_id      TEXT NOT NULL REFERENCES jobs(doc_id),
    from_state  TEXT,
    to_state    TEXT NOT NULL,
    code        TEXT,
    at          REAL NOT NULL
);
CREATE INDEX transitions_doc ON transitions(doc_id);
"""

# Columns describing one particular input file and its filed output. They are
# reset when a quarantined job's input is replaced.
_INPUT_COLUMNS = (
    "source_hash",
    "output_hash",
    "dest_path",
    "dest_key",
    "remote_id",
    "upload_started_at",
)
_DB_FILE_MODE = 0o600


class TransitionError(Exception):
    """The requested change is not allowed by the state machine."""


class StaleJobError(Exception):
    """The job changed since the caller read it (another process got there first)."""


class JobNotFoundError(KeyError):
    pass


class QueueFullError(Exception):
    pass


class DestinationTakenError(Exception):
    """Another job already reserved this destination path."""


@dataclass(frozen=True)
class Job:
    doc_id: str
    revision: int
    state: State
    source_name: str
    source_hash: str | None
    output_hash: str | None
    dest_path: str | None
    remote_id: str | None
    upload_started_at: float | None
    failure_kind: FailureKind | None
    failure_code: str | None
    failed_from: State | None
    attempts: int
    created_at: float
    updated_at: float

    @classmethod
    def _from_row(cls, row: sqlite3.Row) -> Job:
        return cls(
            doc_id=row["doc_id"],
            revision=row["revision"],
            state=State(row["state"]),
            source_name=row["source_name"],
            source_hash=row["source_hash"],
            output_hash=row["output_hash"],
            dest_path=row["dest_path"],
            remote_id=row["remote_id"],
            upload_started_at=row["upload_started_at"],
            failure_kind=FailureKind(row["failure_kind"]) if row["failure_kind"] else None,
            failure_code=row["failure_code"],
            failed_from=State(row["failed_from"]) if row["failed_from"] else None,
            attempts=row["attempts"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


def _check_code(code: str | None) -> None:
    # Codes are short identifiers like "encrypted_pdf"; refusing anything else
    # keeps document text and raw exception messages out of the database. The
    # message deliberately does not repeat the rejected value.
    if code is None:
        return
    if not (0 < len(code) <= 64) or not all(
        c.isascii() and (c.isalnum() or c in "_-.") for c in code
    ):
        raise ValueError("invalid code: use a short ASCII identifier")


def _check_sha256(value: str) -> None:
    if len(value) != 64 or not all(c in "0123456789abcdef" for c in value):
        raise ValueError("expected a lowercase hex SHA-256")


def destination_key(path: str) -> str:
    """Comparison key for destination paths: NFC-normalized and case-folded,
    so names that collide on case-insensitive or normalizing storage collide here."""
    return unicodedata.normalize("NFC", unicodedata.normalize("NFC", path).casefold())


def _secure_db_files(path: Path) -> None:
    # Create the database 0600 before SQLite touches it. SQLite gives the -wal
    # and -shm sidecars the database file's mode, so they inherit this too.
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, _DB_FILE_MODE)
    try:
        os.fchmod(fd, _DB_FILE_MODE)
    finally:
        os.close(fd)
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = path.with_name(path.name + suffix)
        try:
            fd = os.open(sidecar, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            continue
        try:
            os.fchmod(fd, _DB_FILE_MODE)
        finally:
            os.close(fd)


class JobStore:
    """SQLite-backed job store. Safe to open from several processes at once."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_active: int | None = None,
        clock=time.time,
        busy_timeout_ms: int = 10_000,
    ):
        """max_active bounds how many jobs may be in ACTIVE_STATES at once. Every
        way into an active state (intake, retry, review approval, replacement)
        checks it inside its write transaction and raises QueueFullError, leaving
        the job where it was, when there is no room."""
        self._clock = clock
        self._max_active = max_active
        path = Path(path)
        _secure_db_files(path)
        # isolation_level=None: we issue BEGIN IMMEDIATE ourselves so every
        # write takes the lock up front instead of failing on upgrade.
        self._db = sqlite3.connect(str(path), isolation_level=None, timeout=busy_timeout_ms / 1000)
        try:
            self._db.row_factory = sqlite3.Row
            self._enable_wal(busy_timeout_ms / 1000)
            # FULL: a committed transition survives power loss, not just a crash.
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA foreign_keys=ON")
            self._migrate()
        except BaseException:
            self._db.close()
            raise

    def _enable_wal(self, timeout_s: float) -> None:
        # Switching to WAL needs an exclusive moment and ignores the busy
        # timeout, so processes opening a fresh file together can see
        # "database is locked". Retry with backoff up to the busy timeout.
        deadline = time.monotonic() + timeout_s
        delay = 0.005
        while True:
            try:
                mode = self._db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc) or time.monotonic() >= deadline:
                    raise
            else:
                if mode.lower() == "wal":
                    return
                raise RuntimeError(f"could not enable WAL (journal_mode={mode})")
            time.sleep(delay)
            delay = min(delay * 2, 0.2)

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> JobStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            yield self._db
            self._db.execute("COMMIT")
        except BaseException:
            # COMMIT itself can fail and leave the transaction open; never
            # keep holding the write lock after an error.
            if self._db.in_transaction:
                self._db.execute("ROLLBACK")
            raise

    def _migrate(self) -> None:
        with self._write() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"database schema v{version} is newer than this program (v{SCHEMA_VERSION})"
                )
            if version == 0:
                for statement in _SCHEMA.split(";"):
                    if statement.strip():
                        db.execute(statement)
                db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    # -- reads ---------------------------------------------------------------

    def get(self, doc_id: str) -> Job:
        row = self._db.execute("SELECT * FROM jobs WHERE doc_id=?", (doc_id,)).fetchone()
        if row is None:
            raise JobNotFoundError(doc_id)
        return Job._from_row(row)

    def jobs_in(self, *states: State) -> list[Job]:
        marks = ",".join("?" * len(states))
        rows = self._db.execute(
            f"SELECT * FROM jobs WHERE state IN ({marks}) ORDER BY created_at, doc_id",  # noqa: S608
            [s.value for s in states],
        ).fetchall()
        return [Job._from_row(r) for r in rows]

    def recoverable(self) -> list[Job]:
        """Jobs the pipeline must resume after a restart, oldest first."""
        return self.jobs_in(*ACTIVE_STATES)

    def count_active(self) -> int:
        return self._count_active(self._db)

    @staticmethod
    def _count_active(db: sqlite3.Connection) -> int:
        marks = ",".join("?" * len(ACTIVE_STATES))
        return db.execute(
            f"SELECT COUNT(*) FROM jobs WHERE state IN ({marks})",  # noqa: S608
            [s.value for s in ACTIVE_STATES],
        ).fetchone()[0]

    def find_by_source_hash(self, source_hash: str) -> list[Job]:
        rows = self._db.execute(
            "SELECT * FROM jobs WHERE source_hash=? ORDER BY created_at, doc_id", (source_hash,)
        ).fetchall()
        return [Job._from_row(r) for r in rows]

    def stage_result(self, doc_id: str, stage: Stage) -> dict[str, Any] | None:
        row = self._db.execute(
            "SELECT data FROM stage_results WHERE doc_id=? AND stage=?",
            (doc_id, Stage(stage).value),
        ).fetchone()
        return None if row is None else json.loads(row["data"])

    def history(self, doc_id: str) -> list[tuple[State | None, State, str | None]]:
        rows = self._db.execute(
            "SELECT from_state, to_state, code FROM transitions WHERE doc_id=? ORDER BY id",
            (doc_id,),
        ).fetchall()
        return [
            (State(r["from_state"]) if r["from_state"] else None, State(r["to_state"]), r["code"])
            for r in rows
        ]

    # -- writes --------------------------------------------------------------

    def create(
        self,
        source_name: str,
        *,
        doc_id: str | None = None,
        intake: Mapping[str, Any] | None = None,
        ignore_capacity: bool = False,
    ) -> Job:
        """Register a new job in RECEIVED. Committed before the file is moved.

        `intake` (the inbox entry's identity) is stored as the INTAKE stage
        result in the same transaction, so crash recovery can find the file.
        ignore_capacity is for recovery of files already in the spool, which
        must be registered whatever the queue holds.
        """
        if doc_id is None:
            doc_id = uuid.uuid4().hex
        elif not isinstance(doc_id, str) or len(doc_id) != 32 or doc_id != doc_id.lower():
            raise ValueError("doc_id must be 32 lowercase hex characters")
        else:
            try:
                if uuid.UUID(hex=doc_id).hex != doc_id:
                    raise ValueError
            except ValueError:
                raise ValueError("doc_id must be 32 lowercase hex characters") from None
        now = self._clock()
        with self._write() as db:
            if not ignore_capacity:
                self._check_capacity(db)
            db.execute(
                "INSERT INTO jobs (doc_id, revision, state, source_name, created_at, updated_at)"
                " VALUES (?,1,?,?,?,?)",
                (doc_id, State.RECEIVED.value, source_name, now, now),
            )
            if intake is not None:
                db.execute(
                    "INSERT INTO stage_results (doc_id, stage, data, recorded_at) VALUES (?,?,?,?)",
                    (doc_id, Stage.INTAKE.value, json.dumps(intake, sort_keys=True), now),
                )
            self._log(db, doc_id, None, State.RECEIVED, None, now)
            created = self._read(db, doc_id)
        return created

    def set_source_hash(self, job: Job, source_hash: str) -> Job:
        _check_sha256(source_hash)
        if job.state is not State.RECEIVED:
            raise TransitionError("source hash is recorded at intake")
        with self._write() as db:
            updated = self._cas(db, job, source_hash=source_hash)
        return updated

    def update_intake(self, job: Job, intake: Mapping[str, Any]) -> Job:
        """Re-record where a not-yet-adopted input is (it grew before adoption)."""
        if job.state is not State.RECEIVED or job.source_hash is not None:
            raise TransitionError("intake can only change before the input is adopted")
        now = self._clock()
        with self._write() as db:
            updated = self._cas(db, job)
            db.execute(
                "INSERT INTO stage_results (doc_id, stage, data, recorded_at) VALUES (?,?,?,?)"
                " ON CONFLICT(doc_id, stage) DO UPDATE"
                " SET data=excluded.data, recorded_at=excluded.recorded_at",
                (job.doc_id, Stage.INTAKE.value, json.dumps(intake, sort_keys=True), now),
            )
        return updated

    def set_output_hash(self, job: Job, output_hash: str) -> Job:
        _check_sha256(output_hash)
        if job.state is not State.CLASSIFIED:
            raise TransitionError("output hash is recorded before the job is ready")
        with self._write() as db:
            updated = self._cas(db, job, output_hash=output_hash)
        return updated

    def reserve_destination(self, job: Job, dest_path: str) -> Job:
        """Reserve a destination path for this job before it is uploaded.

        Paths are sanitized by the caller; the store guarantees no two jobs hold
        paths that collide after normalization and case folding.
        """
        if job.state is not State.CLASSIFIED:
            raise TransitionError("destinations are reserved before the job is ready")
        if not dest_path or len(dest_path) > 1024:
            raise ValueError("invalid destination path")
        with self._write() as db:
            try:
                updated = self._cas(
                    db, job, dest_path=dest_path, dest_key=destination_key(dest_path)
                )
            except sqlite3.IntegrityError:
                raise DestinationTakenError from None
        return updated

    def set_remote_id(self, job: Job, remote_id: str) -> Job:
        if job.state is not State.UPLOADING:
            raise TransitionError("remote id is recorded while uploading")
        if not remote_id or len(remote_id) > 512:
            raise ValueError("invalid remote id")
        with self._write() as db:
            updated = self._cas(db, job, remote_id=remote_id)
        return updated

    def advance(
        self,
        job: Job,
        to: State,
        *,
        result: tuple[Stage, Mapping[str, Any]] | None = None,
        code: str | None = None,
    ) -> Job:
        """Move a job to `to`, storing a stage result in the same transaction.

        A crash can never leave a job advanced without the data its state
        promises, and work based on a stale read of the job is rejected.
        """
        frm = job.state
        if to not in TRANSITIONS[frm]:
            raise TransitionError(f"{frm} -> {to} is not allowed")
        _check_code(code)
        if (frm, to) in CODE_REQUIRED and code is None:
            raise TransitionError(f"{frm} -> {to} needs a reason code")
        required = REQUIRED_RESULT.get(to)
        if result is not None:
            stage = Stage(result[0])
            if stage is not required:
                raise TransitionError(f"entering {to} records {required}, not {stage}")
        elif required is not None and (frm, to) in FRESH_RESULT_REQUIRED:
            raise TransitionError(f"{frm} -> {to} needs a new {required} result")
        if to is State.READY and (job.output_hash is None or job.dest_path is None):
            raise TransitionError("ready needs an output hash and a reserved destination")
        now = self._clock()
        columns: dict[str, str | None] = {"state": to.value}
        if to is State.NEEDS_REVIEW:
            # The category may change in review: release the old destination.
            # (Review is only reachable before any upload has started.)
            columns.update(output_hash=None, dest_path=None, dest_key=None)
        if to is State.UPLOADING and job.upload_started_at is None:
            # Never cleared: from now on an object may exist at the destination.
            columns["upload_started_at"] = now
        with self._write() as db:
            if frm not in ACTIVE_STATES and to in ACTIVE_STATES:
                self._check_capacity(db)
            updated = self._cas(db, job, **columns)
            if result is not None:
                db.execute(
                    "INSERT INTO stage_results (doc_id, stage, data, recorded_at) VALUES (?,?,?,?)"
                    " ON CONFLICT(doc_id, stage) DO UPDATE"
                    " SET data=excluded.data, recorded_at=excluded.recorded_at",
                    (job.doc_id, required.value, json.dumps(result[1], sort_keys=True), now),
                )
            elif (
                required is not None
                and not db.execute(
                    "SELECT 1 FROM stage_results WHERE doc_id=? AND stage=?",
                    (job.doc_id, required.value),
                ).fetchone()
            ):
                raise TransitionError(f"entering {to} needs a {required} result")
            self._log(db, job.doc_id, frm, to, code, now)
        return updated

    def fail(self, job: Job, kind: FailureKind, code: str) -> Job:
        """Park an active job as FAILED, remembering where to resume on retry."""
        if job.state not in ACTIVE_STATES:
            raise TransitionError(f"cannot fail a job in {job.state}")
        _check_code(code)
        now = self._clock()
        with self._write() as db:
            updated = self._cas(
                db,
                job,
                attempts_increment=True,
                state=State.FAILED.value,
                failure_kind=FailureKind(kind).value,
                failure_code=code,
                failed_from=job.state.value,
            )
            self._log(db, job.doc_id, job.state, State.FAILED, code, now)
        return updated

    def retry(self, job: Job) -> Job:
        """Return a retryable failure to the state it failed from."""
        if job.state is not State.FAILED:
            raise TransitionError(f"job is {job.state}, not failed")
        if job.failure_kind is not FailureKind.RETRYABLE or job.failed_from is None:
            raise TransitionError("permanent failures cannot be retried")
        now = self._clock()
        with self._write() as db:
            self._check_capacity(db)
            updated = self._cas(
                db,
                job,
                state=job.failed_from.value,
                failure_kind=None,
                failure_code=None,
                failed_from=None,
            )
            self._log(db, job.doc_id, State.FAILED, job.failed_from, "retry", now)
        return updated

    def discard(self, job: Job) -> Job:
        """Give up on a job awaiting a person (review, quarantine, or failure)."""
        if job.state not in (State.NEEDS_REVIEW, State.QUARANTINED, State.FAILED):
            raise TransitionError(f"cannot discard a job in {job.state}")
        now = self._clock()
        # Free the destination for other jobs, unless an upload may already have
        # put an object there: then the name stays reserved until reconciliation
        # (issue #7) confirms the remote path is empty.
        may_be_uploaded = job.upload_started_at is not None or job.remote_id is not None
        columns = {} if may_be_uploaded else {"dest_key": None}
        with self._write() as db:
            updated = self._cas(db, job, state=State.DISCARDED.value, **columns)
            self._log(db, job.doc_id, job.state, State.DISCARDED, "discard", now)
        return updated

    def replace(
        self, job: Job, source_name: str, *, intake: Mapping[str, Any] | None = None
    ) -> Job:
        """Restart a quarantined job with a replacement input file.

        Everything derived from the old input (hashes, destination, stage
        results) is cleared in the same transaction, so the replacement can
        never be confused with the document it replaces.
        """
        if job.state is not State.QUARANTINED:
            raise TransitionError("only quarantined jobs take a replacement input")
        now = self._clock()
        with self._write() as db:
            self._check_capacity(db)
            updated = self._cas(
                db,
                job,
                state=State.RECEIVED.value,
                source_name=source_name,
                **dict.fromkeys(_INPUT_COLUMNS),
            )
            db.execute("DELETE FROM stage_results WHERE doc_id=?", (job.doc_id,))
            if intake is not None:
                db.execute(
                    "INSERT INTO stage_results (doc_id, stage, data, recorded_at) VALUES (?,?,?,?)",
                    (job.doc_id, Stage.INTAKE.value, json.dumps(intake, sort_keys=True), now),
                )
            self._log(db, job.doc_id, State.QUARANTINED, State.RECEIVED, "replaced", now)
        return updated

    def _cas(
        self,
        db: sqlite3.Connection,
        job: Job,
        *,
        attempts_increment: bool = False,
        **columns: str | None,
    ) -> Job:
        sets = "".join(f", {name}=?" for name in columns)
        bump = ", attempts=attempts+1" if attempts_increment else ""
        cur = db.execute(
            f"UPDATE jobs SET revision=revision+1, updated_at=?{sets}{bump}"  # noqa: S608
            " WHERE doc_id=? AND revision=? AND state=?",
            [self._clock(), *columns.values(), job.doc_id, job.revision, job.state.value],
        )
        if cur.rowcount == 1:
            return self._read(db, job.doc_id)
        row = db.execute("SELECT 1 FROM jobs WHERE doc_id=?", (job.doc_id,)).fetchone()
        if row is None:
            raise JobNotFoundError(job.doc_id)
        raise StaleJobError(f"job {job.doc_id} changed since revision {job.revision}")

    @staticmethod
    def _read(db: sqlite3.Connection, doc_id: str) -> Job:
        # Snapshot taken inside the write transaction: the revision returned to
        # the caller is exactly the one this write produced.
        return Job._from_row(db.execute("SELECT * FROM jobs WHERE doc_id=?", (doc_id,)).fetchone())

    def _check_capacity(self, db: sqlite3.Connection) -> None:
        if self._max_active is not None and self._count_active(db) >= self._max_active:
            raise QueueFullError

    @staticmethod
    def _log(
        db: sqlite3.Connection,
        doc_id: str,
        from_state: State | None,
        to_state: State,
        code: str | None,
        now: float,
    ) -> None:
        db.execute(
            "INSERT INTO transitions (doc_id, from_state, to_state, code, at) VALUES (?,?,?,?,?)",
            (doc_id, from_state.value if from_state else None, to_state.value, code, now),
        )
