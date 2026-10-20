"""Durable job store: every scan is a persisted state machine (docs/PLAN.md, "Job lifecycle").

A job's state names the last stage that finished, so after a crash the next
action is derived from the state alone. Every state change is a compare-and-set
inside a write transaction: if another process already moved the job, the
change is rejected instead of silently overwriting it.

The database never stores document text in transition details; those are
short machine-readable codes only.
"""

from __future__ import annotations

import json
import sqlite3
import time
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

# Normal forward edges. FAILED is reachable from every active state through
# fail(), and leaves only through retry() (retryable) or discard().
TRANSITIONS: Mapping[State, frozenset[State]] = {
    State.RECEIVED: frozenset({State.VALIDATED, State.QUARANTINED}),
    State.VALIDATED: frozenset({State.OCR_DONE, State.NEEDS_REVIEW, State.QUARANTINED}),
    State.OCR_DONE: frozenset({State.CLASSIFIED, State.NEEDS_REVIEW}),
    State.CLASSIFIED: frozenset({State.READY, State.NEEDS_REVIEW}),
    # Approving a review records the category, then the job continues normally.
    State.NEEDS_REVIEW: frozenset({State.CLASSIFIED, State.DISCARDED}),
    State.READY: frozenset({State.UPLOADING}),
    # UPLOADING -> READY: the remote object did not match, so upload again.
    State.UPLOADING: frozenset({State.VERIFIED, State.READY}),
    State.VERIFIED: frozenset({State.COMPLETE}),
    # A quarantined input is never repaired by metadata edits: a replacement
    # file re-enters at RECEIVED and must pass validation again.
    State.QUARANTINED: frozenset({State.RECEIVED, State.DISCARDED}),
    State.FAILED: frozenset(),
    State.COMPLETE: frozenset(),
    State.DISCARDED: frozenset(),
}

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE jobs (
    doc_id        TEXT PRIMARY KEY,
    state         TEXT NOT NULL,
    source_name   TEXT NOT NULL,
    source_hash   TEXT,
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


class TransitionError(Exception):
    """The requested state change is not allowed by the state machine."""


class StaleStateError(Exception):
    """The job was not in the expected state (another process moved it first)."""


class JobNotFoundError(KeyError):
    pass


@dataclass(frozen=True)
class Job:
    doc_id: str
    state: State
    source_name: str
    source_hash: str | None
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
            state=State(row["state"]),
            source_name=row["source_name"],
            source_hash=row["source_hash"],
            failure_kind=FailureKind(row["failure_kind"]) if row["failure_kind"] else None,
            failure_code=row["failure_code"],
            failed_from=State(row["failed_from"]) if row["failed_from"] else None,
            attempts=row["attempts"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


def _check_code(code: str | None) -> None:
    # Codes are short identifiers like "encrypted_pdf"; refusing anything else
    # keeps document text and raw exception messages out of the database.
    if code is None:
        return
    if not (0 < len(code) <= 64) or not all(c.isalnum() or c in "_-." for c in code):
        raise ValueError(f"invalid code {code!r}: use a short identifier")


class JobStore:
    """SQLite-backed job store. Safe to open from several processes at once."""

    def __init__(self, path: str | Path, *, clock=time.time, busy_timeout_ms: int = 10_000):
        self._clock = clock
        # isolation_level=None: we issue BEGIN IMMEDIATE ourselves so every
        # write takes the lock up front instead of failing on upgrade.
        self._db = sqlite3.connect(str(path), isolation_level=None, timeout=busy_timeout_ms / 1000)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        # FULL: a committed transition survives power loss, not just a crash.
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._migrate()

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
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        self._db.execute("COMMIT")

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
        marks = ",".join("?" * len(ACTIVE_STATES))
        return self._db.execute(
            f"SELECT COUNT(*) FROM jobs WHERE state IN ({marks})",  # noqa: S608
            [s.value for s in ACTIVE_STATES],
        ).fetchone()[0]

    def find_by_source_hash(self, source_hash: str) -> list[Job]:
        rows = self._db.execute(
            "SELECT * FROM jobs WHERE source_hash=? ORDER BY created_at, doc_id", (source_hash,)
        ).fetchall()
        return [Job._from_row(r) for r in rows]

    def stage_result(self, doc_id: str, stage: str) -> dict[str, Any] | None:
        row = self._db.execute(
            "SELECT data FROM stage_results WHERE doc_id=? AND stage=?", (doc_id, stage)
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

    def create(self, source_name: str, *, doc_id: str | None = None) -> Job:
        """Register a new job in RECEIVED. Committed before the file is moved."""
        doc_id = doc_id or uuid.uuid4().hex
        uuid.UUID(hex=doc_id)  # reject malformed ids; they become path components later
        now = self._clock()
        with self._write() as db:
            db.execute(
                "INSERT INTO jobs (doc_id, state, source_name, created_at, updated_at)"
                " VALUES (?,?,?,?,?)",
                (doc_id, State.RECEIVED.value, source_name, now, now),
            )
            self._log(db, doc_id, None, State.RECEIVED, None, now)
        return self.get(doc_id)

    def set_source_hash(self, doc_id: str, source_hash: str) -> None:
        if len(source_hash) != 64 or not all(c in "0123456789abcdef" for c in source_hash):
            raise ValueError("source_hash must be a lowercase hex SHA-256")
        with self._write() as db:
            cur = db.execute(
                "UPDATE jobs SET source_hash=?, updated_at=? WHERE doc_id=?",
                (source_hash, self._clock(), doc_id),
            )
            if cur.rowcount == 0:
                raise JobNotFoundError(doc_id)

    def advance(
        self,
        doc_id: str,
        expected: State,
        to: State,
        *,
        result: tuple[str, Mapping[str, Any]] | None = None,
        code: str | None = None,
    ) -> Job:
        """Move a job from `expected` to `to`, storing a stage result atomically.

        The stage result and the state change commit together, so a crash can
        never leave a job advanced without the data its next stage needs.
        """
        if to not in TRANSITIONS[expected]:
            raise TransitionError(f"{expected} -> {to} is not allowed")
        _check_code(code)
        now = self._clock()
        with self._write() as db:
            self._cas(db, doc_id, expected, now, state=to.value)
            if result is not None:
                stage, data = result
                db.execute(
                    "INSERT INTO stage_results (doc_id, stage, data, recorded_at) VALUES (?,?,?,?)"
                    " ON CONFLICT(doc_id, stage) DO UPDATE"
                    " SET data=excluded.data, recorded_at=excluded.recorded_at",
                    (doc_id, stage, json.dumps(data, sort_keys=True), now),
                )
            self._log(db, doc_id, expected, to, code, now)
        return self.get(doc_id)

    def fail(self, doc_id: str, expected: State, kind: FailureKind, code: str) -> Job:
        """Park an active job as FAILED, remembering where to resume on retry."""
        if expected not in ACTIVE_STATES:
            raise TransitionError(f"cannot fail a job in {expected}")
        _check_code(code)
        now = self._clock()
        with self._write() as db:
            self._cas(
                db,
                doc_id,
                expected,
                now,
                state=State.FAILED.value,
                failure_kind=kind.value,
                failure_code=code,
                failed_from=expected.value,
                attempts_increment=True,
            )
            self._log(db, doc_id, expected, State.FAILED, code, now)
        return self.get(doc_id)

    def retry(self, doc_id: str) -> Job:
        """Return a retryable failure to the state it failed from."""
        now = self._clock()
        with self._write() as db:
            # Read inside the write lock so failed_from cannot change under us.
            row = db.execute("SELECT * FROM jobs WHERE doc_id=?", (doc_id,)).fetchone()
            if row is None:
                raise JobNotFoundError(doc_id)
            job = Job._from_row(row)
            if job.state is not State.FAILED:
                raise TransitionError(f"job is {job.state}, not failed")
            if job.failure_kind is not FailureKind.RETRYABLE or job.failed_from is None:
                raise TransitionError("permanent failures cannot be retried")
            self._cas(
                db,
                doc_id,
                State.FAILED,
                now,
                state=job.failed_from.value,
                failure_kind=None,
                failure_code=None,
                failed_from=None,
            )
            self._log(db, doc_id, State.FAILED, job.failed_from, "retry", now)
        return self.get(doc_id)

    def discard(self, doc_id: str, expected: State) -> Job:
        """Give up on a job awaiting a person (review, quarantine, or failure)."""
        if expected not in (State.NEEDS_REVIEW, State.QUARANTINED, State.FAILED):
            raise TransitionError(f"cannot discard a job in {expected}")
        now = self._clock()
        with self._write() as db:
            self._cas(db, doc_id, expected, now, state=State.DISCARDED.value)
            self._log(db, doc_id, expected, State.DISCARDED, "discard", now)
        return self.get(doc_id)

    def _cas(
        self,
        db: sqlite3.Connection,
        doc_id: str,
        expected: State,
        now: float,
        *,
        attempts_increment: bool = False,
        **columns: str | None,
    ) -> None:
        sets = ", ".join(f"{name}=?" for name in columns)
        bump = ", attempts=attempts+1" if attempts_increment else ""
        cur = db.execute(
            f"UPDATE jobs SET {sets}, updated_at=?{bump} WHERE doc_id=? AND state=?",  # noqa: S608
            [*columns.values(), now, doc_id, expected.value],
        )
        if cur.rowcount == 1:
            return
        row = db.execute("SELECT state FROM jobs WHERE doc_id=?", (doc_id,)).fetchone()
        if row is None:
            raise JobNotFoundError(doc_id)
        raise StaleStateError(f"job {doc_id} is {row['state']}, expected {expected}")

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
