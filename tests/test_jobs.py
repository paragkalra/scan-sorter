import multiprocessing
import os
import sqlite3
import stat

import pytest

from scan_sorter.jobs import (
    ACTIVE_STATES,
    SCHEMA_VERSION,
    TRANSITIONS,
    DestinationTakenError,
    FailureKind,
    JobNotFoundError,
    JobStore,
    QueueFullError,
    Stage,
    StaleJobError,
    State,
    TransitionError,
)

HAPPY_PATH = [
    State.VALIDATED,
    State.OCR_DONE,
    State.CLASSIFIED,
    State.READY,
    State.UPLOADING,
    State.VERIFIED,
    State.COMPLETE,
]

# Forward walk from RECEIVED to each state reachable through advance().
PATHS = {
    State.RECEIVED: [],
    **{s: HAPPY_PATH[: i + 1] for i, s in enumerate(HAPPY_PATH)},
    State.NEEDS_REVIEW: [State.VALIDATED, State.OCR_DONE, State.NEEDS_REVIEW],
    State.QUARANTINED: [State.QUARANTINED],
}

SHA = "a" * 64
OUT_SHA = "b" * 64


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "jobs.sqlite"


@pytest.fixture
def store(db_path):
    with JobStore(db_path) as s:
        yield s


def step(store, job, to):
    """Advance one edge, supplying exactly what that edge requires."""
    if to is State.VALIDATED:
        return store.advance(job, to, result=(Stage.VALIDATE, {"pages": 1}))
    if to is State.OCR_DONE:
        return store.advance(job, to, result=(Stage.OCR, {"chars": 10}))
    if to is State.CLASSIFIED:
        return store.advance(job, to, result=(Stage.CLASSIFY, {"category": "bills"}))
    if to is State.READY and job.state is State.CLASSIFIED:
        job = store.set_output_hash(job, OUT_SHA)
        job = store.reserve_destination(job, f"Bills/2026/{job.doc_id}.pdf")
        return store.advance(job, to)
    if to is State.VERIFIED:
        return store.advance(job, to, result=(Stage.VERIFY, {"match": True}))
    if to in (State.NEEDS_REVIEW, State.QUARANTINED) or (job.state, to) == (
        State.UPLOADING,
        State.READY,
    ):
        return store.advance(job, to, code="reason")
    return store.advance(job, to)


def walk(store, job, path):
    for nxt in path:
        job = step(store, job, nxt)
    return job


def new(store, state=State.RECEIVED, name="scan.pdf"):
    return walk(store, store.create(name), PATHS[state])


# -- creation ------------------------------------------------------------------


def test_create_starts_in_received_with_history(store):
    job = store.create("scan001.pdf")
    assert (job.state, job.revision) == (State.RECEIVED, 1)
    assert len(job.doc_id) == 32
    assert store.history(job.doc_id) == [(None, State.RECEIVED, None)]


@pytest.mark.parametrize(
    "bad",
    [
        "../../etc",
        "12345678-1234-5678-1234-567812345678",
        "{12345678123456781234567812345678}",
        "urn:uuid:12345678-1234-5678-1234-567812345678",
        "ABCDEF12" * 4,
        "1234-5678123456781234567812345678",
        "g" * 32,
    ],
)
def test_create_accepts_only_canonical_doc_ids(store, bad):
    with pytest.raises(ValueError):
        store.create("x.pdf", doc_id=bad)


def test_create_respects_max_active(store):
    store.create("a.pdf", max_active=1)
    with pytest.raises(QueueFullError):
        store.create("b.pdf", max_active=1)
    assert store.count_active() == 1


# -- transitions ---------------------------------------------------------------


def test_happy_path_reaches_complete_with_all_data(store):
    job = new(store, State.COMPLETE)
    assert job.state is State.COMPLETE
    assert [h[1] for h in store.history(job.doc_id)] == [State.RECEIVED, *HAPPY_PATH]
    assert job.output_hash == OUT_SHA
    assert store.stage_result(job.doc_id, Stage.CLASSIFY) == {"category": "bills"}
    assert store.recoverable() == []


ILLEGAL = [(a, b) for a in PATHS for b in State if b not in TRANSITIONS[a] and a is not b]


@pytest.mark.parametrize(("start", "target"), ILLEGAL)
def test_illegal_transitions_are_rejected(store, start, target):
    job = new(store, start)
    with pytest.raises(TransitionError):
        store.advance(job, target, code="x")
    assert store.get(job.doc_id).state is start


def test_review_is_not_reachable_before_ocr(store):
    job = new(store, State.VALIDATED)
    with pytest.raises(TransitionError):
        store.advance(job, State.NEEDS_REVIEW, code="no_text")


@pytest.mark.parametrize("target", [State.VALIDATED, State.OCR_DONE, State.CLASSIFIED])
def test_entering_a_stage_state_requires_its_result(store, target):
    job = new(
        store,
        {
            State.VALIDATED: State.RECEIVED,
            State.OCR_DONE: State.VALIDATED,
            State.CLASSIFIED: State.OCR_DONE,
        }[target],
    )
    with pytest.raises(TransitionError):
        store.advance(job, target)
    assert store.get(job.doc_id).revision == job.revision


def test_verified_requires_verify_result(store):
    job = new(store, State.UPLOADING)
    with pytest.raises(TransitionError):
        store.advance(job, State.VERIFIED)


def test_result_must_belong_to_the_target_stage(store):
    job = store.create("scan.pdf")
    with pytest.raises(TransitionError):
        store.advance(job, State.VALIDATED, result=(Stage.OCR, {}))
    with pytest.raises(ValueError):
        store.advance(job, State.VALIDATED, result=("made_up", {}))


def test_review_approval_needs_a_fresh_decision(store):
    job = new(store, State.CLASSIFIED)
    job = store.advance(job, State.NEEDS_REVIEW, code="low_confidence")
    with pytest.raises(TransitionError):
        store.advance(job, State.CLASSIFIED)
    job = store.advance(job, State.CLASSIFIED, result=(Stage.CLASSIFY, {"category": "tax"}))
    assert store.stage_result(job.doc_id, Stage.CLASSIFY) == {"category": "tax"}


@pytest.mark.parametrize("start", [State.RECEIVED, State.VALIDATED])
def test_quarantine_needs_a_reason(store, start):
    job = new(store, start)
    with pytest.raises(TransitionError):
        store.advance(job, State.QUARANTINED)


def test_upload_mismatch_needs_a_reason(store):
    job = new(store, State.UPLOADING)
    with pytest.raises(TransitionError):
        store.advance(job, State.READY)
    assert store.advance(job, State.READY, code="hash_mismatch").state is State.READY


def test_ready_needs_output_hash_and_destination(store):
    job = new(store, State.CLASSIFIED)
    with pytest.raises(TransitionError):
        store.advance(job, State.READY)
    job = store.set_output_hash(job, OUT_SHA)
    with pytest.raises(TransitionError):
        store.advance(job, State.READY)
    job = store.reserve_destination(job, "Bills/x.pdf")
    assert store.advance(job, State.READY).state is State.READY


def test_rejected_transition_stores_nothing(store):
    job = store.create("scan.pdf")
    store.advance(job, State.QUARANTINED, code="corrupt")
    with pytest.raises(StaleJobError):
        store.advance(job, State.VALIDATED, result=(Stage.VALIDATE, {"pages": 9}))
    assert store.stage_result(job.doc_id, Stage.VALIDATE) is None
    assert len(store.history(job.doc_id)) == 2


# -- stale writes ----------------------------------------------------------------


def test_stale_read_is_rejected(store):
    job = store.create("scan.pdf")
    step(store, job, State.VALIDATED)
    with pytest.raises(StaleJobError):
        step(store, job, State.VALIDATED)


def test_same_state_after_fail_and_retry_still_rejects_stale_work(store):
    old = store.create("scan.pdf")
    failed = store.fail(old, FailureKind.RETRYABLE, "busy")
    assert store.retry(failed).state is State.RECEIVED
    with pytest.raises(StaleJobError):
        step(store, old, State.VALIDATED)


def test_stale_work_cannot_land_on_a_replaced_input(store):
    old = store.create("scan.pdf")
    q = store.advance(old, State.QUARANTINED, code="encrypted_pdf")
    store.replace(q, "rescan.pdf")
    with pytest.raises(StaleJobError):
        store.advance(old, State.VALIDATED, result=(Stage.VALIDATE, {"from": "old"}))
    assert store.stage_result(old.doc_id, Stage.VALIDATE) is None


def test_two_connections_racing_only_one_wins(db_path):
    with JobStore(db_path) as a, JobStore(db_path) as b:
        job = a.create("scan.pdf")
        seen_by_b = b.get(job.doc_id)
        step(a, job, State.VALIDATED)
        with pytest.raises(StaleJobError):
            step(b, seen_by_b, State.VALIDATED)
        assert b.get(job.doc_id).state is State.VALIDATED


def test_unknown_job_raises_not_found(store):
    job = store.create("scan.pdf")
    ghost = job.__class__(**{**job.__dict__, "doc_id": "0" * 32})
    with pytest.raises(JobNotFoundError):
        store.get("0" * 32)
    with pytest.raises(JobNotFoundError):
        step(store, ghost, State.VALIDATED)


# -- input identity, destination, remote id ------------------------------------------


def test_source_hash_validation_and_lookup(store):
    job = store.create("scan.pdf")
    with pytest.raises(ValueError):
        store.set_source_hash(job, "not-a-hash")
    job = store.set_source_hash(job, SHA)
    assert [j.doc_id for j in store.find_by_source_hash(SHA)] == [job.doc_id]
    validated = step(store, job, State.VALIDATED)
    with pytest.raises(TransitionError):
        store.set_source_hash(validated, SHA)


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("Bills/2026/a.pdf", "bills/2026/A.PDF"),
        ("Bills/Été.pdf", "bills/Été.pdf"),
        ("Bills/Straße.pdf", "bills/STRASSE.pdf"),
    ],
)
def test_destination_collisions_after_normalization_are_refused(store, first, second):
    a = store.reserve_destination(new(store, State.CLASSIFIED), first)
    with pytest.raises(DestinationTakenError):
        store.reserve_destination(new(store, State.CLASSIFIED), second)
    assert store.get(a.doc_id).dest_path == first


def test_destination_rules(store):
    job = new(store, State.VALIDATED)
    with pytest.raises(TransitionError):
        store.reserve_destination(job, "Bills/x.pdf")
    job = new(store, State.CLASSIFIED)
    for bad in ("", "x" * 1025):
        with pytest.raises(ValueError):
            store.reserve_destination(job, bad)


def test_review_releases_the_destination(store):
    a = store.set_output_hash(new(store, State.CLASSIFIED), OUT_SHA)
    a = store.reserve_destination(a, "Bills/x.pdf")
    a = store.advance(a, State.NEEDS_REVIEW, code="user_flagged")
    assert (a.dest_path, a.output_hash) == (None, None)
    assert store.reserve_destination(new(store, State.CLASSIFIED), "Bills/x.pdf").dest_path


def test_discarding_a_failed_job_releases_its_destination(store):
    a = new(store, State.READY)
    path = a.dest_path
    store.discard(store.fail(a, FailureKind.PERMANENT, "bad_path"))
    assert store.reserve_destination(new(store, State.CLASSIFIED), path).dest_path == path


def test_remote_id_only_while_uploading(store):
    with pytest.raises(TransitionError):
        store.set_remote_id(new(store, State.READY), "id:abc")
    job = new(store, State.UPLOADING)
    with pytest.raises(ValueError):
        store.set_remote_id(job, "")
    assert store.set_remote_id(job, "id:abc").remote_id == "id:abc"


def test_replace_clears_everything_from_the_old_input(store):
    job = store.set_source_hash(store.create("scan.pdf"), SHA)
    job = step(store, job, State.VALIDATED)
    job = store.advance(job, State.QUARANTINED, code="encrypted_pdf")
    job = store.replace(job, "rescan.pdf")
    assert (job.state, job.source_name, job.source_hash) == (State.RECEIVED, "rescan.pdf", None)
    assert store.stage_result(job.doc_id, Stage.VALIDATE) is None
    assert store.find_by_source_hash(SHA) == []
    assert store.history(job.doc_id)[-1] == (State.QUARANTINED, State.RECEIVED, "replaced")


def test_replace_only_from_quarantine(store):
    with pytest.raises(TransitionError):
        store.replace(new(store, State.NEEDS_REVIEW), "x.pdf")


# -- codes -------------------------------------------------------------------------


def test_codes_reject_text_without_echoing_it(store):
    job = store.create("scan.pdf")
    leaked_text = "SSN 123-45-6789 found"
    with pytest.raises(ValueError) as exc:
        store.advance(job, State.QUARANTINED, code=leaked_text)
    assert "123-45-6789" not in str(exc.value)
    for bad in ("x" * 65, "café", ""):
        with pytest.raises(ValueError):
            store.fail(job, FailureKind.RETRYABLE, bad)
    assert store.get(job.doc_id).revision == job.revision


# -- failure, retry, discard -------------------------------------------------------


@pytest.mark.parametrize("state", sorted(ACTIVE_STATES))
def test_retryable_failure_resumes_where_it_failed(store, state):
    job = new(store, state)
    failed = store.fail(job, FailureKind.RETRYABLE, "timeout")
    assert (failed.state, failed.failed_from, failed.attempts) == (State.FAILED, state, 1)
    assert job.doc_id not in [j.doc_id for j in store.recoverable()]
    resumed = store.retry(failed)
    assert resumed.state is state
    assert (resumed.failure_kind, resumed.failure_code, resumed.failed_from) == (None, None, None)


def test_attempts_accumulate_across_failures(store):
    job = store.create("scan.pdf")
    for _ in range(3):
        job = store.retry(store.fail(job, FailureKind.RETRYABLE, "busy"))
    assert job.attempts == 3


def test_permanent_failure_cannot_be_retried_but_can_be_discarded(store):
    failed = store.fail(store.create("scan.pdf"), FailureKind.PERMANENT, "bad_path")
    with pytest.raises(TransitionError):
        store.retry(failed)
    assert store.discard(failed).state is State.DISCARDED


@pytest.mark.parametrize("state", [State.NEEDS_REVIEW, State.QUARANTINED, State.COMPLETE])
def test_only_active_states_can_fail(store, state):
    with pytest.raises(TransitionError):
        store.fail(new(store, state), FailureKind.RETRYABLE, "x")


def test_retry_requires_failed_state(store):
    with pytest.raises(TransitionError):
        store.retry(store.create("scan.pdf"))


@pytest.mark.parametrize("state", [State.RECEIVED, State.READY, State.COMPLETE])
def test_discard_only_from_states_awaiting_a_person(store, state):
    with pytest.raises(TransitionError):
        store.discard(new(store, state))


# -- queries, schema, durability -----------------------------------------------------


def test_recoverable_lists_only_active_jobs_oldest_first(db_path):
    clock = iter(range(10_000)).__next__
    with JobStore(db_path, clock=clock) as store:
        ids = {state: new(store, state, f"{state}.pdf").doc_id for state in PATHS}
        got = [j.doc_id for j in store.recoverable()]
        assert set(got) == {ids[s] for s in ACTIVE_STATES}
        assert got == sorted(got, key=lambda d: store.get(d).created_at)
        assert store.count_active() == len(ACTIVE_STATES)


def test_wal_and_full_sync_are_enabled(store):
    assert store._db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert store._db.execute("PRAGMA synchronous").fetchone()[0] == 2  # FULL


def test_reopening_keeps_data(db_path):
    with JobStore(db_path) as s:
        doc_id = s.create("scan.pdf").doc_id
    with JobStore(db_path) as s:
        assert s.get(doc_id).state is State.RECEIVED


def test_refuses_newer_schema(db_path):
    JobStore(db_path).close()
    raw = sqlite3.connect(db_path)
    raw.execute(f"PRAGMA user_version={SCHEMA_VERSION + 1}")
    raw.close()
    with pytest.raises(RuntimeError, match="newer"):
        JobStore(db_path)


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.fixture
def permissive_umask():
    old = os.umask(0o022)
    yield
    os.umask(old)


def test_database_and_sidecars_are_private(db_path, permissive_umask):
    with JobStore(db_path) as s:
        s.create("scan.pdf")
        for suffix in ("", "-wal", "-shm"):
            assert _mode(f"{db_path}{suffix}") == 0o600, suffix


def test_existing_world_readable_database_is_tightened(db_path, permissive_umask):
    JobStore(db_path).close()
    os.chmod(db_path, 0o644)
    with JobStore(db_path):
        assert _mode(db_path) == 0o600


def test_symlinked_database_path_is_refused(tmp_path):
    target = tmp_path / "elsewhere.sqlite"
    target.touch()
    link = tmp_path / "jobs.sqlite"
    link.symlink_to(target)
    with pytest.raises(OSError):
        JobStore(link)


class _CommitFails:
    """Connection proxy whose next COMMIT fails without committing."""

    def __init__(self, real):
        self._real = real
        self.armed = True

    def execute(self, sql, *args):
        if sql == "COMMIT" and self.armed:
            self.armed = False
            raise sqlite3.OperationalError("disk I/O error")
        return self._real.execute(sql, *args)

    def __getattr__(self, name):
        return getattr(self._real, name)


def test_failed_commit_rolls_back_and_releases_the_lock(db_path):
    with JobStore(db_path) as store, JobStore(db_path) as other:
        job = store.create("scan.pdf")
        real = store._db
        store._db = _CommitFails(real)
        with pytest.raises(sqlite3.OperationalError):
            step(store, job, State.VALIDATED)
        assert not real.in_transaction
        store._db = real
        assert other.get(job.doc_id).state is State.RECEIVED
        # Another connection can take the write lock right away.
        step(other, job, State.VALIDATED)


def _open_after_barrier(db_path, barrier):
    barrier.wait()
    JobStore(db_path).close()


def test_many_processes_opening_a_fresh_database_all_succeed(tmp_path):
    ctx = multiprocessing.get_context("fork")
    for attempt in range(5):
        db_path = tmp_path / f"fresh{attempt}.sqlite"
        barrier = ctx.Barrier(6)
        procs = [ctx.Process(target=_open_after_barrier, args=(db_path, barrier)) for _ in range(6)]
        for p in procs:
            p.start()
        for p in procs:
            p.join(30)
        assert [p.exitcode for p in procs] == [0] * 6


# -- crash recovery ----------------------------------------------------------------
# A child process dies (os._exit, no cleanup) either mid-transaction or right after
# a commit. It exits with CRASHED only after reaching that exact point, so an
# unexpected error in the child (exit status 1) fails the test instead of passing.

CRASHED = 77


def _crash_mid_transition(db_path, doc_id, state):
    store = JobStore(db_path)
    store._db.execute("BEGIN IMMEDIATE")
    cur = store._db.execute(
        "UPDATE jobs SET state='complete', revision=revision+1 WHERE doc_id=? AND state=?",
        (doc_id, state.value),
    )
    if cur.rowcount == 1:
        os._exit(CRASHED)
    os._exit(2)


def _crash_after_commit(db_path, doc_id, target):
    store = JobStore(db_path)
    step(store, store.get(doc_id), target)
    os._exit(CRASHED)


def _run_child(fn, *args):
    proc = multiprocessing.get_context("fork").Process(target=fn, args=args)
    proc.start()
    proc.join(30)
    assert proc.exitcode == CRASHED


NEXT = {
    State.RECEIVED: State.VALIDATED,
    State.VALIDATED: State.OCR_DONE,
    State.OCR_DONE: State.CLASSIFIED,
    State.CLASSIFIED: State.READY,
    State.READY: State.UPLOADING,
    State.UPLOADING: State.VERIFIED,
    State.VERIFIED: State.COMPLETE,
}


@pytest.mark.parametrize("state", sorted(ACTIVE_STATES))
def test_crash_mid_transition_leaves_job_resumable(db_path, state):
    with JobStore(db_path) as store:
        job = new(store, state)
    _run_child(_crash_mid_transition, db_path, job.doc_id, state)
    with JobStore(db_path) as store:
        assert store.get(job.doc_id) == job
        assert job.doc_id in [j.doc_id for j in store.recoverable()]
        # The dead writer's lock is gone: the pipeline can carry on.
        step(store, job, NEXT[state])


@pytest.mark.parametrize("state", sorted(ACTIVE_STATES))
def test_crash_after_commit_keeps_the_transition(db_path, state):
    with JobStore(db_path) as store:
        job = new(store, state)
    _run_child(_crash_after_commit, db_path, job.doc_id, NEXT[state])
    with JobStore(db_path) as store:
        assert store.get(job.doc_id).state is NEXT[state]
        assert store.history(job.doc_id)[-1][:2] == (state, NEXT[state])
