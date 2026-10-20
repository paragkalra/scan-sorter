import multiprocessing
import os
import sqlite3

import pytest

from scan_sorter.jobs import (
    ACTIVE_STATES,
    SCHEMA_VERSION,
    TRANSITIONS,
    FailureKind,
    JobNotFoundError,
    JobStore,
    StaleStateError,
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

# Shortest forward walk from RECEIVED to each state reachable through advance().
PATHS = {
    State.RECEIVED: [],
    **{s: HAPPY_PATH[: i + 1] for i, s in enumerate(HAPPY_PATH)},
    State.NEEDS_REVIEW: [State.VALIDATED, State.NEEDS_REVIEW],
    State.QUARANTINED: [State.QUARANTINED],
}

SHA = "a" * 64


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "jobs.sqlite"


@pytest.fixture
def store(db_path):
    with JobStore(db_path) as s:
        yield s


def walk(store, doc_id, path):
    state = State.RECEIVED
    for nxt in path:
        store.advance(doc_id, state, nxt)
        state = nxt
    return state


def test_create_starts_in_received_with_history(store):
    job = store.create("scan001.pdf")
    assert job.state is State.RECEIVED
    assert len(job.doc_id) == 32
    assert store.history(job.doc_id) == [(None, State.RECEIVED, None)]


def test_create_rejects_malformed_doc_id(store):
    with pytest.raises(ValueError):
        store.create("x.pdf", doc_id="../../etc")


def test_happy_path_reaches_complete(store):
    job = store.create("scan.pdf")
    walk(store, job.doc_id, HAPPY_PATH)
    assert store.get(job.doc_id).state is State.COMPLETE
    assert [h[1] for h in store.history(job.doc_id)] == [State.RECEIVED, *HAPPY_PATH]
    assert store.recoverable() == []


ILLEGAL = [
    (a, b) for a in State for b in State if b not in TRANSITIONS[a] and a in PATHS and a is not b
]


@pytest.mark.parametrize(("start", "target"), ILLEGAL)
def test_illegal_transitions_are_rejected(store, start, target):
    job = store.create("scan.pdf")
    walk(store, job.doc_id, PATHS[start])
    with pytest.raises(TransitionError):
        store.advance(job.doc_id, start, target)
    assert store.get(job.doc_id).state is start


def test_stale_expected_state_is_rejected(store):
    job = store.create("scan.pdf")
    store.advance(job.doc_id, State.RECEIVED, State.VALIDATED)
    with pytest.raises(StaleStateError):
        store.advance(job.doc_id, State.RECEIVED, State.VALIDATED)


def test_two_processes_racing_only_one_wins(db_path):
    with JobStore(db_path) as a, JobStore(db_path) as b:
        job = a.create("scan.pdf")
        a.advance(job.doc_id, State.RECEIVED, State.VALIDATED)
        with pytest.raises(StaleStateError):
            b.advance(job.doc_id, State.RECEIVED, State.VALIDATED)
        assert b.get(job.doc_id).state is State.VALIDATED


def test_unknown_job_raises_not_found(store):
    with pytest.raises(JobNotFoundError):
        store.get("0" * 32)
    with pytest.raises(JobNotFoundError):
        store.advance("0" * 32, State.RECEIVED, State.VALIDATED)


def test_stage_result_commits_with_the_transition(store):
    job = store.create("scan.pdf")
    store.advance(job.doc_id, State.RECEIVED, State.VALIDATED, result=("validate", {"pages": 3}))
    assert store.stage_result(job.doc_id, "validate") == {"pages": 3}


def test_rejected_transition_does_not_store_result(store):
    job = store.create("scan.pdf")
    with pytest.raises(StaleStateError):
        store.advance(job.doc_id, State.VALIDATED, State.OCR_DONE, result=("ocr", {"chars": 9}))
    assert store.stage_result(job.doc_id, "ocr") is None
    assert len(store.history(job.doc_id)) == 1


def test_stage_result_is_overwritten_on_rerun(store):
    job = store.create("scan.pdf")
    walk(store, job.doc_id, [State.VALIDATED, State.OCR_DONE, State.CLASSIFIED, State.READY])
    store.advance(job.doc_id, State.READY, State.UPLOADING, result=("upload", {"try": 1}))
    store.advance(job.doc_id, State.UPLOADING, State.READY, code="hash_mismatch")
    store.advance(job.doc_id, State.READY, State.UPLOADING, result=("upload", {"try": 2}))
    assert store.stage_result(job.doc_id, "upload") == {"try": 2}


def test_codes_must_be_short_identifiers(store):
    job = store.create("scan.pdf")
    with pytest.raises(ValueError):
        store.advance(job.doc_id, State.RECEIVED, State.QUARANTINED, code="SSN 123-45-6789 found")
    with pytest.raises(ValueError):
        store.fail(job.doc_id, State.RECEIVED, FailureKind.RETRYABLE, "x" * 65)
    assert store.get(job.doc_id).state is State.RECEIVED


def test_source_hash_lookup_and_validation(store):
    job = store.create("scan.pdf")
    store.set_source_hash(job.doc_id, SHA)
    assert [j.doc_id for j in store.find_by_source_hash(SHA)] == [job.doc_id]
    with pytest.raises(ValueError):
        store.set_source_hash(job.doc_id, "not-a-hash")
    with pytest.raises(JobNotFoundError):
        store.set_source_hash("0" * 32, SHA)


@pytest.mark.parametrize("state", sorted(ACTIVE_STATES))
def test_retryable_failure_resumes_where_it_failed(store, state):
    job = store.create("scan.pdf")
    walk(store, job.doc_id, PATHS[state])
    failed = store.fail(job.doc_id, state, FailureKind.RETRYABLE, "timeout")
    assert (failed.state, failed.failed_from, failed.attempts) == (State.FAILED, state, 1)
    assert job.doc_id not in [j.doc_id for j in store.recoverable()]
    resumed = store.retry(job.doc_id)
    assert resumed.state is state
    assert (resumed.failure_kind, resumed.failure_code, resumed.failed_from) == (None, None, None)
    assert resumed.attempts == 1


def test_attempts_accumulate_across_failures(store):
    job = store.create("scan.pdf")
    for _ in range(3):
        store.fail(job.doc_id, State.RECEIVED, FailureKind.RETRYABLE, "busy")
        store.retry(job.doc_id)
    assert store.get(job.doc_id).attempts == 3


def test_permanent_failure_cannot_be_retried_but_can_be_discarded(store):
    job = store.create("scan.pdf")
    store.fail(job.doc_id, State.RECEIVED, FailureKind.PERMANENT, "bad_path")
    with pytest.raises(TransitionError):
        store.retry(job.doc_id)
    assert store.discard(job.doc_id, State.FAILED).state is State.DISCARDED


@pytest.mark.parametrize("state", [State.NEEDS_REVIEW, State.QUARANTINED, State.COMPLETE])
def test_only_active_states_can_fail(store, state):
    job = store.create("scan.pdf")
    walk(store, job.doc_id, PATHS[state])
    with pytest.raises(TransitionError):
        store.fail(job.doc_id, state, FailureKind.RETRYABLE, "x")


def test_retry_requires_failed_state(store):
    job = store.create("scan.pdf")
    with pytest.raises(TransitionError):
        store.retry(job.doc_id)


@pytest.mark.parametrize("state", [State.RECEIVED, State.READY, State.COMPLETE])
def test_discard_only_from_states_awaiting_a_person(store, state):
    job = store.create("scan.pdf")
    walk(store, job.doc_id, PATHS[state])
    with pytest.raises(TransitionError):
        store.discard(job.doc_id, state)


def test_quarantined_replacement_reenters_at_received(store):
    job = store.create("scan.pdf")
    store.advance(job.doc_id, State.RECEIVED, State.QUARANTINED, code="encrypted_pdf")
    with pytest.raises(TransitionError):
        store.advance(job.doc_id, State.QUARANTINED, State.READY)
    store.advance(job.doc_id, State.QUARANTINED, State.RECEIVED, code="replaced")
    assert store.get(job.doc_id).state is State.RECEIVED


def test_recoverable_lists_only_active_jobs_oldest_first(db_path):
    clock = iter(range(1000)).__next__
    with JobStore(db_path, clock=clock) as store:
        ids = {}
        for state in PATHS:
            ids[state] = store.create(f"{state}.pdf").doc_id
            walk(store, ids[state], PATHS[state])
        got = [j.doc_id for j in store.recoverable()]
        assert set(got) == {ids[s] for s in ACTIVE_STATES}
        assert got == sorted(got, key=lambda d: store.get(d).created_at)
        assert store.count_active() == len(ACTIVE_STATES)


def test_wal_and_full_sync_are_enabled(store):
    assert store._db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert store._db.execute("PRAGMA synchronous").fetchone()[0] == 2  # FULL


def test_reopening_keeps_data_and_schema(db_path):
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


# -- crash recovery ------------------------------------------------------------
# A child process dies (os._exit, no cleanup) either mid-transaction or right
# after a commit. The parent then reopens the store as a restarted pipeline would.


def _crash_mid_transition(db_path, doc_id, state, target):
    store = JobStore(db_path)
    store._db.execute("BEGIN IMMEDIATE")
    store._db.execute(
        "UPDATE jobs SET state=? WHERE doc_id=? AND state=?", (target.value, doc_id, state.value)
    )
    os._exit(1)


def _crash_after_commit(db_path, doc_id, state, target):
    store = JobStore(db_path)
    store.advance(doc_id, state, target)
    os._exit(1)


def _run_child(fn, *args):
    proc = multiprocessing.get_context("fork").Process(target=fn, args=args)
    proc.start()
    proc.join(10)
    assert proc.exitcode == 1


NEXT = {s: next(iter(sorted(TRANSITIONS[s]))) for s in ACTIVE_STATES}


@pytest.mark.parametrize("state", sorted(ACTIVE_STATES))
def test_crash_mid_transition_leaves_job_resumable(db_path, state):
    with JobStore(db_path) as store:
        doc_id = store.create("scan.pdf").doc_id
        walk(store, doc_id, PATHS[state])
    _run_child(_crash_mid_transition, db_path, doc_id, state, NEXT[state])
    with JobStore(db_path) as store:
        assert store.get(doc_id).state is state
        assert doc_id in [j.doc_id for j in store.recoverable()]
        # The dead writer's lock is gone: the pipeline can carry on.
        store.advance(doc_id, state, NEXT[state])


@pytest.mark.parametrize("state", sorted(ACTIVE_STATES))
def test_crash_after_commit_keeps_the_transition(db_path, state):
    with JobStore(db_path) as store:
        doc_id = store.create("scan.pdf").doc_id
        walk(store, doc_id, PATHS[state])
    _run_child(_crash_after_commit, db_path, doc_id, state, NEXT[state])
    with JobStore(db_path) as store:
        assert store.get(doc_id).state is NEXT[state]
        assert store.history(doc_id)[-1][:2] == (state, NEXT[state])
