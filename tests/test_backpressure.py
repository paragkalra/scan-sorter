import multiprocessing
from collections import namedtuple

import pytest

from scan_sorter.backpressure import Limits, admit
from scan_sorter.jobs import JobStore

Usage = namedtuple("Usage", "total used free")


def disk(free):
    return lambda _path: Usage(0, 0, free)


@pytest.fixture
def store(tmp_path):
    with JobStore(tmp_path / "jobs.sqlite") as s:
        yield s


def test_admits_when_queue_and_disk_have_room(store, tmp_path):
    got = admit(store, tmp_path, "a.pdf", Limits(2, 100), disk_usage=disk(100))
    assert got.reason is None
    assert got.job.source_name == "a.pdf"


def test_pauses_when_queue_is_full(store, tmp_path):
    store.create("a.pdf")
    store.create("b.pdf")
    got = admit(store, tmp_path, "c.pdf", Limits(2, 100), disk_usage=disk(10**9))
    assert (got.job, got.reason) == (None, "queue_full")
    assert store.count_active() == 2


def test_jobs_waiting_on_a_person_do_not_fill_the_queue(store, tmp_path):
    job = store.create("a.pdf")
    store.advance(job, job.state.QUARANTINED, code="corrupt")
    assert admit(store, tmp_path, "b.pdf", Limits(1, 100), disk_usage=disk(10**9)).job


def test_pauses_when_disk_is_low(store, tmp_path):
    got = admit(store, tmp_path, "a.pdf", Limits(10, 100), disk_usage=disk(99))
    assert (got.job, got.reason) == (None, "disk_low")
    assert store.count_active() == 0


def _admit_after_barrier(db_path, barrier, out):
    with JobStore(db_path) as s:
        barrier.wait()
        got = admit(s, db_path.parent, "x.pdf", Limits(1, 0), disk_usage=disk(1))
        out.put(got.job is not None)


def test_concurrent_processes_cannot_overfill_the_queue(tmp_path):
    db_path = tmp_path / "jobs.sqlite"
    JobStore(db_path).close()
    ctx = multiprocessing.get_context("fork")
    n = 6
    barrier, out = ctx.Barrier(n), ctx.Queue()
    procs = [
        ctx.Process(target=_admit_after_barrier, args=(db_path, barrier, out)) for _ in range(n)
    ]
    for p in procs:
        p.start()
    results = [out.get(timeout=30) for _ in procs]
    for p in procs:
        p.join(10)
        assert p.exitcode == 0
    assert results.count(True) == 1
    with JobStore(db_path) as s:
        assert s.count_active() == 1
