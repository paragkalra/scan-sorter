from collections import namedtuple

import pytest

from scan_sorter.backpressure import IntakeDecision, Limits, check_intake
from scan_sorter.jobs import JobStore, State

Usage = namedtuple("Usage", "total used free")


def disk(free):
    return lambda _path: Usage(0, 0, free)


@pytest.fixture
def store(tmp_path):
    with JobStore(tmp_path / "jobs.sqlite") as s:
        yield s


def test_accepts_when_queue_and_disk_have_room(store, tmp_path):
    assert check_intake(store, tmp_path, Limits(2, 100), disk_usage=disk(100)) == IntakeDecision(
        True
    )


def test_pauses_when_queue_is_full(store, tmp_path):
    store.create("a.pdf")
    store.create("b.pdf")
    got = check_intake(store, tmp_path, Limits(2, 100), disk_usage=disk(10**9))
    assert got == IntakeDecision(False, "queue_full")


def test_jobs_waiting_on_a_person_do_not_fill_the_queue(store, tmp_path):
    job = store.create("a.pdf")
    store.advance(job.doc_id, State.RECEIVED, State.QUARANTINED, code="corrupt")
    assert check_intake(store, tmp_path, Limits(1, 100), disk_usage=disk(10**9)).accept


def test_pauses_when_disk_is_low(store, tmp_path):
    got = check_intake(store, tmp_path, Limits(10, 100), disk_usage=disk(99))
    assert got == IntakeDecision(False, "disk_low")
