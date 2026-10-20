import hashlib
import multiprocessing
import os
import stat
from collections import namedtuple
from pathlib import Path

import pytest

from scan_sorter import fsutil, ingest
from scan_sorter.fsutil import Identity
from scan_sorter.ingest import ORIGINAL, Spool, TransferGate, Watcher
from scan_sorter.jobs import FailureKind, JobStore, QueueFullError, Stage, State

Usage = namedtuple("Usage", "total used free")
PLENTY = lambda _p: Usage(0, 0, 1 << 40)  # noqa: E731


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def dirs(tmp_path):
    inbox, spool = tmp_path / "inbox", tmp_path / "spool"
    inbox.mkdir()
    spool.mkdir()
    return inbox, spool


@pytest.fixture
def spool(dirs):
    with Spool(*dirs) as s:
        yield s


@pytest.fixture
def store(tmp_path):
    with JobStore(tmp_path / "jobs.sqlite") as s:
        yield s


def write(path: Path, data: bytes = b"%PDF-1.7 scan") -> Identity:
    path.write_bytes(data)
    return Identity.of(os.lstat(path))


def original(spool_dir: Path, doc_id: str) -> Path:
    return spool_dir / "jobs" / doc_id / ORIGINAL


# -- transfer gate --------------------------------------------------------------


def ident(size=10, mtime=1, ino=1, mode=stat.S_IFREG | 0o644):
    return Identity(1, ino, size, mtime, mode)


def make_gate(clock):
    return TransferGate(
        stable_seconds=10, fallback_stable_seconds=60, max_wait_seconds=600, clock=clock
    )


def test_gate_closed_file_is_ready_after_stable_window():
    clock = Clock()
    gate = make_gate(clock)
    assert gate.observe({"a": ident()}, closed=["a"]).ready == []
    clock.t += 9
    assert gate.observe({"a": ident()}).ready == []
    clock.t += 1
    assert gate.observe({"a": ident()}).ready == ["a"]


def test_gate_without_close_waits_for_fallback_window():
    clock = Clock()
    gate = make_gate(clock)
    gate.observe({"a": ident()})
    clock.t += 59
    assert gate.observe({"a": ident()}).ready == []
    clock.t += 1
    assert gate.observe({"a": ident()}).ready == ["a"]


def test_gate_change_restarts_the_window_and_clears_close():
    clock = Clock()
    gate = make_gate(clock)
    gate.observe({"a": ident(size=10)}, closed=["a"])
    clock.t += 9
    gate.observe({"a": ident(size=20)})  # writer reopened and appended
    clock.t += 5
    assert gate.observe({"a": ident(size=20)}).ready == []
    clock.t += 60
    assert gate.observe({"a": ident(size=20)}).ready == ["a"]


def test_gate_close_reported_with_a_change_counts_for_that_change():
    clock = Clock()
    gate = make_gate(clock)
    gate.observe({"a": ident(size=10)})
    clock.t += 1
    gate.observe({"a": ident(size=20)}, closed=["a"])
    clock.t += 10
    assert gate.observe({"a": ident(size=20)}).ready == ["a"]


def test_gate_replaced_file_starts_over():
    clock = Clock()
    gate = make_gate(clock)
    gate.observe({"a": ident(ino=1)})
    clock.t += 590
    gate.observe({"a": ident(ino=2, size=1)})  # same name, new file
    clock.t += 20
    result = gate.observe({"a": ident(ino=2, size=2)})
    assert result.overdue == [] and result.ready == []


def test_gate_never_settling_file_is_overdue():
    clock = Clock()
    gate = make_gate(clock)
    for i in range(70):
        result = gate.observe({"a": ident(size=i)})
        clock.t += 10
    assert result.overdue == ["a"]
    assert result.ready == []


def test_gate_non_regular_entries_are_ready_at_once():
    gate = make_gate(Clock())
    assert gate.observe({"l": ident(mode=stat.S_IFLNK | 0o777)}).ready == ["l"]


def test_gate_forgets_vanished_names_and_close_marks():
    clock = Clock()
    gate = make_gate(clock)
    gate.observe({"a": ident()}, closed=["a"])
    gate.forget_closed()
    clock.t += 10
    assert gate.observe({"a": ident()}).ready == []
    gate.observe({})
    assert gate._seen == {}


def test_gate_ignores_close_for_unknown_names():
    assert make_gate(Clock()).observe({}, closed=["ghost"]).ready == []


# -- spool setup -----------------------------------------------------------------------


def test_spool_refuses_symlinked_directories(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "inbox").symlink_to(real)
    (tmp_path / "spool").mkdir()
    with pytest.raises(OSError):
        Spool(tmp_path / "inbox", tmp_path / "spool")


def test_spool_dirs_are_private(dirs):
    inbox, spool_dir = dirs
    with Spool(inbox, spool_dir):
        assert stat.S_IMODE(os.stat(spool_dir).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(spool_dir / "jobs").st_mode) == 0o700


def test_spool_skips_dotfiles(dirs, spool):
    inbox, _ = dirs
    write(inbox / ".~upload.tmp")
    write(inbox / "scan.pdf")
    assert list(spool.inbox_entries()) == ["scan.pdf"]


# -- adoption ------------------------------------------------------------------------


def test_adopt_moves_file_and_records_hash_and_intake(dirs, spool, store):
    inbox, spool_dir = dirs
    data = b"%PDF-1.7 hello"
    st = write(inbox / "scan001.pdf", data)
    job = spool.adopt(store, "scan001.pdf", st)
    assert job.state is State.RECEIVED
    assert job.source_hash == hashlib.sha256(data).hexdigest()
    assert job.source_name == "scan001.pdf"
    assert not (inbox / "scan001.pdf").exists()
    moved = original(spool_dir, job.doc_id)
    assert moved.read_bytes() == data
    assert Identity.of(os.lstat(moved)).same_file(st)
    assert stat.S_IMODE(os.stat(moved.parent).st_mode) == 0o700
    intake = store.stage_result(job.doc_id, Stage.INTAKE)
    assert bytes.fromhex(intake["inbox_name_hex"]) == b"scan001.pdf"
    assert Identity.from_dict(intake) == st


def test_adopt_symlink_is_quarantined_and_target_untouched(dirs, spool, store, tmp_path):
    inbox, spool_dir = dirs
    secret = tmp_path / "secret.txt"
    secret.write_text("private")
    (inbox / "evil.pdf").symlink_to(secret)
    job = spool.adopt(store, "evil.pdf", fsutil.lstat_at("evil.pdf", spool.inbox_fd))
    assert job.state is State.QUARANTINED
    assert store.history(job.doc_id)[-1][2] == "not_regular_file"
    assert secret.read_text() == "private"
    assert original(spool_dir, job.doc_id).is_symlink()


def test_adopt_fifo_is_quarantined_without_blocking(dirs, spool, store):
    inbox, _ = dirs
    os.mkfifo(inbox / "pipe.pdf")
    job = spool.adopt(store, "pipe.pdf", fsutil.lstat_at("pipe.pdf", spool.inbox_fd))
    assert job.state is State.QUARANTINED


def test_adopt_directory_is_quarantined(dirs, spool, store):
    inbox, _ = dirs
    (inbox / "folder").mkdir()
    job = spool.adopt(store, "folder", fsutil.lstat_at("folder", spool.inbox_fd))
    assert job.state is State.QUARANTINED
    assert not (inbox / "folder").exists()


def test_adopt_refuses_a_file_that_changed_after_the_gate(dirs, spool, store):
    inbox, _ = dirs
    st = write(inbox / "scan.pdf", b"part")
    with open(inbox / "scan.pdf", "ab") as f:
        f.write(b"more bytes")
    with pytest.raises(ingest.SourceChangedError):
        spool.adopt(store, "scan.pdf", st)
    assert os.listdir(inbox) == ["scan.pdf"]
    assert store.jobs_in(*State) == []


def test_adopt_quarantines_a_file_written_to_during_the_rename(dirs, spool, store, monkeypatch):
    inbox, spool_dir = dirs
    st = write(inbox / "scan.pdf", b"part")
    real_rename = os.rename

    def rename_then_writer_appends(src, dst, **kw):
        real_rename(src, dst, **kw)
        with open(spool_dir / "jobs" / os.listdir(spool_dir / "jobs")[0] / ORIGINAL, "ab") as f:
            f.write(b"late bytes from an open handle")

    monkeypatch.setattr(ingest.os, "rename", rename_then_writer_appends)
    job = spool.adopt(store, "scan.pdf", st)
    assert job.state is State.QUARANTINED
    assert store.history(job.doc_id)[-1][2] == "changed_during_adoption"


def test_adopt_fails_when_the_file_vanished(dirs, spool, store):
    inbox, _ = dirs
    st = write(inbox / "scan.pdf")
    real_create = store.create

    def create_then_vanish(*a, **k):
        job = real_create(*a, **k)
        (inbox / "scan.pdf").unlink()
        return job

    store.create = create_then_vanish
    job = spool.adopt(store, "scan.pdf", st)
    assert (job.state, job.failure_kind, job.failure_code) == (
        State.FAILED,
        FailureKind.PERMANENT,
        "source_missing",
    )


def test_adopt_queue_full_leaves_file_in_inbox(dirs, tmp_path):
    inbox, spool_dir = dirs
    with Spool(inbox, spool_dir) as spool, JobStore(tmp_path / "q.sqlite", max_active=0) as store:
        st = write(inbox / "scan.pdf")
        with pytest.raises(QueueFullError):
            spool.adopt(store, "scan.pdf", st)
        assert (inbox / "scan.pdf").exists()
        assert store.jobs_in(*State) == []


def test_non_utf8_filename_round_trips(dirs, spool, store):
    inbox, spool_dir = dirs
    raw = b"scan\xff\x01.pdf"
    fd = os.open(os.fsencode(inbox) + b"/" + raw, os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(fd, b"data")
    os.close(fd)
    name = os.fsdecode(raw)
    job = spool.adopt(store, name, spool.inbox_entries()[name])
    assert job.state is State.RECEIVED
    assert job.source_name == "scan\\xff\\x01.pdf"
    assert os.listdir(inbox) == []


# -- reconcile ---------------------------------------------------------------------------


def _registered_but_not_moved(spool, store, name, st):
    intake = {"inbox_name_hex": os.fsencode(name).hex(), **st.as_dict()}
    return store.create(name, intake=intake)


def test_reconcile_finishes_an_adoption_cut_before_the_rename(dirs, spool, store):
    inbox, spool_dir = dirs
    st = write(inbox / "scan.pdf", b"abc")
    job = _registered_but_not_moved(spool, store, "scan.pdf", st)
    assert spool.reconcile(store) == [job.doc_id]
    job = store.get(job.doc_id)
    assert job.source_hash == hashlib.sha256(b"abc").hexdigest()
    assert original(spool_dir, job.doc_id).read_bytes() == b"abc"
    assert os.listdir(inbox) == []


def test_reconcile_records_hash_when_cut_after_the_rename(dirs, spool, store):
    inbox, spool_dir = dirs
    st = write(inbox / "scan.pdf", b"abc")
    job = _registered_but_not_moved(spool, store, "scan.pdf", st)
    (spool_dir / "jobs" / job.doc_id).mkdir()
    os.rename(inbox / "scan.pdf", original(spool_dir, job.doc_id))
    spool.reconcile(store)
    assert store.get(job.doc_id).source_hash == hashlib.sha256(b"abc").hexdigest()


def test_reconcile_does_not_take_a_different_file_with_the_same_name(dirs, spool, store):
    inbox, _ = dirs
    st = write(inbox / "scan.pdf", b"first")
    job = _registered_but_not_moved(spool, store, "scan.pdf", st)
    (inbox / "scan.pdf").unlink()
    write(inbox / "scan.pdf", b"second scan, same name")
    spool.reconcile(store)
    assert store.get(job.doc_id).failure_code == "source_missing"
    assert (inbox / "scan.pdf").read_bytes() == b"second scan, same name"


def test_reconcile_fails_jobs_whose_file_is_gone(dirs, spool, store):
    inbox, _ = dirs
    st = write(inbox / "scan.pdf")
    job = _registered_but_not_moved(spool, store, "scan.pdf", st)
    (inbox / "scan.pdf").unlink()
    spool.reconcile(store)
    assert store.get(job.doc_id).state is State.FAILED


def test_reconcile_adopts_spool_dirs_without_a_row(dirs, spool, store):
    _, spool_dir = dirs
    doc_id = "ab" * 16
    (spool_dir / "jobs" / doc_id).mkdir()
    original(spool_dir, doc_id).write_bytes(b"orphan")
    assert spool.reconcile(store) == [doc_id]
    job = store.get(doc_id)
    assert (job.source_name, job.source_hash) == (
        "recovered",
        hashlib.sha256(b"orphan").hexdigest(),
    )


def test_reconcile_removes_empty_orphan_dirs_and_ignores_junk(dirs, spool, store):
    _, spool_dir = dirs
    (spool_dir / "jobs" / ("cd" * 16)).mkdir()
    (spool_dir / "jobs" / "not-a-job").mkdir()
    (spool_dir / "jobs" / "not-a-job" / ORIGINAL).write_bytes(b"x")
    (spool_dir / "jobs" / "stray-file").write_bytes(b"x")
    assert spool.reconcile(store) == []
    assert sorted(os.listdir(spool_dir / "jobs")) == ["not-a-job", "stray-file"]


def test_reconcile_is_idempotent(dirs, spool, store):
    inbox, _ = dirs
    job = spool.adopt(store, "scan.pdf", write(inbox / "scan.pdf"))
    assert spool.reconcile(store) == []
    assert spool.reconcile(store) == []
    assert store.get(job.doc_id).revision == job.revision


def test_recovered_orphans_ignore_queue_capacity(dirs, tmp_path):
    inbox, spool_dir = dirs
    doc_id = "ef" * 16
    with Spool(inbox, spool_dir) as spool, JobStore(tmp_path / "q.sqlite", max_active=0) as store:
        (spool_dir / "jobs" / doc_id).mkdir()
        original(spool_dir, doc_id).write_bytes(b"x")
        spool.reconcile(store)
        assert store.get(doc_id).state is State.RECEIVED


# -- crash injection through the real adopt() ---------------------------------------
# A child process runs Spool.adopt and dies at a chosen point; the parent restarts,
# reconciles, and checks exactly one job owns the scan with its hash recorded.

CRASHED = 77


def _crash_during_adopt(inbox, spool_dir, db_path, point):
    real_rename, real_fsync, real_hash = os.rename, os.fsync, fsutil.sha256_file

    def die():
        os._exit(CRASHED)

    if point == "before_rename":
        ingest.os.rename = lambda *a, **k: die()
    elif point == "after_rename":

        def rename(*a, **k):
            real_rename(*a, **k)
            die()

        ingest.os.rename = rename
    elif point == "before_hash":
        ingest.fsutil.sha256_file = lambda *a, **k: die()
    with Spool(inbox, spool_dir) as spool, JobStore(db_path) as store:
        spool.adopt(store, "scan.pdf", spool.inbox_entries()["scan.pdf"])
    os.rename, os.fsync, fsutil.sha256_file = real_rename, real_fsync, real_hash
    os._exit(3)


@pytest.mark.parametrize("point", ["before_rename", "after_rename", "before_hash"])
def test_crash_during_adoption_is_recovered(dirs, tmp_path, point):
    inbox, spool_dir = dirs
    db_path = tmp_path / "jobs.sqlite"
    write(inbox / "scan.pdf", b"precious")
    proc = multiprocessing.get_context("fork").Process(
        target=_crash_during_adopt, args=(inbox, spool_dir, db_path, point)
    )
    proc.start()
    proc.join(30)
    assert proc.exitcode == CRASHED
    with Spool(inbox, spool_dir) as spool, JobStore(db_path) as store:
        spool.reconcile(store)
        jobs = store.jobs_in(*State)
        assert len(jobs) == 1
        job = jobs[0]
        assert (job.state, job.source_hash) == (
            State.RECEIVED,
            hashlib.sha256(b"precious").hexdigest(),
        )
        assert original(spool_dir, job.doc_id).read_bytes() == b"precious"
        assert os.listdir(inbox) == []


# -- watcher -----------------------------------------------------------------------------


@pytest.fixture
def clock():
    return Clock()


def make_watcher(store, spool, clock, **kw):
    gate = TransferGate(
        stable_seconds=10, fallback_stable_seconds=60, max_wait_seconds=600, clock=clock
    )
    kw.setdefault("disk_usage", PLENTY)
    return Watcher(store, spool, gate, min_free_bytes=1, **kw)


def test_watcher_adopts_a_closed_file_after_the_stable_window(dirs, spool, store, clock):
    inbox, _ = dirs
    w = make_watcher(store, spool, clock)
    if w.inotify is None:
        pytest.skip("inotify unavailable")
    write(inbox / "scan.pdf")
    assert w.poll_once().adopted == []
    clock.t += 10
    report = w.poll_once()
    assert len(report.adopted) == 1
    assert os.listdir(inbox) == []
    w.close()


def test_watcher_without_inotify_uses_fallback_window(dirs, spool, store, clock):
    inbox, _ = dirs
    w = make_watcher(store, spool, clock, use_inotify=False)
    write(inbox / "scan.pdf")
    w.poll_once()
    clock.t += 59
    assert w.poll_once().adopted == []
    clock.t += 1
    assert len(w.poll_once().adopted) == 1


def test_watcher_pauses_on_low_disk_and_leaves_files(dirs, spool, store, clock):
    inbox, _ = dirs
    w = make_watcher(store, spool, clock, use_inotify=False, disk_usage=lambda _p: Usage(0, 0, 0))
    write(inbox / "scan.pdf")
    w.poll_once()
    clock.t += 60
    report = w.poll_once()
    assert (report.adopted, report.paused) == ([], "disk_low")
    assert os.listdir(inbox) == ["scan.pdf"]


def test_watcher_pauses_on_full_queue_and_resumes(dirs, tmp_path, clock):
    inbox, spool_dir = dirs
    with Spool(inbox, spool_dir) as spool, JobStore(tmp_path / "q.sqlite", max_active=1) as store:
        w = make_watcher(store, spool, clock, use_inotify=False)
        write(inbox / "a.pdf")
        write(inbox / "b.pdf")
        w.poll_once()
        clock.t += 60
        report = w.poll_once()
        assert (len(report.adopted), report.paused) == (1, "queue_full")
        assert os.listdir(inbox) == ["b.pdf"]
        store.fail(store.recoverable()[0], FailureKind.PERMANENT, "x")
        assert len(w.poll_once().adopted) == 1


def test_watcher_quarantines_overdue_files_even_when_full(dirs, tmp_path, clock):
    inbox, spool_dir = dirs
    with Spool(inbox, spool_dir) as spool, JobStore(tmp_path / "q.sqlite", max_active=0) as store:
        w = make_watcher(store, spool, clock, use_inotify=False)
        for i in range(70):
            write(inbox / "slow.pdf", b"x" * (i + 1))
            report = w.poll_once()
            clock.t += 10
            if report.quarantined:
                break
        assert len(report.quarantined) == 1
        job = store.get(report.quarantined[0])
        assert store.history(job.doc_id)[-1][2] == "incomplete_transfer"
        assert os.listdir(inbox) == []


def test_watcher_quarantines_symlinks_immediately(dirs, spool, store, clock, tmp_path):
    inbox, _ = dirs
    (tmp_path / "target").write_text("x")
    (inbox / "link.pdf").symlink_to(tmp_path / "target")
    report = make_watcher(store, spool, clock, use_inotify=False).poll_once()
    assert len(report.quarantined) == 1


def test_inotify_overflow_drops_close_marks(dirs, spool, store, clock):
    inbox, _ = dirs
    w = make_watcher(store, spool, clock)
    if w.inotify is None:
        pytest.skip("inotify unavailable")
    write(inbox / "scan.pdf")
    w.inotify.overflowed = True
    w.poll_once()
    clock.t += 10
    assert w.poll_once().adopted == []  # no trusted close: wait for the fallback
    clock.t += 50
    assert len(w.poll_once().adopted) == 1
    w.close()


def test_run_reconciles_first_and_stops(dirs, spool, store, clock):
    import threading

    inbox, _ = dirs
    st = write(inbox / "scan.pdf")
    job = _registered_but_not_moved(spool, store, "scan.pdf", st)
    stop = threading.Event()
    stop.set()
    make_watcher(store, spool, clock, use_inotify=False).run(stop, interval=0)
    assert store.get(job.doc_id).source_hash is not None
