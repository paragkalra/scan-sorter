import hashlib
import multiprocessing
import os
import stat
import threading
from collections import namedtuple
from pathlib import Path

import pytest

from scan_sorter import fsutil, ingest
from scan_sorter.fsutil import Identity
from scan_sorter.ingest import INCOMING, ORIGINAL, Spool, SpoolBusyError, TransferGate, Watcher
from scan_sorter.inotify import IN_CLOSE_NOWRITE, IN_CLOSE_WRITE, IN_MODIFY, IN_OPEN
from scan_sorter.jobs import FailureKind, JobStore, QueueFullError, Stage, State

Usage = namedtuple("Usage", "total used free")
PLENTY = lambda _p: Usage(0, 0, 1 << 40)  # noqa: E731
NO_DISK = lambda _p: Usage(0, 0, 0)  # noqa: E731


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


def gen_dir(spool_dir: Path, doc_id: str, gen: int = 0) -> Path:
    return spool_dir / "jobs" / doc_id / f"g{gen}"


def original(spool_dir: Path, doc_id: str, gen: int = 0) -> Path:
    return gen_dir(spool_dir, doc_id, gen) / ORIGINAL


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def last_code(store, job):
    return store.history(job.doc_id)[-1][2]


# -- transfer gate --------------------------------------------------------------


def ident(size=10, mtime=1, ino=1, mode=stat.S_IFREG | 0o644):
    return Identity(1, ino, size, mtime, mode)


def make_gate(clock):
    return TransferGate(
        stable_seconds=10, fallback_stable_seconds=60, max_wait_seconds=600, clock=clock
    )


def started_gate(clock):
    """A gate past its first (startup) scan, watching with reliable events."""
    gate = make_gate(clock)
    gate.observe({}, events_reliable=True)
    return gate


def test_gate_closed_file_is_ready_after_stable_window():
    clock = Clock()
    gate = started_gate(clock)
    assert gate.observe({"a": ident()}, [("a", IN_CLOSE_WRITE)], events_reliable=True).ready == []
    clock.t += 9
    assert gate.observe({"a": ident()}, events_reliable=True).ready == []
    clock.t += 1
    assert gate.observe({"a": ident()}, events_reliable=True).ready == ["a"]


def test_gate_watched_arrival_without_close_is_never_ready_only_overdue():
    # A writer that pauses for minutes with the file open must not be adopted.
    clock = Clock()
    gate = started_gate(clock)
    gate.observe({"a": ident()}, events_reliable=True)
    clock.t += 599
    result = gate.observe({"a": ident()}, events_reliable=True)
    assert result.ready == [] and result.overdue == []
    clock.t += 1
    assert gate.observe({"a": ident()}, events_reliable=True).overdue == ["a"]


def test_gate_files_present_at_startup_use_fallback_window():
    clock = Clock()
    gate = make_gate(clock)
    gate.observe({"a": ident()}, events_reliable=True)
    clock.t += 60
    assert gate.observe({"a": ident()}, events_reliable=True).ready == ["a"]


def test_gate_without_events_uses_fallback_window():
    clock = Clock()
    gate = make_gate(clock)
    gate.observe({})
    gate.observe({"a": ident()})
    clock.t += 59
    assert gate.observe({"a": ident()}).ready == []
    clock.t += 1
    assert gate.observe({"a": ident()}).ready == ["a"]


def test_gate_change_restarts_the_window_and_clears_close():
    clock = Clock()
    gate = started_gate(clock)
    gate.observe({"a": ident(size=10)}, [("a", IN_CLOSE_WRITE)], events_reliable=True)
    clock.t += 9
    gate.observe({"a": ident(size=20)}, events_reliable=True)  # reopened, appended
    clock.t += 100
    assert gate.observe({"a": ident(size=20)}, events_reliable=True).ready == []
    gate.observe({"a": ident(size=20)}, [("a", IN_CLOSE_WRITE)], events_reliable=True)
    clock.t += 10
    assert gate.observe({"a": ident(size=20)}, events_reliable=True).ready == ["a"]


def test_gate_replaced_file_starts_over():
    clock = Clock()
    gate = make_gate(clock)
    gate.observe({"a": ident(ino=1)})
    clock.t += 590
    gate.observe({"a": ident(ino=2, size=1)})
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


def test_gate_non_regular_entries_are_ready_at_once():
    gate = started_gate(Clock())
    assert gate.observe({"l": ident(mode=stat.S_IFLNK | 0o777)}).ready == ["l"]


def test_gate_overflow_falls_back_to_stability_window():
    clock = Clock()
    gate = started_gate(clock)
    gate.observe({"a": ident()}, [("a", IN_CLOSE_WRITE)], events_reliable=True)
    gate.forget_closed()
    clock.t += 10
    assert gate.observe({"a": ident()}, events_reliable=True).ready == []
    clock.t += 50
    assert gate.observe({"a": ident()}, events_reliable=True).ready == ["a"]


def test_gate_forgets_vanished_names_and_ignores_unknown_closes():
    gate = started_gate(Clock())
    gate.observe({"a": ident()})
    assert gate.observe({}, [("ghost", IN_CLOSE_WRITE)]).ready == []
    assert gate._seen == {}


# -- spool setup -----------------------------------------------------------------------


def test_spool_refuses_symlinked_directories(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "inbox").symlink_to(real)
    (tmp_path / "spool").mkdir()
    with pytest.raises(OSError):
        Spool(tmp_path / "inbox", tmp_path / "spool")


def test_spool_dirs_are_private_and_jobs_entry_is_synced(dirs, monkeypatch):
    inbox, spool_dir = dirs
    synced = []
    real_fsync = os.fsync
    monkeypatch.setattr(ingest.os, "fsync", lambda fd: (synced.append(fd), real_fsync(fd)))
    with Spool(inbox, spool_dir) as s:
        assert s.spool_fd in synced
        assert stat.S_IMODE(os.stat(spool_dir).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(spool_dir / "jobs").st_mode) == 0o700


def test_spool_skips_dotfiles(dirs, spool):
    inbox, _ = dirs
    write(inbox / ".~upload.tmp")
    write(inbox / "scan.pdf")
    assert list(spool.inbox_entries()) == ["scan.pdf"]


# -- adoption ------------------------------------------------------------------------


def test_adopt_makes_a_private_copy_and_records_hash_and_intake(dirs, spool, store):
    inbox, spool_dir = dirs
    data = b"%PDF-1.7 hello"
    st = write(inbox / "scan001.pdf", data)
    job = spool.adopt(store, "scan001.pdf", st)
    assert (job.state, job.source_hash, job.source_name) == (
        State.RECEIVED,
        sha(data),
        "scan001.pdf",
    )
    assert os.listdir(inbox) == []
    copy = original(spool_dir, job.doc_id)
    assert copy.read_bytes() == data
    copy_id = Identity.of(os.lstat(copy))
    assert not copy_id.same_file(st)  # a new inode the printer never had
    assert stat.S_IMODE(copy_id.mode) == 0o600
    assert os.listdir(gen_dir(spool_dir, job.doc_id)) == [ORIGINAL]
    assert stat.S_IMODE(os.stat(gen_dir(spool_dir, job.doc_id)).st_mode) == 0o700
    intake = store.stage_result(job.doc_id, Stage.INTAKE)
    assert bytes.fromhex(intake["inbox_name_hex"]) == b"scan001.pdf"
    assert (intake["gen"], intake["quarantine"]) == (0, None)
    assert Identity.from_dict(intake) == st


def test_writer_keeping_its_handle_cannot_change_the_adopted_copy(dirs, spool, store):
    inbox, spool_dir = dirs
    write(inbox / "scan.pdf", b"original bytes")
    handle = open(inbox / "scan.pdf", "r+b")  # noqa: SIM115
    try:
        job = spool.adopt(store, "scan.pdf", spool.inbox_entries()["scan.pdf"])
        handle.seek(0)
        handle.write(b"TAMPERED")
        handle.flush()
    finally:
        handle.close()
    assert original(spool_dir, job.doc_id).read_bytes() == b"original bytes"
    assert store.get(job.doc_id).source_hash == sha(b"original bytes")


def test_hardlinked_input_is_quarantined(dirs, spool, store):
    inbox, _ = dirs
    write(inbox / "scan.pdf")
    os.link(inbox / "scan.pdf", inbox / "alias.pdf")
    job = spool.adopt(store, "scan.pdf", spool.inbox_entries()["scan.pdf"])
    assert (job.state, last_code(store, job)) == (State.QUARANTINED, "multiple_links")


def test_source_changing_during_the_copy_is_quarantined(dirs, spool, store, monkeypatch):
    inbox, spool_dir = dirs
    write(inbox / "scan.pdf", b"part one")
    real_pread = os.pread

    appended = []

    def pread_while_writer_appends(fd, n, off):
        data = real_pread(fd, n, off)
        if data and not appended:
            appended.append(True)
            appender = os.open(f"/proc/self/fd/{fd}", os.O_WRONLY | os.O_APPEND)
            os.write(appender, b" more")
            os.close(appender)
        return data

    monkeypatch.setattr(fsutil.os, "pread", pread_while_writer_appends)
    job = spool.adopt(store, "scan.pdf", spool.inbox_entries()["scan.pdf"])
    assert (job.state, last_code(store, job)) == (State.QUARANTINED, "changed_during_adoption")
    assert ORIGINAL not in os.listdir(gen_dir(spool_dir, job.doc_id))


def test_private_copy_reports_a_reset_mtime_as_a_change(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.write_bytes(b"abc")
    st = os.stat(src)
    real_pread = os.pread

    def pread_then_tamper(f, n, off):
        data = real_pread(f, n, off)
        if data:
            with open(src, "r+b") as w:
                w.write(b"xyz")
            os.utime(src, ns=(st.st_atime_ns, st.st_mtime_ns))  # client resets mtime
        return data

    fd = os.open(src, os.O_RDONLY)
    dir_fd = os.open(tmp_path, os.O_RDONLY)
    try:
        monkeypatch.setattr(fsutil.os, "pread", pread_then_tamper)
        _, stable = fsutil.private_copy(fd, "dst", dir_fd)
    finally:
        os.close(fd)
        os.close(dir_fd)
    assert not stable


def test_adopt_symlink_is_quarantined_and_target_untouched(dirs, spool, store, tmp_path):
    inbox, spool_dir = dirs
    secret = tmp_path / "secret.txt"
    secret.write_text("private")
    (inbox / "evil.pdf").symlink_to(secret)
    job = spool.adopt(store, "evil.pdf", fsutil.lstat_at("evil.pdf", spool.inbox_fd))
    assert (job.state, last_code(store, job)) == (State.QUARANTINED, "not_regular_file")
    assert secret.read_text() == "private"
    assert (gen_dir(spool_dir, job.doc_id) / INCOMING).is_symlink()


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


def test_source_deleted_at_the_rename_fails_the_job_cleanly(dirs, spool, store, monkeypatch):
    inbox, _ = dirs
    st = write(inbox / "scan.pdf")
    real_rename = os.rename

    def delete_first(src, dst, **kw):
        if dst == INCOMING:
            (inbox / "scan.pdf").unlink()
        return real_rename(src, dst, **kw)

    monkeypatch.setattr(ingest.os, "rename", delete_first)
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
    inbox, _ = dirs
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


def _registered(store, name, st, *, gen=0, quarantine=None):
    return store.create(name, intake=ingest._intake(name, st, gen, quarantine))


def test_reconcile_finishes_an_adoption_cut_before_the_rename(dirs, spool, store):
    inbox, spool_dir = dirs
    st = write(inbox / "scan.pdf", b"abc")
    job = _registered(store, "scan.pdf", st)
    assert spool.reconcile(store) == [job.doc_id]
    assert store.get(job.doc_id).source_hash == sha(b"abc")
    assert original(spool_dir, job.doc_id).read_bytes() == b"abc"
    assert os.listdir(inbox) == []


def test_reconcile_finishes_an_adoption_cut_after_the_rename(dirs, spool, store):
    inbox, spool_dir = dirs
    st = write(inbox / "scan.pdf", b"abc")
    job = _registered(store, "scan.pdf", st)
    gen_dir(spool_dir, job.doc_id).mkdir(parents=True)
    os.rename(inbox / "scan.pdf", gen_dir(spool_dir, job.doc_id) / INCOMING)
    spool.reconcile(store)
    assert store.get(job.doc_id).source_hash == sha(b"abc")
    assert os.listdir(gen_dir(spool_dir, job.doc_id)) == [ORIGINAL]


def test_reconcile_keeps_quarantine_intent(dirs, spool, store):
    inbox, _ = dirs
    st = write(inbox / "slow.pdf", b"half a scan")
    job = _registered(store, "slow.pdf", st, quarantine="incomplete_transfer")
    spool.reconcile(store)
    job = store.get(job.doc_id)
    assert (job.state, job.source_hash) == (State.QUARANTINED, None)
    assert last_code(store, job) == "incomplete_transfer"


def test_recovery_redoes_durability_barriers_before_the_hash(dirs, spool, store, monkeypatch):
    inbox, spool_dir = dirs
    st = write(inbox / "scan.pdf", b"abc")
    job = _registered(store, "scan.pdf", st)
    g = gen_dir(spool_dir, job.doc_id)
    g.mkdir(parents=True)
    os.rename(inbox / "scan.pdf", g / INCOMING)
    events = []
    real_fsync, real_set = os.fsync, store.set_source_hash

    def fsync(fd):
        events.append(os.readlink(f"/proc/self/fd/{fd}"))
        real_fsync(fd)

    def set_source_hash(*a, **k):
        events.append("HASH")
        return real_set(*a, **k)

    monkeypatch.setattr(ingest.os, "fsync", fsync)
    store.set_source_hash = set_source_hash
    spool.reconcile(store)
    before_hash = events[: events.index("HASH")]
    for needed in (
        str(g / ORIGINAL),
        str(g),
        str(g.parent),
        str(spool_dir / "jobs"),
        str(inbox),
    ):
        assert needed in before_hash, needed


def test_reconcile_does_not_take_a_different_file_with_the_same_name(dirs, spool, store):
    inbox, _ = dirs
    st = write(inbox / "scan.pdf", b"first")
    job = _registered(store, "scan.pdf", st)
    (inbox / "scan.pdf").unlink()
    write(inbox / "scan.pdf", b"second scan, same name")
    spool.reconcile(store)
    assert store.get(job.doc_id).failure_code == "source_missing"
    assert (inbox / "scan.pdf").read_bytes() == b"second scan, same name"


def test_reconcile_moves_a_replacement_into_its_own_generation(dirs, spool, store):
    inbox, spool_dir = dirs
    old = spool.adopt(store, "scan.pdf", write(inbox / "scan.pdf", b"old, unreadable"))
    old = store.advance(old, State.QUARANTINED, code="corrupt")
    st = write(inbox / "rescan.pdf", b"new and good")
    store.replace(old, "rescan.pdf", intake=ingest._intake("rescan.pdf", st, 1, None))
    spool.reconcile(store)
    job = store.get(old.doc_id)
    assert job.source_hash == sha(b"new and good")
    assert original(spool_dir, job.doc_id, 1).read_bytes() == b"new and good"
    assert original(spool_dir, job.doc_id, 0).read_bytes() == b"old, unreadable"


def test_reconcile_adopts_spool_dirs_without_a_row(dirs, spool, store):
    _, spool_dir = dirs
    doc_id = "ab" * 16
    gen_dir(spool_dir, doc_id).mkdir(parents=True)
    original(spool_dir, doc_id).write_bytes(b"orphan")
    assert spool.reconcile(store) == [doc_id]
    job = store.get(doc_id)
    assert (job.source_name, job.source_hash) == ("recovered", sha(b"orphan"))


def test_reconcile_removes_empty_orphan_dirs_and_ignores_junk(dirs, spool, store):
    _, spool_dir = dirs
    (spool_dir / "jobs" / ("cd" * 16)).mkdir()
    (spool_dir / "jobs" / "not-a-job" / "g0").mkdir(parents=True)
    (spool_dir / "jobs" / "not-a-job" / "g0" / ORIGINAL).write_bytes(b"x")
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
        gen_dir(spool_dir, doc_id).mkdir(parents=True)
        original(spool_dir, doc_id).write_bytes(b"x")
        spool.reconcile(store)
        assert store.get(doc_id).state is State.RECEIVED


# -- crash injection through the real adopt() ---------------------------------------
# A child process runs Spool.adopt and dies at a chosen point; the parent restarts,
# reconciles, and checks exactly one job owns the scan with its hash recorded.

CRASHED = 77


def _crash_during_adopt(inbox, spool_dir, db_path, point, quarantine):
    real_rename = os.rename
    renames = []

    def die():
        os._exit(CRASHED)

    def rename(*a, **k):
        renames.append(a)
        if point == "before_move" and len(renames) == 1:
            die()
        if point == "before_publish_copy" and len(renames) == 2:
            die()
        real_rename(*a, **k)
        if point == "after_move" and len(renames) == 1:
            die()

    ingest.os.rename = rename
    if point == "during_copy":
        ingest.fsutil.private_copy = lambda *a, **k: die()
    if point == "before_hash":
        ingest.fsutil.sha256_file = lambda *a, **k: die()
    with Spool(inbox, spool_dir) as spool, JobStore(db_path) as store:
        spool.adopt(
            store,
            "scan.pdf",
            spool.inbox_entries()["scan.pdf"],
            quarantine_code=quarantine,
            ignore_capacity=True,
        )
    os._exit(3)


POINTS = ["before_move", "after_move", "during_copy", "before_publish_copy", "before_hash"]


def _crash_and_recover(dirs, tmp_path, point, quarantine=None):
    inbox, spool_dir = dirs
    db_path = tmp_path / "jobs.sqlite"
    write(inbox / "scan.pdf", b"precious")
    proc = multiprocessing.get_context("fork").Process(
        target=_crash_during_adopt, args=(inbox, spool_dir, db_path, point, quarantine)
    )
    proc.start()
    proc.join(30)
    assert proc.exitcode == CRASHED
    with Spool(inbox, spool_dir) as spool, JobStore(db_path) as store:
        spool.reconcile(store)
        jobs = store.jobs_in(*State)
        assert len(jobs) == 1
        assert os.listdir(inbox) == []
        return store.history(jobs[0].doc_id), jobs[0]


@pytest.mark.parametrize("point", POINTS)
def test_crash_during_adoption_is_recovered(dirs, tmp_path, point):
    _, job = _crash_and_recover(dirs, tmp_path, point)
    assert (job.state, job.source_hash) == (State.RECEIVED, sha(b"precious"))
    assert original(dirs[1], job.doc_id).read_bytes() == b"precious"
    assert os.listdir(gen_dir(dirs[1], job.doc_id)) == [ORIGINAL]


@pytest.mark.parametrize("point", ["before_move", "after_move"])
def test_crash_during_overdue_adoption_still_quarantines(dirs, tmp_path, point):
    history, job = _crash_and_recover(dirs, tmp_path, point, quarantine="incomplete_transfer")
    assert job.state is State.QUARANTINED
    assert history[-1][2] == "incomplete_transfer"


# -- watcher -----------------------------------------------------------------------------


@pytest.fixture
def clock():
    return Clock()


def make_watcher(store, spool, clock, **kw):
    kw.setdefault("disk_usage", PLENTY)
    return Watcher(store, spool, make_gate(clock), min_free_bytes=1, **kw)


def test_watcher_adopts_a_closed_file_after_the_stable_window(dirs, spool, store, clock):
    inbox, _ = dirs
    w = make_watcher(store, spool, clock)
    if w.inotify is None:
        pytest.skip("inotify unavailable")
    w.poll_once()  # startup scan
    write(inbox / "scan.pdf")
    assert w.poll_once().adopted == []
    clock.t += 10
    assert len(w.poll_once().adopted) == 1
    assert os.listdir(inbox) == []
    w.close()


def test_watcher_does_not_adopt_a_file_held_open_by_its_writer(dirs, spool, store, clock):
    inbox, _ = dirs
    w = make_watcher(store, spool, clock)
    if w.inotify is None:
        pytest.skip("inotify unavailable")
    w.poll_once()
    with open(inbox / "scan.pdf", "wb") as f:
        f.write(b"first pages")
        f.flush()
        w.poll_once()
        clock.t += 120  # writer pauses for two minutes, file still open
        assert w.poll_once().adopted == []
        f.write(b" last page")
    w.poll_once()
    clock.t += 10
    assert len(w.poll_once().adopted) == 1
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
    w = make_watcher(store, spool, clock, use_inotify=False, disk_usage=NO_DISK)
    write(inbox / "scan.pdf")
    w.poll_once()
    clock.t += 60
    report = w.poll_once()
    assert (report.adopted, report.paused) == ([], "disk_low")
    assert os.listdir(inbox) == ["scan.pdf"]


def test_watcher_pauses_overdue_adoption_on_low_disk(dirs, spool, store, clock):
    inbox, _ = dirs
    w = make_watcher(store, spool, clock, use_inotify=False, disk_usage=NO_DISK)
    for i in range(70):
        write(inbox / "slow.pdf", b"x" * (i + 1))
        report = w.poll_once()
        clock.t += 10
    assert (report.quarantined, report.paused) == ([], "disk_low")
    assert os.listdir(inbox) == ["slow.pdf"]


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
        assert last_code(store, store.get(report.quarantined[0])) == "incomplete_transfer"
        assert os.listdir(inbox) == []


def test_overdue_file_growing_during_registration_is_still_quarantined(dirs, spool, store):
    inbox, _ = dirs
    st = write(inbox / "slow.pdf", b"x")
    real_create = store.create

    def create_while_writer_appends(*a, **k):
        with open(inbox / "slow.pdf", "ab") as f:
            f.write(b"more")
        return real_create(*a, **k)

    store.create = create_while_writer_appends
    job = spool.adopt(store, "slow.pdf", st, quarantine_code="incomplete_transfer")
    assert job.state is State.QUARANTINED


def test_watcher_keeps_going_after_one_entry_errors(dirs, spool, store, clock, monkeypatch):
    inbox, _ = dirs
    w = make_watcher(store, spool, clock, use_inotify=False)
    write(inbox / "a.pdf")
    write(inbox / "b.pdf")
    w.poll_once()
    clock.t += 60
    real_adopt = spool.adopt

    def adopt(store, name, *a, **k):
        if name == "a.pdf":
            raise PermissionError(13, "denied")
        return real_adopt(store, name, *a, **k)

    monkeypatch.setattr(spool, "adopt", adopt)
    report = w.poll_once()
    assert len(report.adopted) == 1
    assert os.listdir(inbox) == ["a.pdf"]


def test_watcher_quarantines_symlinks_immediately(dirs, spool, store, clock, tmp_path):
    inbox, _ = dirs
    (tmp_path / "target").write_text("x")
    (inbox / "link.pdf").symlink_to(tmp_path / "target")
    report = make_watcher(store, spool, clock, use_inotify=False).poll_once()
    assert len(report.quarantined) == 1


def test_run_reconciles_first_and_stops(dirs, spool, store, clock):
    inbox, _ = dirs
    job = _registered(store, "scan.pdf", write(inbox / "scan.pdf"))
    stop = threading.Event()
    stop.set()
    make_watcher(store, spool, clock, use_inotify=False).run(stop, interval=0)
    assert store.get(job.doc_id).source_hash is not None


def test_gate_later_event_cancels_an_earlier_close():
    clock = Clock()
    gate = started_gate(clock)
    gate.observe({"a": ident()}, [("a", IN_CLOSE_WRITE)], events_reliable=True)
    gate.observe({"a": ident()}, [("a", IN_MODIFY)], events_reliable=True)
    clock.t += 100
    assert gate.observe({"a": ident()}, events_reliable=True).ready == []


def test_inotify_reports_events_in_order(dirs, spool):
    from scan_sorter.inotify import IN_CREATE, IN_DELETE, try_inotify

    inbox, _ = dirs
    ino = try_inotify(spool.inbox_fd)
    if ino is None:
        pytest.skip("inotify unavailable")
    try:
        write(inbox / "a.pdf")
        (inbox / "a.pdf").unlink()
        masks = [m for n, m, _c in ino.read() if n == b"a.pdf"]
        assert masks[0] & IN_CREATE and masks[-1] & IN_DELETE
        assert any(m & IN_CLOSE_WRITE for m in masks)
    finally:
        ino.close()


def test_close_of_a_deleted_file_does_not_certify_its_replacement(dirs, spool, store, clock):
    inbox, spool_dir = dirs
    w = make_watcher(store, spool, clock)
    if w.inotify is None:
        pytest.skip("inotify unavailable")
    w.poll_once()
    write(inbox / "scan.pdf", b"first, finished")
    (inbox / "scan.pdf").unlink()
    with open(inbox / "scan.pdf", "wb") as f:
        f.write(b"second, still being written")
        f.flush()
        w.poll_once()
        clock.t += 120
        assert w.poll_once().adopted == []
        f.write(b" and the last page")
    w.poll_once()
    clock.t += 10
    adopted = w.poll_once().adopted
    assert len(adopted) == 1
    assert original(spool_dir, adopted[0]).read_bytes().endswith(b"the last page")
    w.close()


def test_source_bytes_are_synced_before_leaving_the_inbox(dirs, spool, store, monkeypatch):
    inbox, _ = dirs
    st = write(inbox / "slow.pdf", b"partial")
    events = []
    real_fsync, real_rename = os.fsync, os.rename

    def fsync(fd):
        events.append(("fsync", os.readlink(f"/proc/self/fd/{fd}")))
        real_fsync(fd)

    def rename(src, dst, **kw):
        events.append(("rename", src))
        real_rename(src, dst, **kw)

    monkeypatch.setattr(fsutil.os, "fsync", fsync)
    monkeypatch.setattr(ingest.os, "rename", rename)
    spool.adopt(store, "slow.pdf", st, quarantine_code="incomplete_transfer")
    assert events.index(("fsync", str(inbox / "slow.pdf"))) < events.index(("rename", "slow.pdf"))


def test_adoption_cut_by_a_transient_error_resumes_on_the_next_poll(
    dirs, tmp_path, clock, monkeypatch
):
    import errno as errno_mod

    inbox, spool_dir = dirs
    with Spool(inbox, spool_dir) as spool, JobStore(tmp_path / "q.sqlite", max_active=1) as store:
        w = make_watcher(store, spool, clock, use_inotify=False)
        write(inbox / "a.pdf", b"aaa")
        w.poll_once()
        clock.t += 60
        real_copy = fsutil.private_copy
        calls = []

        def copy_fails_once(*a, **k):
            calls.append(1)
            if len(calls) == 1:
                raise OSError(errno_mod.ENOSPC, "No space left on device")
            return real_copy(*a, **k)

        monkeypatch.setattr(ingest.fsutil, "private_copy", copy_fails_once)
        report = w.poll_once()
        assert report.adopted == []
        [job] = store.jobs_in(State.RECEIVED)
        assert job.source_hash is None
        write(inbox / "b.pdf", b"bbb")
        w.poll_once()  # resumes a.pdf first
        assert store.get(job.doc_id).source_hash == sha(b"aaa")
        clock.t += 60
        store.fail(store.get(job.doc_id), FailureKind.PERMANENT, "done")
        assert len(w.poll_once().adopted) == 1  # the queue is not stuck


def test_interrupted_orphan_recovery_can_be_resumed(dirs, spool, store, monkeypatch):
    _, spool_dir = dirs
    doc_id = "ab" * 16
    gen_dir(spool_dir, doc_id).mkdir(parents=True)
    original(spool_dir, doc_id).write_bytes(b"orphan")
    real_hash = fsutil.sha256_file

    def hash_fails(*a, **k):
        raise OSError(5, "I/O error")

    monkeypatch.setattr(ingest.fsutil, "sha256_file", hash_fails)
    with pytest.raises(OSError):
        spool.reconcile(store)
    monkeypatch.setattr(ingest.fsutil, "sha256_file", real_hash)
    spool.reconcile(store)
    assert store.get(doc_id).source_hash == sha(b"orphan")


def test_files_discovered_during_an_overflow_use_the_fallback(dirs, spool, store, clock):
    inbox, _ = dirs
    w = make_watcher(store, spool, clock)
    if w.inotify is None:
        pytest.skip("inotify unavailable")
    w.poll_once()
    write(inbox / "scan.pdf")
    w.inotify.read()  # its close event is lost in the overflow
    w.inotify.overflowed = True
    w.poll_once()
    clock.t += 60
    assert len(w.poll_once().adopted) == 1
    w.close()


def test_gate_reopened_file_waits_for_the_new_handle_to_close():
    clock = Clock()
    gate = started_gate(clock)
    gate.observe({"a": ident()}, [("a", IN_CLOSE_WRITE)], events_reliable=True)
    gate.observe({"a": ident()}, [("a", IN_OPEN)], events_reliable=True)  # reopened, no write
    clock.t += 100
    assert gate.observe({"a": ident()}, events_reliable=True).ready == []
    gate.observe({"a": ident()}, [("a", IN_CLOSE_WRITE)], events_reliable=True)
    clock.t += 10
    assert gate.observe({"a": ident()}, events_reliable=True).ready == ["a"]


def test_gate_a_reader_does_not_cancel_a_finished_write():
    clock = Clock()
    gate = started_gate(clock)
    events = [("a", IN_CLOSE_WRITE), ("a", IN_OPEN), ("a", IN_CLOSE_NOWRITE)]
    gate.observe({"a": ident()}, events, events_reliable=True)
    clock.t += 10
    assert gate.observe({"a": ident()}, events_reliable=True).ready == ["a"]


def test_gate_open_handles_also_block_the_fallback():
    clock = Clock()
    gate = make_gate(clock)
    gate.observe({"a": ident()}, [("a", IN_OPEN)], events_reliable=True)  # startup file
    clock.t += 100
    assert gate.observe({"a": ident()}, events_reliable=True).ready == []


def test_watcher_waits_for_a_writer_that_reopens_without_writing(dirs, spool, store, clock):
    inbox, spool_dir = dirs
    w = make_watcher(store, spool, clock)
    if w.inotify is None:
        pytest.skip("inotify unavailable")
    w.poll_once()
    write(inbox / "scan.pdf", b"page one")
    w.poll_once()
    with open(inbox / "scan.pdf", "ab") as f:
        w.poll_once()
        clock.t += 120
        assert w.poll_once().adopted == []
        f.write(b" page two")
    w.poll_once()
    clock.t += 10
    [doc] = w.poll_once().adopted
    assert original(spool_dir, doc).read_bytes() == b"page one page two"
    w.close()


def test_only_one_process_can_own_a_spool(dirs):
    with Spool(*dirs):
        with pytest.raises(SpoolBusyError):
            Spool(*dirs)
    with Spool(*dirs):
        pass  # released on close


def test_quarantine_recovery_redoes_barriers_first(dirs, spool, store, monkeypatch):
    inbox, spool_dir = dirs
    st = write(inbox / "slow.pdf", b"partial")
    job = _registered(store, "slow.pdf", st, quarantine="incomplete_transfer")
    g = gen_dir(spool_dir, job.doc_id)
    g.mkdir(parents=True)
    os.rename(inbox / "slow.pdf", g / INCOMING)
    events = []
    real_fsync, real_advance = os.fsync, store.advance

    def fsync(fd):
        events.append(os.readlink(f"/proc/self/fd/{fd}"))
        real_fsync(fd)

    def advance(*a, **k):
        events.append("COMMIT")
        return real_advance(*a, **k)

    monkeypatch.setattr(fsutil.os, "fsync", fsync)
    store.advance = advance
    spool.reconcile(store)
    before = events[: events.index("COMMIT")]
    for needed in (str(g / INCOMING), str(g), str(g.parent), str(spool_dir / "jobs"), str(inbox)):
        assert needed in before, needed


def test_orphan_with_only_an_unverified_input_is_quarantined(dirs, spool, store):
    _, spool_dir = dirs
    doc_id = "12" * 16
    gen_dir(spool_dir, doc_id).mkdir(parents=True)
    (gen_dir(spool_dir, doc_id) / INCOMING).write_bytes(b"half moved")
    assert spool.reconcile(store) == [doc_id]
    job = store.get(doc_id)
    assert (job.state, last_code(store, job)) == (State.QUARANTINED, "orphaned_input")


def test_upload_renamed_into_place_while_still_open_is_not_adopted(dirs, spool, store, clock):
    inbox, spool_dir = dirs
    w = make_watcher(store, spool, clock)
    if w.inotify is None:
        pytest.skip("inotify unavailable")
    w.poll_once()
    with open(inbox / ".upload", "wb") as f:
        f.write(b"page one")
        f.flush()
        os.rename(inbox / ".upload", inbox / "scan.pdf")
        w.poll_once()
        clock.t += 120
        assert w.poll_once().adopted == []
        f.write(b" page two")
    w.poll_once()
    clock.t += 10
    [doc] = w.poll_once().adopted
    assert original(spool_dir, doc).read_bytes() == b"page one page two"
    w.close()


def test_upload_closed_then_renamed_into_place_is_adopted_promptly(dirs, spool, store, clock):
    inbox, _ = dirs
    w = make_watcher(store, spool, clock)
    if w.inotify is None:
        pytest.skip("inotify unavailable")
    w.poll_once()
    write(inbox / ".upload", b"complete scan")
    w.poll_once()
    os.rename(inbox / ".upload", inbox / "scan.pdf")
    w.poll_once()
    clock.t += 10
    assert len(w.poll_once().adopted) == 1
    w.close()


def test_file_moved_in_from_elsewhere_uses_the_fallback(dirs, spool, store, clock, tmp_path):
    inbox, _ = dirs
    w = make_watcher(store, spool, clock)
    if w.inotify is None:
        pytest.skip("inotify unavailable")
    w.poll_once()
    write(tmp_path / "outside.pdf")
    os.rename(tmp_path / "outside.pdf", inbox / "scan.pdf")
    w.poll_once()
    clock.t += 59
    assert w.poll_once().adopted == []
    clock.t += 1
    assert len(w.poll_once().adopted) == 1
    w.close()


def test_failed_file_fsync_keeps_the_job_resumable(dirs, spool, store, monkeypatch):
    inbox, spool_dir = dirs
    st = write(inbox / "slow.pdf", b"partial")
    job = _registered(store, "slow.pdf", st, quarantine="incomplete_transfer")
    g = gen_dir(spool_dir, job.doc_id)
    g.mkdir(parents=True)
    os.rename(inbox / "slow.pdf", g / INCOMING)

    def eio(*a, **k):
        raise OSError(5, "I/O error")

    monkeypatch.setattr(ingest.fsutil, "fsync_file", eio)
    with pytest.raises(OSError):
        spool.reconcile(store)
    assert store.get(job.doc_id).state is State.RECEIVED
    monkeypatch.undo()
    spool.reconcile(store)
    assert store.get(job.doc_id).state is State.QUARANTINED
