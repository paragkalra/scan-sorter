import os
import struct
import sys

import pikepdf
import pytest

from scan_sorter import sandbox, validate
from scan_sorter.ingest import Spool
from scan_sorter.jobs import FailureKind, JobStore, Stage, State
from scan_sorter.validate import DuplicatePolicy, ValidationLimits, inspect

# -- fixtures -----------------------------------------------------------------------


def make_pdf(path, pages=2, **save):
    pdf = pikepdf.new()
    for _ in range(pages):
        pdf.add_blank_page()
    pdf.save(path, **save)
    return path


def png_bytes(width=100, height=50):
    ihdr = struct.pack(">II", width, height) + b"\x08\x02\x00\x00\x00"
    return b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + ihdr + b"\x00" * 4


def jpeg_bytes(width=640, height=480, *, sof=0xC0):
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    frame = (
        b"\xff" + bytes([sof]) + struct.pack(">HBHH", 17, 8, height, width) + b"\x03" + b"\x00" * 9
    )
    return b"\xff\xd8" + app0 + frame + b"\xff\xd9"


@pytest.fixture
def fd_of(tmp_path):
    opened = []

    def opener(data_or_path):
        path = data_or_path
        if isinstance(data_or_path, bytes):
            path = tmp_path / f"f{len(opened)}"
            path.write_bytes(data_or_path)
        fd = os.open(path, os.O_RDONLY)
        opened.append(fd)
        return fd

    yield opener
    for fd in opened:
        os.close(fd)


# -- sandbox -------------------------------------------------------------------------


def test_sandbox_refuses_shell_strings():
    with pytest.raises(TypeError):
        sandbox.run("echo hi")


def test_sandbox_kills_on_timeout():
    r = sandbox.run(
        [sys.executable, "-c", "while True: pass"],
        limits=sandbox.Limits(timeout_seconds=1, cpu_seconds=30),
    )
    assert r.timed_out


def test_sandbox_memory_limit_stops_the_child():
    r = sandbox.run(
        [sys.executable, "-c", "x = bytearray(2 << 30)"],
        limits=sandbox.Limits(memory_bytes=512 << 20),
    )
    assert r.returncode not in (0, None)


def test_sandbox_child_cannot_write_files(tmp_path):
    target = tmp_path / "out"
    code = f"f = open({str(target)!r}, 'w'); f.write('x' * 10); f.flush()"
    r = sandbox.run([sys.executable, "-c", code])
    assert r.returncode != 0
    assert not target.exists() or target.stat().st_size == 0


def test_sandbox_child_gets_a_minimal_environment(monkeypatch):
    monkeypatch.setenv("RCLONE_TOKEN", "secret")
    r = sandbox.run([sys.executable, "-c", "import os; print(sorted(os.environ))"])
    assert b"RCLONE_TOKEN" not in r.stdout


# -- sniffing and image headers --------------------------------------------------------


@pytest.mark.parametrize(
    ("head", "kind"),
    [
        (b"%PDF-1.7\n", "pdf"),
        (b"\x00" * 100 + b"%PDF-1.4", "pdf"),  # junk before the header is allowed
        (b"\x89PNG\r\n\x1a\nrest", "png"),
        (b"\xff\xd8\xff\xe0", "jpeg"),
        (b"GIF89a", None),
        (b"PK\x03\x04", None),
        (b"#!/bin/sh\n", None),
    ],
)
def test_sniff(head, kind):
    assert validate.sniff(head) == kind


def test_png_and_jpeg_sizes(fd_of):
    assert validate.png_size(fd_of(png_bytes(123, 45))) == (123, 45)
    assert validate.jpeg_size(fd_of(jpeg_bytes(640, 480))) == (640, 480)
    assert validate.jpeg_size(fd_of(jpeg_bytes(10, 20, sof=0xC2))) == (10, 20)  # progressive


@pytest.mark.parametrize(
    "data",
    [
        b"\xff\xd8\xff\xda\x00\x08" + b"\x00" * 20,  # scan before any frame
        b"\xff\xd8\xff\xe0\x00\x01",  # impossible segment length
        b"\xff\xd8\xff\xe0\x00\x10JFIF",  # truncated
        b"\xff\xd8\x00\x00\x00\x00",  # not a marker
    ],
)
def test_malformed_jpeg_headers(fd_of, data):
    assert validate.jpeg_size(fd_of(data)) is None


def test_dht_marker_is_not_mistaken_for_a_frame(fd_of):
    dht = b"\xff\xc4" + struct.pack(">H", 5) + b"\x00\x00\x00"
    data = b"\xff\xd8" + dht + jpeg_bytes(7, 9)[2:]
    assert validate.jpeg_size(fd_of(data)) == (7, 9)


# -- inspect ------------------------------------------------------------------------------


def test_inspect_pdf(fd_of, tmp_path):
    result, code = inspect(fd_of(make_pdf(tmp_path / "a.pdf", 3)), validate.DEFAULT_LIMITS)
    assert code is None
    assert result == {"kind": "pdf", "bytes": result["bytes"], "pages": 3, "restricted": False}


def test_inspect_password_protected_pdf_is_quarantined(fd_of, tmp_path):
    path = make_pdf(tmp_path / "a.pdf", encryption=pikepdf.Encryption(user="secret", owner="o"))
    assert inspect(fd_of(path), validate.DEFAULT_LIMITS) == (None, "encrypted_pdf")


def test_inspect_owner_restricted_pdf_continues(fd_of, tmp_path):
    path = make_pdf(tmp_path / "a.pdf", encryption=pikepdf.Encryption(user="", owner="owner"))
    result, code = inspect(fd_of(path), validate.DEFAULT_LIMITS)
    assert code is None and result["restricted"] is True


@pytest.mark.parametrize(
    ("data", "code"),
    [
        (b"", "empty_file"),
        (b"hello, not a document", "unsupported_type"),
        (b"%PDF-1.7\nthis is not really a pdf", "corrupt_pdf"),
        (png_bytes()[:20], "corrupt_image"),
        (png_bytes(0, 10), "corrupt_image"),
        (png_bytes(20000, 20000), "image_too_large"),
        (b"\xff\xd8\xff\xda\x00\x08" + b"\x00" * 20, "corrupt_image"),
    ],
)
def test_inspect_quarantine_codes(fd_of, data, code):
    assert inspect(fd_of(data), validate.DEFAULT_LIMITS) == (None, code)


def test_inspect_limits(fd_of, tmp_path):
    path = make_pdf(tmp_path / "a.pdf", 5)
    assert inspect(fd_of(path), ValidationLimits(max_pages=4)) == (None, "too_many_pages")
    assert inspect(fd_of(path), ValidationLimits(max_bytes=10)) == (None, "too_large")


def test_inspect_images(fd_of):
    result, code = inspect(fd_of(jpeg_bytes(640, 480)), validate.DEFAULT_LIMITS)
    assert code is None
    assert (result["kind"], result["width"], result["height"], result["pages"]) == (
        "jpeg",
        640,
        480,
        1,
    )


@pytest.mark.parametrize(
    ("fake", "code"),
    [
        (sandbox.Result(None, b"", b""), "parse_timeout"),
        (sandbox.Result(-9, b"", b""), "parse_failed"),
        (sandbox.Result(0, b"not json", b""), "parse_failed"),
        (sandbox.Result(0, b"[1, 2]", b""), "parse_failed"),
        (sandbox.Result(0, b'{"pages": "many"}', b""), "corrupt_pdf"),
        (sandbox.Result(0, b'{"pages": 0}', b""), "corrupt_pdf"),
    ],
)
def test_inspect_handles_a_misbehaving_probe(fd_of, tmp_path, monkeypatch, fake, code):
    monkeypatch.setattr(validate.sandbox, "run", lambda *a, **k: fake)
    assert inspect(fd_of(make_pdf(tmp_path / "a.pdf")), validate.DEFAULT_LIMITS) == (None, code)


def test_probe_errors_never_echo_parser_text(fd_of):
    report = validate.probe_pdf(fd_of(b"%PDF-1.7\n(SSN 123-45-6789) garbage"), sandbox.Limits())
    assert report == {"error": "corrupt_pdf"}


# -- validate() with the store and spool ---------------------------------------------------


@pytest.fixture
def env(tmp_path):
    inbox, spool_dir = tmp_path / "inbox", tmp_path / "spool"
    inbox.mkdir()
    spool_dir.mkdir()
    with Spool(inbox, spool_dir) as spool, JobStore(tmp_path / "jobs.sqlite") as store:
        yield inbox, spool, store


def adopt(env, name, data):
    inbox, spool, store = env
    (inbox / name).write_bytes(data)
    return spool.adopt(store, name, spool.inbox_entries()[name])


def pdf_bytes(tmp_path, pages=1):
    return make_pdf(tmp_path / f"src{pages}.pdf", pages).read_bytes()


def test_validate_records_the_result(env, tmp_path):
    _, spool, store = env
    job = validate.validate(store, spool, adopt(env, "a.pdf", pdf_bytes(tmp_path, 2)))
    assert job.state is State.VALIDATED
    assert store.stage_result(job.doc_id, Stage.VALIDATE)["pages"] == 2


def test_validate_quarantines_with_a_code(env):
    _, spool, store = env
    job = validate.validate(store, spool, adopt(env, "a.txt", b"plain text"))
    assert job.state is State.QUARANTINED
    assert store.history(job.doc_id)[-1][2] == "unsupported_type"


def test_validate_needs_an_adopted_received_job(env):
    _, spool, store = env
    with pytest.raises(ValueError):
        validate.validate(store, spool, store.create("x.pdf"))


def _complete(store, job):
    """Walk a job to COMPLETE (its later stages are not under test here)."""
    job = store.advance(job, State.VALIDATED, result=(Stage.VALIDATE, {}))
    job = store.advance(job, State.OCR_DONE, result=(Stage.OCR, {}))
    job = store.advance(job, State.CLASSIFIED, result=(Stage.CLASSIFY, {}))
    job = store.set_output_hash(job, "c" * 64)
    job = store.reserve_destination(job, f"x/{job.doc_id}.pdf")
    job = store.advance(job, State.READY)
    job = store.advance(job, State.UPLOADING)
    job = store.advance(job, State.VERIFIED, result=(Stage.VERIFY, {}))
    return store.advance(job, State.COMPLETE)


def test_duplicate_of_a_filed_document_is_skipped(env, tmp_path):
    _, spool, store = env
    data = pdf_bytes(tmp_path)
    first = _complete(store, adopt(env, "a.pdf", data))
    again = validate.validate(store, spool, adopt(env, "b.pdf", data))
    assert again.state is State.DISCARDED
    assert store.history(again.doc_id)[-1][2] == f"duplicate_of_{first.doc_id}"


def test_file_again_policy_processes_the_duplicate(env, tmp_path):
    _, spool, store = env
    data = pdf_bytes(tmp_path)
    _complete(store, adopt(env, "a.pdf", data))
    again = validate.validate(
        store, spool, adopt(env, "b.pdf", data), duplicates=DuplicatePolicy.FILE_AGAIN
    )
    assert again.state is State.VALIDATED


def test_duplicate_of_a_failed_job_resumes_that_job(env, tmp_path):
    _, spool, store = env
    data = pdf_bytes(tmp_path)
    first = adopt(env, "a.pdf", data)
    first = store.fail(first, FailureKind.RETRYABLE, "timeout")
    again = validate.validate(store, spool, adopt(env, "b.pdf", data))
    assert again.state is State.DISCARDED
    assert store.get(first.doc_id).state is State.RECEIVED  # retried


def test_duplicate_of_a_job_in_progress_is_dropped_even_with_file_again(env, tmp_path):
    _, spool, store = env
    data = pdf_bytes(tmp_path)
    first = adopt(env, "a.pdf", data)
    again = validate.validate(
        store, spool, adopt(env, "b.pdf", data), duplicates=DuplicatePolicy.FILE_AGAIN
    )
    assert again.state is State.DISCARDED
    assert store.history(again.doc_id)[-1][2] == f"duplicate_of_{first.doc_id}"


def test_discarded_duplicates_are_not_matched_again(env, tmp_path):
    _, spool, store = env
    data = pdf_bytes(tmp_path)
    first = _complete(store, adopt(env, "a.pdf", data))
    validate.validate(store, spool, adopt(env, "b.pdf", data))
    third = validate.validate(store, spool, adopt(env, "c.pdf", data))
    assert store.history(third.doc_id)[-1][2] == f"duplicate_of_{first.doc_id}"
