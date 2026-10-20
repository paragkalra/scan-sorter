"""Validation and deduplication: RECEIVED -> VALIDATED (docs/PLAN.md, "Validation",
"Deduplication semantics").

Type is decided from magic bytes, never the file name. PDFs are opened only
by the sandboxed probe; images only have their headers parsed here (they are
decoded later, in the sandboxed OCR stage). Every rejection is a quarantine
with a short code, so a person can see and decide.
"""

from __future__ import annotations

import json
import logging
import os
import struct
import zlib
from dataclasses import dataclass
from enum import StrEnum

from scan_sorter import sandbox
from scan_sorter.ingest import Spool
from scan_sorter.jobs import Job, JobStore, NotCanonicalError, StaleJobError, State

log = logging.getLogger(__name__)

_HEAD = 1024  # PDF readers accept the %PDF- header anywhere in the first 1 KiB


class DuplicatePolicy(StrEnum):
    SKIP = "skip"  # a document already filed is not filed again
    FILE_AGAIN = "file_again"


@dataclass(frozen=True)
class ValidationLimits:
    max_bytes: int = 100 << 20
    max_pages: int = 500
    max_image_pixels: int = 100_000_000
    probe: sandbox.Limits = sandbox.Limits(timeout_seconds=60, cpu_seconds=60)


DEFAULT_LIMITS = ValidationLimits()


def sniff(head: bytes) -> str | None:
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if b"%PDF-" in head[:_HEAD]:
        return "pdf"
    return None


_PNG_DEPTHS = {0: {1, 2, 4, 8, 16}, 2: {8, 16}, 3: {1, 2, 4, 8}, 4: {8, 16}, 6: {8, 16}}


def png_size(fd: int) -> tuple[int, int] | None:
    """Size from a complete, CRC-checked IHDR chunk with legal field values."""
    data = os.pread(fd, 33, 0)
    if len(data) < 33 or data[8:16] != b"\x00\x00\x00\x0dIHDR":
        return None
    ihdr = data[16:29]
    (crc,) = struct.unpack(">I", data[29:33])
    if zlib.crc32(data[12:29]) != crc:
        return None
    width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", ihdr)
    if depth not in _PNG_DEPTHS.get(color, ()) or compression or filtering or interlace > 1:
        return None
    return width, height


# Start-of-frame markers carry the image size; C4 (DHT), C8 (JPG) and CC
# (DAC) share the range but are not frames.
_SOF = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}


def jpeg_size(fd: int) -> tuple[int, int] | None:
    """Walk JPEG segment headers to the first frame header.

    Reads only each segment's header (positional reads), so metadata of any
    size before the frame is fine; the walk is bounded by the file size.
    """
    size = os.fstat(fd).st_size
    if os.pread(fd, 2, 0) != b"\xff\xd8":
        return None
    pos = 2
    while pos + 4 <= size:
        head = os.pread(fd, 4, pos)
        if len(head) < 4 or head[0] != 0xFF:
            return None
        marker = head[1]
        if marker == 0xFF:  # fill byte
            pos += 1
            continue
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:  # no length
            pos += 2
            continue
        (length,) = struct.unpack(">H", head[2:4])
        if length < 2 or pos + 2 + length > size:
            return None
        if marker in _SOF:
            frame = os.pread(fd, length - 2, pos + 4)
            if len(frame) < 6:
                return None
            precision, height, width, components = struct.unpack(">BHHB", frame[:6])
            if (
                precision not in (8, 12, 16)
                or not 1 <= components <= 4
                or length != 8 + 3 * components
            ):
                return None
            return width, height
        if marker in (0xDA, 0xD9):  # scan or end of image before any frame header
            return None
        pos += 2 + length
    return None


def probe_pdf(fd: int, limits: sandbox.Limits) -> dict:
    os.lseek(fd, 0, os.SEEK_SET)
    result = sandbox.run(sandbox.python_module("scan_sorter.probe"), stdin_fd=fd, limits=limits)
    if result.timed_out:
        return {"error": "parse_timeout"}
    if result.returncode != 0:
        # Killed by a resource limit, or crashed inside the parser.
        return {"error": "parse_failed"}
    try:
        report = json.loads(result.stdout.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return {"error": "parse_failed"}
    if not isinstance(report, dict):
        return {"error": "parse_failed"}
    return report


def inspect(fd: int, limits: ValidationLimits) -> tuple[dict | None, str | None]:
    """(validation result, None) or (None, quarantine code)."""
    size = os.fstat(fd).st_size
    if size == 0:
        return None, "empty_file"
    if size > limits.max_bytes:
        return None, "too_large"
    kind = sniff(os.pread(fd, _HEAD, 0))
    if kind is None:
        return None, "unsupported_type"
    result: dict = {"kind": kind, "bytes": size}
    if kind == "pdf":
        report = probe_pdf(fd, limits.probe)
        if "error" in report:
            return None, str(report["error"])
        pages = report.get("pages")
        if not isinstance(pages, int) or pages < 1:
            return None, "corrupt_pdf"
        if pages > limits.max_pages:
            return None, "too_many_pages"
        # Owner-password ("restricted") PDFs open without a password and are
        # common for statements; they continue. Ones needing a password do not.
        result.update(pages=pages, restricted=bool(report.get("restricted")))
    else:
        dims = png_size(fd) if kind == "png" else jpeg_size(fd)
        if dims is None or 0 in dims:
            return None, "corrupt_image"
        width, height = dims
        if width * height > limits.max_image_pixels:
            return None, "image_too_large"
        result.update(pages=1, width=width, height=height)
    return result, None


def _supersede_if_duplicate(
    store: JobStore, job: Job, policy: DuplicatePolicy, winner: Job | None
) -> Job | None:
    """Discard `job` in favour of `winner` unless it is the winner itself."""
    if winner is None or winner.doc_id == job.doc_id:
        return None
    log.info("job %s is a duplicate of %s", job.doc_id, winner.doc_id)
    return store.supersede(job, winner, f"duplicate_of_{winner.doc_id}")


def validate(
    store: JobStore,
    spool: Spool,
    job: Job,
    *,
    limits: ValidationLimits = DEFAULT_LIMITS,
    duplicates: DuplicatePolicy = DuplicatePolicy.SKIP,
    attempts: int = 5,
) -> Job:
    """Run the validation stage for one RECEIVED, adopted job.

    Of all live jobs with the same bytes, one carries on and the others are
    discarded as its duplicates (see JobStore._elect). The election is
    repeated inside the transaction that marks this job validated, so racing
    validators cannot both go ahead.
    """
    if job.state is not State.RECEIVED or job.source_hash is None:
        raise ValueError("validation needs an adopted RECEIVED job")
    skip_filed = duplicates is DuplicatePolicy.SKIP
    for _ in range(attempts):
        try:
            done = _supersede_if_duplicate(
                store, job, duplicates, store.canonical(job.source_hash, skip_filed=skip_filed)
            )
        except StaleJobError:
            # The job we deferred to changed (e.g. its input was replaced).
            job = store.get(job.doc_id)
            if job.state is not State.RECEIVED:
                return job
            continue
        if done is not None:
            return done
        fd = spool.open_original(store, job)
        try:
            result, code = inspect(fd, limits)
        finally:
            os.close(fd)
        if code is not None:
            log.info("job %s quarantined: %s", job.doc_id, code)
            return store.advance(job, State.QUARANTINED, code=code)
        try:
            return store.mark_validated(job, result, skip_filed=skip_filed)
        except NotCanonicalError:
            continue  # another copy won meanwhile: re-elect and give way to it
        except StaleJobError:
            job = store.get(job.doc_id)
            if job.state is not State.RECEIVED:
                return job
    raise RuntimeError(f"job {job.doc_id}: duplicate election did not settle")
