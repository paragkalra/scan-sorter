"""PDF probe, run only inside the sandbox: ``python -I -m scan_sorter.probe``.

Reads the PDF on stdin (a regular, seekable file descriptor) and prints one
line of JSON: {"pages": n, "restricted": bool} or {"error": code}. It never
writes files. Errors are reported as short codes, never as parser messages,
which could echo document content.
"""

from __future__ import annotations

import json
import os
import sys


def probe(fd: int) -> dict:
    import pikepdf  # imported here: only the sandboxed child loads the parser

    stream = os.fdopen(fd, "rb", closefd=False)
    try:
        with pikepdf.open(stream) as pdf:
            return {"pages": len(pdf.pages), "restricted": bool(pdf.is_encrypted)}
    except pikepdf.PasswordError:
        return {"error": "encrypted_pdf"}
    except (pikepdf.PdfError, ValueError, OSError, RecursionError):
        return {"error": "corrupt_pdf"}


def main() -> int:
    print(json.dumps(probe(0)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
