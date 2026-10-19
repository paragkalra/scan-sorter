# Security policy

scan-sorter handles private documents (tax forms, medical records, IDs), so security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting instead:
**Security** tab, then **Report a vulnerability**.

Include what you found, how to reproduce it, and the impact you expect. You should get an acknowledgement within 7 days.

## Scope

Especially interesting:

- Any way document content can leave the host other than the upload to the user's configured storage remote.
- Escaping the destination root (path traversal, symlinks, Unicode tricks) via filenames, OCR text, or model output.
- A malicious PDF or image gaining access to storage credentials or altering other filed documents.
- Losing or duplicating a document through crashes, retries, or interrupted uploads.

## Supported versions

The project is pre-alpha. Only the `main` branch is supported until the first release.
