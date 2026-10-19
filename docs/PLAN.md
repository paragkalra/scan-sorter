# scan-sorter: design plan v2.2 (local-models-only, approved 2026-10-19)

Revision of v1 addressing review findings 1-18 (see "Changes from v1" at the end).

## Goal
Open-source, self-hosted tool. A home HP printer scans documents; the tool OCRs them, classifies the document type with a LOCAL model or rules only (no cloud AI), names them, and files them into the user's own cloud storage, creating category folders as needed.

Privacy promise (precise wording): document content is processed only on the user's machine; the only outbound traffic is the upload to the user's own storage remote (plus a one-time, separate model download step). No cloud-AI credentials exist. Storage credentials do exist and are isolated (see Security).

## Scope of M1 (deliberately narrow)
- One ingest path: SMB network folder. One tested remote: Dropbox (App Folder). Fixed category list.
- Classification: user rules + one optional pinned local model. No learned classifier, no automatic new categories (both deferred).
- Durable queue, crash recovery, verified uploads, review/retry CLI, acceptance corpus. Security isolation from day one.
- One logical document per submitted PDF (documented requirement).

## Components (containers on one host, docker compose)
- `samba`: dedicated SMB share for the printer only. SMB2/3 only (SMB1 never enabled), dedicated low-privilege user, share maps to the inbox volume and nothing else. NAS shares as the inbox are out of scope for M1 (cross-filesystem adoption deferred to M3, using copy-to-temp, fsync, verify, local atomic rename, persist adoption, then delete source, with crash reconciliation).
- `worker`: orchestrator + validation + OCR + classification. Network: internal network to `ollama` only; no internet, no storage credentials. Untrusted-file parsing (qpdf, ocrmypdf/Tesseract, image decoders) runs in subprocesses with timeouts, memory/PID limits (ulimits/cgroups), structured argv (never a shell), bounded tmpfs scratch.
- `ollama`: internal network only, `OLLAMA_NO_CLOUD=1`, cloud-backed model names rejected. Models are pulled in a separate one-time `scan-sorter models pull` step that runs with egress, then runtime has none. Models pinned by digest.
- `uploader`: holds rclone config/tokens (writable secrets volume, 0600). Treats the shared DB and spool as untrusted input from the worker: before every upload it independently re-validates the destination path with its own copy of the sanitizer (allowlist, length, under fixed root, reserved path matches doc_id), checks the source is a regular non-symlink file inside `ready/<doc_id>/` owned by the worker UID, and re-hashes it against the recorded output hash. Any failure -> job `failed(permanent)`, not uploaded. Reads only the `ready/` spool; network egress allowed only to the storage provider (documented host firewall / compose network). Never parses PDFs beyond hashing bytes.
- Shared state: SQLite (WAL) on a local volume used by worker and uploader; single writer per state transition, guarded by row-level status checks.
- Model endpoint config accepts only the internal compose hostname or localhost; anything else is refused at startup. An egress test (`scan-sorter doctor`) attempts external connections from worker and ollama and fails if any succeed.

## Job lifecycle (durable)
States: `received -> validated -> ocr_done -> classified -> (needs_review) -> ready -> uploading -> verified -> complete`, plus `quarantined` and `failed(retryable|permanent)`.
- Each job has a persistent UUID (`doc_id`), source SHA-256, and per-stage results persisted in SQLite before advancing.
- Ingest from SMB, two separate gates. Transfer completion: inotify `IN_CLOSE_WRITE` where available AND size+mtime stable for N seconds. Content validity is checked afterwards, during validation, not at the transfer gate. A file that never becomes stable within a bounded time (e.g. 30 min) is adopted and quarantined as `incomplete_transfer` rather than left in the inbox.
- Adoption ordering (durable): (1) insert job row `received` with `doc_id`, inbox filename, size, mtime, and fsync the DB; (2) fsync the source file contents, then rename (same filesystem, inbox and spool are on the same volume) into private spool `jobs/<doc_id>/original.*`, then fsync both the source (inbox) directory and the destination (`jobs/<doc_id>/` and `jobs/`) directories; (3) record source hash. On startup, a reconciler handles both gaps: a DB row whose file is still in the inbox is re-renamed; a spool directory with no DB row is adopted as a new job. The printer share cannot see the spool.
- Spool access is symlink-safe: all file operations use directory-relative calls (`openat`-style via dir fds) with `O_NOFOLLOW`; the spool and inbox reject symlinks and non-regular files (those go to quarantine). The original is kept until `complete` plus a configurable bounded review window (default 14 days, size-capped); then deleted.
- On startup, all non-terminal jobs resume from their last persisted state. Each stage is idempotent.
- Backpressure: bounded queue; if spool disk free space < threshold, the watcher stops accepting new files (they stay in the inbox) and `doctor`/logs report it.

## Validation
Magic-byte content sniffing (not extensions), allowlist PDF/JPEG/PNG, size/page caps, encrypted PDFs -> quarantine, corrupt -> quarantine. Quarantined jobs are visible in the review CLI.

## Deduplication semantics
Track source hash, output hash, job status, and remote path/ID separately.
- Same source hash with a `complete` job: skip and log as duplicate (policy configurable: skip | file again).
- Same source hash with a failed/incomplete job: resume that job, do not create a new one.
- Rescans (different bytes) are new jobs. Text similarity is shown as a review hint only, never auto-deleted.
- CLI: `scan-sorter refile <doc_id>` and `scan-sorter reconcile` (compare DB records vs remote).

## OCR
- Images: JPEG/PNG converted to single-page PDF (img2pdf, lossless). Multi-image grouping is out of scope for M1 (each image is its own document).
- PDFs with an existing text layer: `--skip-text`; mixed pages handled by ocrmypdf per-page. Rotation via `--rotate-pages`; deskew enabled; no aggressive "clean-final" (preserve appearance). Digitally signed PDFs: not rewritten; original is filed unchanged and OCR text is used only for classification.
- Language: configurable Tesseract languages (default `eng`).
- Page order preserved; blank pages kept (removal deferred).
- Classification text: sampled across pages within a token budget (first page in full, then leading text of later pages), not just the first 2,000 chars.
- Empty/near-empty OCR text -> `needs_review`, never classified on empty input.
- Resource bounds: one OCR worker by default, max rasterization DPI cap, per-job timeout.

## Classification and metadata (separate concerns)
Category selection:
1. Rules (keyword/regex). Ordered, first match wins; if two rules for different categories both match, mark a conflict and route to `needs_review`.
2. Local LLM (optional, if configured): JSON-schema-constrained output (Ollama `format`), category must be an ID from the fixed list or the literal `abstain`; temperature 0; few-shot examples. Self-reported confidence is NOT trusted as the gate. Rules have no "weak" mode: a rule either matches or not. Automatic-filing policy (M1):
   - Exactly one rule category matched -> file automatically under that category (LLM, if present, is used only for metadata).
   - No rule matched, LLM configured -> the LLM is run twice with differently ordered category lists and examples; it auto-files only if both runs return the same allowlisted category and neither abstains. Otherwise `needs_review`.
   - `llm_autofile` setting: `on` (default after the acceptance corpus shows false automatic filing rate <= 2% for the chosen model and category set, measured by `scan-sorter eval` on the user's reviewed docs), or `review` (every LLM-only decision goes to review; this is the default until that bar is met).
   - Anything else -> `needs_review`.
3. Rules-only mode is a fully supported configuration (e.g. low-RAM Pi).

Metadata extraction runs on every path regardless of which stage chose the category:
- Date: deterministic regex/date-parser candidates from text; the LLM (if present) may choose among candidates but cannot invent one. The intended date is "document date" (issue/statement date); fallback is scan date with a `scan-` prefix. Year in the path derives from the chosen date.
- Sender and title: LLM if configured, else rule-supplied or `unknown`. Sanitized.
- Filename always includes the full `doc_id` UUID (compact 32-hex form): `{category}/{year}/{date} - {sender} - {title} [{doc_id}].pdf`. Destination paths are additionally reserved via a UNIQUE (case-folded, NFC-normalized) constraint in SQLite before upload, so two jobs can never target the same path even after truncation of other segments.

New categories: not in M1. Later: model may propose; requires explicit approval in review.

## Filing / upload integrity
- Destination root is an application-owned folder (Dropbox App Folder; for Drive later, an app-created root under `drive.file`). Pre-existing user folders are out of scope by default; broader-scope mode documented separately with its tradeoffs.
- Path building: allowlist characters [A-Za-z0-9 _-.()[]], length caps per segment and total, reject `..`/separators/leading dots, Unicode NFC normalization, case-insensitive collision check per provider, always joined under the fixed root. Model output never forms a path directly.
- The destination path is recorded in SQLite (state `uploading`) BEFORE the upload starts.
- Upload with `rclone copyto` to the recorded path (unique by doc_id, so retries never collide with another document). On retry or uncertain outcome: check if the remote object exists; compare by provider hash (Dropbox content hash via `rclone hashsum`) or download-and-compare if the backend lacks a usable hash. Match -> `verified`; mismatch -> re-upload; never overwrite a path belonging to a different doc_id.
- Local original deleted only after `verified` and the review window expires.
- Revoked/expired tokens: job stays `ready`, uploader surfaces `reauth required` in logs and `doctor`.
- rclone OAuth: documented headless flow (`rclone authorize` on a machine with a browser, paste token), Dropbox App Folder app setup guide. Drive guide (M3) covers own client ID, testing-mode 7-day token expiry, and publishing.

## Review and retry (M1 as CLI, web UI in M2)
`scan-sorter review` lists `needs_review` / `quarantined` / `failed`, shows extracted text snippet and proposed metadata, opens the local original (still retained in spool), and lets the user set category/metadata. Classification approval only applies to jobs that passed validation and OCR (`needs_review`). Quarantined jobs cannot be advanced by metadata edits: the user can `discard` them or `replace <doc_id> <file>`, and the replacement re-enters at `received` and must pass validation and OCR like any new input. `retry`, `refile`, `reconcile`, `doctor` commands.
After the local original expires, `refile` downloads the filed object from the remote, verifies it against the recorded output hash, and only then copies to the new path (if hashes mismatch, it aborts as an external change).
Re-categorizing an already-filed doc: copy to new path -> verify -> delete old, all recorded; if the remote object changed or moved externally (hash/ID mismatch), abort and report.

## Web UI (M2) security
Binds to LAN interface explicitly (default localhost; LAN opt-in), password hashed with argon2, login throttling, secure session cookies, CSRF tokens, Host/Origin checks against configured hostname (defeats DNS rebinding), HTTPS via self-signed or user-provided cert (or access through SSH tunnel). PDF previews rendered to images server-side in the sandboxed worker, never served as raw PDF to the browser's viewer.

## Data retention and privacy of local artifacts
| Artifact | Contains | Retention | Protection |
|---|---|---|---|
| Spool originals | full docs | review window, size cap | 0700 dir, owned by worker user |
| OCR scratch | full text/images | job duration (tmpfs) | wiped on completion and on startup sweep |
| SQLite | metadata, snippets, paths | until user prunes; `prune` command | 0600; optional at-rest encryption via host disk encryption (documented) |
| Logs | decisions, error codes | rotated | structured, no document text; exception messages scrubbed |
| rclone tokens | storage creds | until revoked | uploader-only volume, 0600 |
Swap: document recommending encrypted swap or zram on the host. rclone `crypt` optional, with clear notes: loses cloud search/previews; key backup is the user's responsibility; losing it means losing documents.

## Hardware profiles (measured, not promised)
M1 publishes a table of tested hardware / model / quantization with measured latency, peak RAM, temp disk usage. Presets are named by size (`small-1b`, `medium-4b`) not by quality claims. Raspberry Pi guidance: rules-only or 1-2B model, one OCR worker, DPI cap, SSD not SD card, active cooling. Inference timeout or OOM -> job stays `classified=pending` and is retried with backoff or routed to review; never lost.

## Printer compatibility
Before M1 release: compatibility matrix for tested HP models/firmware (SMB dialect, auth, UNC path format, signing requirements, multi-page PDF output). README states that HP workflows requiring HP Smart cloud or HP accounts are not supported in the private mode. Fallback for printers without usable SMB: import from a local folder (e.g. user scans via HP Smart desktop app/USB into a watched folder).

## Later ingest (M3), with contracts
- Local SMTP: tested per printer for port, TLS mode, auth; accepts only configured recipients, never relays, bound to LAN, MIME and attachment size limits, returns `250` only after the attachment is durably spooled; Message-ID + attachment hash dedupe; multiple attachments = multiple jobs.
- IMAP (Gmail): explicitly a separate, less-private mode (Google sees scans). Checkpoint by UID only after durable spooling; UIDVALIDITY change triggers a full re-scan with hash dedupe.

## Testing
- Unit: path sanitizer (traversal, unicode, collisions), rules conflicts, date extraction, schema validation, prompt-injection fixtures (doc text telling the model to change category/path).
- Fault injection: kill at every state boundary, network drop mid-upload, lost upload ack, disk full, revoked token, partial SMB write; assert no loss and no duplicate remote files.
- Acceptance corpus (synthetic, license-clean): poor scans, rotated, multi-page, mixed text/image PDFs, encrypted, empty, duplicates. Metrics recorded: model+version, category set, latency, metadata extraction accuracy, false automatic filings (primary metric), review rate.
- Egress test in `doctor` and CI.

## Security summary
Non-root, read-only root FS, dropped capabilities, no-new-privileges, per-container networks as above, seccomp default, no telemetry, signed images (cosign), SECURITY.md, threat model in README, pinned dependencies, AGPL-3.0.

## Prior art
Paperless-ngx + paperless-gpt / paperless-ai do local OCR + LLM classification inside a DMS. Differentiator: lightweight, no DMS, files directly into the user's own cloud folders.

## Milestones
- M1: SMB ingest (samba container), durable queue + recovery, validation, OCR, rules + optional pinned LLM, metadata extraction, Dropbox upload with verification, review/retry/doctor CLI, isolation, fault-injection tests, acceptance corpus, printer matrix (initial).
- M2: Web review UI (security as specified), learned classifier (enabled only after >= N reviewed examples per category, thresholds evaluated on held-out user data), category proposals with approval.
- M3: SMTP and IMAP ingest, Google Drive and other remotes, multi-image grouping, separator-sheet splitting.

## Changes from v1 (mapping to review findings)
1 durable lifecycle; 2 upload integrity + doc_id suffix + verification; 3 printer matrix + samba container + no SMB1; 4 SMTP contract (M3); 5 one doc per PDF + mixed -> review; 6 metadata separated from category; 7 confidence defined, learned classifier deferred; 8 OCR policies; 9 measured hardware profiles; 10 rclone auth + app-owned root; 11 egress enforcement + OLLAMA_NO_CLOUD + endpoint restriction; 12 worker/uploader split; 13 dedupe semantics; 14 review CLI in M1 + retained originals; 15 web UI hardening + symlink/path/subprocess safety; 16 artifact retention table; 17 narrowed M1; 18 acceptance corpus in M1.
