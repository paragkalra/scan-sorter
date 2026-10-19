# scan-sorter

> **Pre-alpha: not ready for real documents.** Nothing here works end to end yet. Do not point it at your scans until milestone M1 is tagged.

Self-hosted, local-only document sorter for home scanners. Your printer scans to a network folder; scan-sorter OCRs each document, classifies it with rules or a **local** model, names it, and files it into your own cloud storage (Dropbox first), creating category folders as needed.

## Privacy promise

Document content is processed only on your machine. The only outbound traffic is the upload to your own storage remote (plus a one-time, separate model download). No cloud AI is used, and no cloud-AI credentials exist. Storage credentials are isolated in a container that never parses documents.

## How it works

```
HP printer --SMB (LAN)--> [worker: validate -> OCR -> classify -> name] --> [uploader] --> your Dropbox
                                              |
                                        local model (Ollama, no internet)
```

- **Ingest:** printer "Scan to Network Folder" into a dedicated SMB2/3 share.
- **OCR:** ocrmypdf + Tesseract; stored PDFs become searchable.
- **Classify:** your rules first, then an optional pinned local model with schema-constrained output. Anything uncertain goes to review, never into a wrong folder.
- **File:** `{category}/{year}/{date} - {sender} - {title} [{doc_id}].pdf`, uploaded with rclone and verified by hash before the local copy is removed.
- **Durable:** every job is a persisted state machine; crashes resume, uploads never duplicate.

The full design, including the threat model decisions, is in [docs/PLAN.md](docs/PLAN.md).

## Status

| Milestone | Scope | State |
|---|---|---|
| M1 | SMB ingest, durable queue, OCR, rules + optional local model, Dropbox upload with verification, review/retry/doctor CLI, isolation, fault-injection tests | In progress |
| M2 | Web review UI, learned classifier, category proposals | Planned |
| M3 | SMTP/IMAP ingest, Google Drive and other remotes, multi-image grouping | Planned |

## Prior art

[Paperless-ngx](https://github.com/paperless-ngx/paperless-ngx) with paperless-gpt or paperless-ai already does local OCR and LLM classification inside a full document-management system. scan-sorter is deliberately smaller: no DMS, no archive to run, files land directly in folders you already use.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## License

[AGPL-3.0](LICENSE).
