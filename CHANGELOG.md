# Changelog

All notable changes to this project are written here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- First version of the SDK, with no dependencies outside the standard library.
- `Check` and `CheckOrHam` for `POST /scan/check`.
- `CheckBatch` and `CheckBatchOrHam` for `POST /scan/batch`.
- `SubmitFeedback` for `POST /scan/feedback` and `Status` for `GET /scan/status`.
- Fail-open results: every problem gives a skipped result with a reason in `SkipCategory`.
- Retries with a total time budget, an `Idempotency-Key` on every POST, no redirects
  and a 1 MiB limit for answers.
