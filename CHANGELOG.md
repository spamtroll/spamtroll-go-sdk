# Changelog

All notable changes to this project are written here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- The README and the `SubmitFeedback` comment no longer state the feedback limits. They change with the plan, so both now link to the [FAQ](https://spamtroll.io/faq#limits).

### Added
- First version of the SDK, with no dependencies outside the standard library.
- `Check` and `CheckOrHam` for `POST /scan/check`.
- `CheckBatch` and `CheckBatchOrHam` for `POST /scan/batch`.
- `SubmitFeedback` for `POST /scan/feedback` and `Status` for `GET /scan/status`.
- Fail-open results: every problem gives a skipped result with a reason in `SkipCategory`.
- `Result.NormalizedScore()` and `WithScoreDenominator`: the score as a number from 0 to 1,
  the same as `getSpamScore()` in the PHP SDK.
- Retries with a total time budget, an `Idempotency-Key` on every POST, no redirects
  and a 1 MiB limit for answers.
