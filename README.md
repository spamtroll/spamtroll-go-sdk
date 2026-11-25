# Spamtroll Go SDK

[![CI](https://github.com/spamtroll/spamtroll-go-sdk/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/spamtroll/spamtroll-go-sdk/actions/workflows/ci.yml)
[![Vulnerability check](https://github.com/spamtroll/spamtroll-go-sdk/actions/workflows/vulncheck.yml/badge.svg?branch=main)](https://github.com/spamtroll/spamtroll-go-sdk/actions/workflows/vulncheck.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/spamtroll/spamtroll-go-sdk.svg)](https://pkg.go.dev/github.com/spamtroll/spamtroll-go-sdk)
[![License: MIT](https://img.shields.io/github/license/spamtroll/spamtroll-go-sdk)](LICENSE)

Go client for the [Spamtroll](https://spamtroll.io) spam detection API. It has
no dependencies outside the standard library and needs Go 1.22 or newer.

```bash
go get github.com/spamtroll/spamtroll-go-sdk
```

## Quick start

```go
package main

import (
	"context"
	"log"

	spamtroll "github.com/spamtroll/spamtroll-go-sdk"
)

func main() {
	client := spamtroll.NewClient("your-api-key")

	res := client.CheckOrHam(context.Background(), &spamtroll.CheckRequest{
		Content:   "Buy cheap pills now!!!",
		Source:    spamtroll.SourceComment,
		IPAddress: "203.0.113.5",
	})

	if res.Skipped {
		log.Printf("scan skipped (%s): %v", res.SkipCategory, res.Err)
	}
	if res.ShouldBlock() {
		// reject the content
	} else if res.ShouldModerate() {
		// hold it for review
	}
}
```

## Fail-open

An integration must never block real users because Spamtroll has a problem.
`CheckOrHam` and `CheckBatchOrHam` never return an error. If the API key is
missing, the network is down, the answer is wrong or the quota is used up, you
get a result with `Skipped` set to `true`. A skipped result is never blocked:
`ShouldBlock()` returns `false` and `IsSafe()` returns `true`.

Use `SkipCategory` and `Err` to write the reason to your log. The categories are
`not_configured`, `auth`, `quota`, `rate_limit`, `rejected`, `redirected`,
`transport` and `no_verdict`.

If you want to handle errors yourself, use `Check`, `CheckBatch`,
`SubmitFeedback` and `Status`. They return an error, and an `*APIError` when the
API answered with a failure status:

```go
res, err := client.Check(ctx, req)
var apiErr *spamtroll.APIError
if errors.As(err, &apiErr) {
	log.Printf("API error %d %s (request %s)", apiErr.StatusCode, apiErr.Code, apiErr.RequestID)
}
```

If you get an error, let the content through.

## Scanning many items

```go
results := client.CheckBatchOrHam(ctx, []spamtroll.CheckRequest{
	{Content: "first comment"},
	{Content: "second comment"},
})
for i, r := range results {
	if r.ShouldBlock() { /* item i is spam */ }
}
```

A batch can have up to 100 items and the API counts it as one scan for your
daily quota. The results are in the same order as the items. If the API could
not scan one item, that item is a skipped result and the others are normal.

## Moderator feedback

```go
err := client.SubmitFeedback(ctx, &spamtroll.FeedbackRequest{
	SubmissionID: res.SubmissionID,
	CorrectLabel: spamtroll.LabelHam,
})
```

The API allows 20 feedback requests a minute and 100 corrections a day.

## Options

```go
client := spamtroll.NewClient("your-api-key",
	spamtroll.WithTimeout(2*time.Second),      // one attempt, default 3s
	spamtroll.WithMaxRetries(3),               // attempts per call, default 2
	spamtroll.WithTotalBudget(5*time.Second),  // whole call, default 6s
	spamtroll.WithBaseURL("https://api.spamtroll.io/api/v1"),
	spamtroll.WithHTTPClient(myHTTPClient),
	spamtroll.WithUserAgent("my-plugin/1.0"),
)
```

- A call is retried after a network error or a 5xx answer. A POST that got a
  5xx is sent at most twice, with the same `Idempotency-Key`.
- Errors like 401, 402, 422 and 429 are not retried.
- Redirects are not followed, so your API key is never sent to another host.
- Content longer than 64 KiB is cut on a character boundary before it is sent.
- The client reads at most 1 MiB of an answer.

## Development

```bash
go vet ./...
go test -race ./...
```

## License

MIT. See [LICENSE](LICENSE).
