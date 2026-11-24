package spamtroll

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	// ErrNotConfigured means the API key is empty.
	ErrNotConfigured = errors.New("spamtroll: API key is not configured")

	// ErrInvalidRequest means the request cannot be sent, for example an
	// empty batch. It is a coding mistake, not a runtime failure.
	ErrInvalidRequest = errors.New("spamtroll: invalid request")

	// ErrInvalidConfiguration means the client settings are wrong, for example
	// a base URL that is not http or https.
	ErrInvalidConfiguration = errors.New("spamtroll: invalid configuration")

	// ErrNoVerdict means the API answered with a success status, but the body
	// had no verdict. A proxy or a captive portal can cause this.
	ErrNoVerdict = errors.New("spamtroll: response has no verdict")
)

// APIError is an answer from the API with a status code that is not 2xx.
type APIError struct {
	// StatusCode is the HTTP status code.
	StatusCode int
	// Code is the machine-readable code from the API, for example QUOTA_EXCEEDED.
	// It can be empty.
	Code string
	// Message is the text from the API. It can be empty.
	Message string
	// RequestID helps the Spamtroll team find the request in their logs.
	RequestID string
}

func (e *APIError) Error() string {
	text := e.Message
	if text == "" {
		text = http.StatusText(e.StatusCode)
	}
	if e.Code != "" {
		return fmt.Sprintf("spamtroll: API answered %d %s: %s", e.StatusCode, e.Code, text)
	}
	return fmt.Sprintf("spamtroll: API answered %d: %s", e.StatusCode, text)
}

// SkipCategory tells you why a scan has no verdict. It is a closed set, so it
// is safe to use in a switch or to store. The values are the same as in the
// Spamtroll PHP SDK.
type SkipCategory string

const (
	// SkipNone means the scan has a verdict.
	SkipNone SkipCategory = ""
	// SkipNotConfigured means there is no API key.
	SkipNotConfigured SkipCategory = "not_configured"
	// SkipAuth means the API refused the key (401 or 403).
	SkipAuth SkipCategory = "auth"
	// SkipQuota means the daily quota is used up (402).
	SkipQuota SkipCategory = "quota"
	// SkipRateLimit means you sent too many requests (429).
	SkipRateLimit SkipCategory = "rate_limit"
	// SkipRejected means the API refused the request (other 4xx).
	SkipRejected SkipCategory = "rejected"
	// SkipRedirected means the base URL redirects. The SDK never follows
	// redirects, because they would send your API key to another host.
	SkipRedirected SkipCategory = "redirected"
	// SkipTransport means there was no usable answer: a network error, a
	// timeout, or a 5xx.
	SkipTransport SkipCategory = "transport"
	// SkipNoVerdict means the API answered 2xx, but without a verdict.
	SkipNoVerdict SkipCategory = "no_verdict"
)

func categoryOf(err error) SkipCategory {
	if err == nil {
		return SkipNone
	}
	if errors.Is(err, ErrNotConfigured) || errors.Is(err, ErrInvalidConfiguration) {
		return SkipNotConfigured
	}
	if errors.Is(err, ErrNoVerdict) {
		return SkipNoVerdict
	}
	if errors.Is(err, ErrInvalidRequest) {
		return SkipRejected
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.StatusCode == http.StatusPaymentRequired:
			return SkipQuota
		case apiErr.StatusCode == http.StatusTooManyRequests:
			return SkipRateLimit
		case apiErr.StatusCode == http.StatusUnauthorized, apiErr.StatusCode == http.StatusForbidden:
			return SkipAuth
		case apiErr.StatusCode >= 300 && apiErr.StatusCode < 400:
			return SkipRedirected
		case apiErr.StatusCode >= 400 && apiErr.StatusCode < 500:
			return SkipRejected
		case apiErr.StatusCode >= 200 && apiErr.StatusCode < 300:
			return SkipNoVerdict
		}
	}
	return SkipTransport
}
