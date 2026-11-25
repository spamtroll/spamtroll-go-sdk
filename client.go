package spamtroll

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Defaults of a new client. They are the same as in the PHP SDK.
const (
	DefaultBaseURL        = "https://api.spamtroll.io/api/v1"
	DefaultTimeout        = 3 * time.Second
	DefaultMaxRetries     = 2
	DefaultRetryBaseDelay = 250 * time.Millisecond
	DefaultTotalBudget    = 6 * time.Second
	// DefaultScoreDenominator turns the raw score into a number from 0 to 1.
	DefaultScoreDenominator = 30.0
)

// maxResponseBytes is the biggest body the client reads. A captive portal or
// a wrong base URL can send much more than an API answer ever has.
const maxResponseBytes = 1 << 20

// postMaxAttempts limits how often a POST is sent after a 5xx. A scan that
// reaches the backend uses one scan from your quota before it runs, so a
// failed scan has already been paid for.
const postMaxAttempts = 2

// Client talks to the Spamtroll API. It is safe for concurrent use.
type Client struct {
	apiKey         string
	baseURL        string
	http           *http.Client
	timeout        time.Duration
	maxRetries     int
	retryBaseDelay time.Duration
	totalBudget    time.Duration
	userAgent      string
	scoreDivisor   float64
	configErr      error
}

// Option changes a setting of a new Client.
type Option func(*Client)

// WithBaseURL sets the API address. It must start with http:// or https://.
func WithBaseURL(rawURL string) Option {
	return func(c *Client) {
		u, err := url.Parse(rawURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			c.configErr = fmt.Errorf("%w: base URL %q must start with http:// or https://", ErrInvalidConfiguration, rawURL)
			return
		}
		c.baseURL = strings.TrimRight(rawURL, "/")
	}
}

// WithHTTPClient sets the HTTP client. The SDK works on a copy and turns off
// redirects, so your API key is never sent to another host.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			cp := *hc
			c.http = &cp
		}
	}
}

// WithTimeout sets the time limit for one attempt.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithMaxRetries sets how many attempts one call can make, the first one
// included. A POST that gets a 5xx is sent at most twice, whatever you set.
func WithMaxRetries(attempts int) Option {
	return func(c *Client) {
		if attempts >= 1 {
			c.maxRetries = attempts
		}
	}
}

// WithRetryBaseDelay sets the pause before a new attempt. The pause grows
// with each attempt.
func WithRetryBaseDelay(d time.Duration) Option {
	return func(c *Client) {
		if d >= 0 {
			c.retryBaseDelay = d
		}
	}
}

// WithTotalBudget sets the time limit for a whole call, with all attempts and
// pauses. Zero means no limit besides the context.
func WithTotalBudget(d time.Duration) Option {
	return func(c *Client) {
		if d >= 0 {
			c.totalBudget = d
		}
	}
}

// WithScoreDenominator sets the number that Result.NormalizedScore divides the
// raw score by. The default is DefaultScoreDenominator. A value that is not
// above zero is ignored.
func WithScoreDenominator(d float64) Option {
	return func(c *Client) {
		if d > 0 {
			c.scoreDivisor = d
		}
	}
}

// WithUserAgent sets the User-Agent header.
func WithUserAgent(ua string) Option {
	return func(c *Client) {
		if ua != "" {
			c.userAgent = ua
		}
	}
}

// NewClient creates a client. An empty API key is allowed: every call then
// fails with ErrNotConfigured, and CheckOrHam returns a skipped result.
func NewClient(apiKey string, opts ...Option) *Client {
	c := &Client{
		apiKey:         apiKey,
		baseURL:        DefaultBaseURL,
		http:           &http.Client{},
		timeout:        DefaultTimeout,
		maxRetries:     DefaultMaxRetries,
		retryBaseDelay: DefaultRetryBaseDelay,
		totalBudget:    DefaultTotalBudget,
		scoreDivisor:   DefaultScoreDenominator,
		userAgent:      "spamtroll-go-sdk/" + Version,
	}
	for _, opt := range opts {
		opt(c)
	}
	c.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

// IsConfigured reports whether the API key is not empty.
func (c *Client) IsConfigured() bool { return c.apiKey != "" }

// CheckOrHam scans content and never fails. This is the method to use in an
// integration.
//
// Every problem gives a Result with Skipped set to true, and ShouldBlock
// returns false for it. Look at SkipCategory and Err to log the reason.
func (c *Client) CheckOrHam(ctx context.Context, req *CheckRequest) *Result {
	res, err := c.Check(ctx, req)
	if err != nil {
		return skippedResult(err)
	}
	return res
}

// Check scans content (POST /scan/check).
//
// It returns an error when the call itself failed: there is no API key, the
// API refused the key (401), the network failed, the API answered with a 5xx,
// or the request is invalid. If you handle the error yourself, let the content
// through.
//
// When the API answered but gave no verdict (quota used up, too many requests,
// another 4xx, a redirect, or a body that is not a verdict) the result is
// skipped and the error is nil. This is the same as checkSpam in the PHP SDK.
func (c *Client) Check(ctx context.Context, req *CheckRequest) (*Result, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: request is nil", ErrInvalidRequest)
	}
	payload := req.payload()
	raw, err := c.do(ctx, http.MethodPost, "/scan/check", &payload)
	if err != nil {
		if answeredWithoutVerdict(err) {
			return skippedResult(err), nil
		}
		return nil, err
	}
	res, err := c.decodeResult(raw)
	if err != nil {
		return skippedResult(err), nil
	}
	return res, nil
}

// CheckBatchOrHam scans up to MaxBatchItems items in one call and never fails.
// The result has one entry for each item, in the same order. Every problem,
// for the whole call or for one item, gives a skipped result.
func (c *Client) CheckBatchOrHam(ctx context.Context, reqs []CheckRequest) []*Result {
	results, err := c.CheckBatch(ctx, reqs)
	if err != nil {
		results = skipAll(len(reqs), err)
	}
	return results
}

// CheckBatch scans up to MaxBatchItems items in one call (POST /scan/batch).
// The API counts the whole batch as one scan for your daily quota.
//
// On success the result has one entry for each item, in the same order. An
// item the API could not scan is a skipped result, not an error. The same is
// true for the whole call when the API answered without a verdict (see Check):
// every item is then skipped and the error is nil. The API refuses a batch
// with more than 2 MB of content and raw messages together.
func (c *Client) CheckBatch(ctx context.Context, reqs []CheckRequest) ([]*Result, error) {
	if len(reqs) == 0 {
		return nil, fmt.Errorf("%w: a batch needs at least one item", ErrInvalidRequest)
	}
	if len(reqs) > MaxBatchItems {
		return nil, fmt.Errorf("%w: a batch can have at most %d items, got %d", ErrInvalidRequest, MaxBatchItems, len(reqs))
	}
	items := make([]CheckRequest, len(reqs))
	for i := range reqs {
		items[i] = reqs[i].payload()
	}
	raw, err := c.do(ctx, http.MethodPost, "/scan/batch", map[string]any{"items": items})
	if err != nil {
		if answeredWithoutVerdict(err) {
			return skipAll(len(reqs), err), nil
		}
		return nil, err
	}

	var body struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(unwrapData(raw), &body); err != nil {
		return skipAll(len(reqs), fmt.Errorf("%w: %v", ErrNoVerdict, err)), nil
	}

	results := make([]*Result, len(reqs))
	for i := range results {
		if i < len(body.Results) {
			var d scanData
			// The API reports an item it could not scan as {"status":"error"}.
			if json.Unmarshal(body.Results[i], &d) == nil && validStatus(d.Status) {
				results[i] = newResult(&d, c.scoreDivisor)
				continue
			}
		}
		results[i] = skippedResult(fmt.Errorf("spamtroll: batch item %d was not scanned: %w", i, ErrNoVerdict))
	}
	return results, nil
}

// SubmitFeedback tells the API that a moderator disagrees with a verdict
// (POST /scan/feedback). A spam label also trains the classifier of your
// platform. Feedback is limited per minute and per day, and the daily limit
// depends on the plan (see https://spamtroll.io/faq#limits); both limits answer with 429.
func (c *Client) SubmitFeedback(ctx context.Context, req *FeedbackRequest) error {
	if req == nil || req.SubmissionID == "" {
		return fmt.Errorf("%w: submission ID is required", ErrInvalidRequest)
	}
	if req.CorrectLabel != LabelSpam && req.CorrectLabel != LabelHam {
		return fmt.Errorf("%w: label must be %q or %q", ErrInvalidRequest, LabelSpam, LabelHam)
	}
	_, err := c.do(ctx, http.MethodPost, "/scan/feedback", req)
	return err
}

// Status checks the API key and the connection (GET /scan/status). It returns
// the data object of the answer. Use it for a "Test connection" button.
func (c *Client) Status(ctx context.Context) (map[string]any, error) {
	raw, err := c.do(ctx, http.MethodGet, "/scan/status", nil)
	if err != nil {
		return nil, err
	}
	var data map[string]any
	if err := json.Unmarshal(unwrapData(raw), &data); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoVerdict, err)
	}
	return data, nil
}

func (c *Client) decodeResult(raw []byte) (*Result, error) {
	var d scanData
	if err := json.Unmarshal(unwrapData(raw), &d); err != nil || !validStatus(d.Status) {
		return nil, ErrNoVerdict
	}
	return newResult(&d, c.scoreDivisor), nil
}

func skipAll(n int, err error) []*Result {
	results := make([]*Result, n)
	for i := range results {
		results[i] = skippedResult(err)
	}
	return results
}

// unwrapData returns the "data" object of {"success":true,"data":{...}}, or
// the body itself when it has no such object.
func unwrapData(raw []byte) []byte {
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &env) == nil && len(env.Data) > 0 && env.Data[0] == '{' {
		return env.Data
	}
	return raw
}

// do sends a request and returns the body of a 2xx answer.
func (c *Client) do(ctx context.Context, method, path string, payload any) ([]byte, error) {
	if c.configErr != nil {
		return nil, c.configErr
	}
	if c.apiKey == "" {
		return nil, ErrNotConfigured
	}

	var body []byte
	if payload != nil {
		// json.Marshal replaces bytes that are not valid UTF-8, so content
		// with old encodings is still scanned.
		var err error
		if body, err = json.Marshal(payload); err != nil {
			return nil, fmt.Errorf("spamtroll: cannot encode request: %w", err)
		}
	}

	if c.totalBudget > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.totalBudget)
		defer cancel()
	}

	idempotencyKey := ""
	attempts := c.maxRetries
	if method == http.MethodPost {
		idempotencyKey = newUUID()
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			if err := sleep(ctx, time.Duration(attempt)*c.retryBaseDelay); err != nil {
				break
			}
		}

		status, data, err := c.attempt(ctx, method, path, body, idempotencyKey)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				break
			}
			continue
		}

		switch {
		case status >= 200 && status < 300:
			return data, nil
		case status >= 500:
			lastErr = parseAPIError(status, data)
			if method == http.MethodPost && attempts > postMaxAttempts {
				attempts = postMaxAttempts
			}
			continue
		default:
			// 3xx, 401, 402, 429 and other 4xx give the same answer if you
			// ask again, so they are not retried.
			return nil, parseAPIError(status, data)
		}
	}

	if lastErr == nil {
		lastErr = ctx.Err()
	}
	return nil, lastErr
}

func (c *Client) attempt(ctx context.Context, method, path string, body []byte, idempotencyKey string) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return 0, nil, fmt.Errorf("spamtroll: cannot build request: %w", err)
	}
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("spamtroll: request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return 0, nil, fmt.Errorf("spamtroll: cannot read answer: %w", err)
	}
	if len(data) > maxResponseBytes {
		data = nil
	}
	return resp.StatusCode, data, nil
}

func parseAPIError(status int, data []byte) *APIError {
	e := &APIError{StatusCode: status}
	var env struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
	}
	if json.Unmarshal(data, &env) != nil {
		return e
	}
	e.Message = env.Message
	var obj struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	}
	if json.Unmarshal(env.Error, &obj) == nil {
		e.Code, e.RequestID = obj.Code, obj.RequestID
		if obj.Message != "" {
			e.Message = obj.Message
		}
		return e
	}
	var text string
	if json.Unmarshal(env.Error, &text) == nil && text != "" {
		e.Message = text
	}
	return e
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A key is only a help for the API to see a retry; a missing one
		// must not stop a scan.
		return ""
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
