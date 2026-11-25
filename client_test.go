package spamtroll

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(t *testing.T, h http.HandlerFunc, opts ...Option) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	opts = append([]Option{WithBaseURL(srv.URL), WithRetryBaseDelay(0)}, opts...)
	return NewClient("test-key", opts...), srv
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

const blockedBody = `{"success":true,"data":{"submission_id":"abc","status":"blocked","spam_score":21.5,` +
	`"symbols":[{"name":"BAYES_SPAM","score":5,"category":"bayes"}],"threat_categories":["link_spam"],` +
	`"ai_used":true,"ai_classification":"spam","processing_time_ms":12}}`

func TestCheckSendsRequestAndReadsVerdict(t *testing.T) {
	var gotPath, gotKey, gotIdem, gotMethod string
	var gotBody map[string]any
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		gotKey, gotIdem = r.Header.Get("X-API-Key"), r.Header.Get("Idempotency-Key")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		writeJSON(w, 200, blockedBody)
	})

	res, err := c.Check(context.Background(), &CheckRequest{Content: "buy now", IPAddress: "203.0.113.5"})
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != "POST" || gotPath != "/scan/check" || gotKey != "test-key" || gotIdem == "" {
		t.Fatalf("bad request: %s %s key=%q idem=%q", gotMethod, gotPath, gotKey, gotIdem)
	}
	if gotBody["content"] != "buy now" || gotBody["source"] != "generic" || gotBody["ip_address"] != "203.0.113.5" {
		t.Fatalf("bad body: %v", gotBody)
	}
	if _, ok := gotBody["username"]; ok {
		t.Fatal("empty fields must be left out")
	}
	if !res.ShouldBlock() || res.Skipped || res.SubmissionID != "abc" || res.SpamScore != 21.5 ||
		len(res.Symbols) != 1 || res.ThreatCategories[0] != "link_spam" || !res.AIUsed {
		t.Fatalf("bad result: %+v", res)
	}
}

func TestVerdictHelpers(t *testing.T) {
	for _, tt := range []struct {
		status                string
		block, moderate, safe bool
	}{
		{StatusBlocked, true, false, false},
		{StatusSuspicious, false, true, false},
		{StatusSafe, false, false, true},
	} {
		r := &Result{Status: tt.status}
		if r.ShouldBlock() != tt.block || r.ShouldModerate() != tt.moderate || r.IsSafe() != tt.safe {
			t.Errorf("%s: wrong helpers", tt.status)
		}
	}
	skipped := &Result{Status: StatusBlocked, Skipped: true}
	if skipped.ShouldBlock() || !skipped.IsSafe() {
		t.Error("a skipped result must never block")
	}
}

func TestCheckOrHamNeverBlocksOnFailure(t *testing.T) {
	cases := []struct {
		name     string
		handler  http.HandlerFunc
		client   func(*testing.T, http.HandlerFunc) *Client
		category SkipCategory
	}{
		{"401", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 401, `{"success":false}`) }, nil, SkipAuth},
		{"403", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 403, `{"success":false}`) }, nil, SkipAuth},
		{"402", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 402, `{"success":false,"error":{"code":"QUOTA_EXCEEDED","message":"Daily quota exceeded"}}`)
		}, nil, SkipQuota},
		{"429", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 429, `{}`) }, nil, SkipRateLimit},
		{"422", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 422, `{}`) }, nil, SkipRejected},
		{"500", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 500, `{}`) }, nil, SkipTransport},
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://elsewhere.example/", http.StatusMovedPermanently)
		}, nil, SkipRedirected},
		{"html", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, `<html>portal</html>`) }, nil, SkipNoVerdict},
		{"empty", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, ``) }, nil, SkipNoVerdict},
		{"unknown status", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, `{"success":true,"data":{"status":"error"}}`)
		}, nil, SkipNoVerdict},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestClient(t, tt.handler)
			res := c.CheckOrHam(context.Background(), &CheckRequest{Content: "x"})
			if !res.Skipped || res.ShouldBlock() || !res.IsSafe() || res.Err == nil {
				t.Fatalf("not fail-open: %+v", res)
			}
			if res.SkipCategory != tt.category {
				t.Fatalf("category = %q, want %q", res.SkipCategory, tt.category)
			}
		})
	}
}

func TestCheckOrHamWithoutKeyAndWithBadBaseURL(t *testing.T) {
	res := NewClient("").CheckOrHam(context.Background(), &CheckRequest{Content: "x"})
	if !res.Skipped || res.SkipCategory != SkipNotConfigured || !errors.Is(res.Err, ErrNotConfigured) {
		t.Fatalf("unexpected: %+v", res)
	}

	res = NewClient("k", WithBaseURL("ftp://example.com")).CheckOrHam(context.Background(), &CheckRequest{Content: "x"})
	if !res.Skipped || res.SkipCategory != SkipNotConfigured || !errors.Is(res.Err, ErrInvalidConfiguration) {
		t.Fatalf("unexpected: %+v", res)
	}

	res = NewClient("k").CheckOrHam(context.Background(), nil)
	if !res.Skipped || res.ShouldBlock() {
		t.Fatalf("nil request must be skipped: %+v", res)
	}
}

func TestCheckReturnsAPIError(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 401, `{"success":false,"error":{"code":"QUOTA_EXCEEDED","message":"Daily quota exceeded","request_id":"req-1"}}`)
	})
	_, err := c.Check(context.Background(), &CheckRequest{Content: "x"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want APIError, got %v", err)
	}
	if apiErr.StatusCode != 401 || apiErr.Code != "QUOTA_EXCEEDED" || apiErr.RequestID != "req-1" ||
		apiErr.Message != "Daily quota exceeded" {
		t.Fatalf("bad error: %+v", apiErr)
	}
	if !strings.Contains(apiErr.Error(), "QUOTA_EXCEEDED") {
		t.Fatalf("bad text: %s", apiErr.Error())
	}
}

func TestErrorBodyAsPlainString(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 400, `{"error":"bad input"}`) })
	res, err := c.Check(context.Background(), &CheckRequest{Content: "x"})
	var apiErr *APIError
	if err != nil || res == nil || !errors.As(res.Err, &apiErr) || apiErr.Message != "bad input" {
		t.Fatalf("got %+v, %v", res, err)
	}
}

// The strict calls follow the PHP SDK: an answer without a verdict is a
// skipped result with no error. Only a failed call is an error.
func TestCheckAnswerWithoutVerdictIsASkippedResult(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   SkipCategory
	}{
		{402, `{"error":{"code":"QUOTA_EXCEEDED"}}`, SkipQuota},
		{403, `{}`, SkipAuth},
		{422, `{"error":{"code":"VALIDATION_ERROR","message":"content is required"}}`, SkipRejected},
		{429, `{}`, SkipRateLimit},
		{302, ``, SkipRedirected},
		{200, `<html>login</html>`, SkipNoVerdict},
		{200, `{"success":true,"data":{"status":"weird"}}`, SkipNoVerdict},
	}
	for _, tc := range cases {
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, tc.status, tc.body) })
		res, err := c.Check(context.Background(), &CheckRequest{Content: "x"})
		if err != nil || res == nil || !res.Skipped || res.ShouldBlock() || res.SkipCategory != tc.want || res.Err == nil {
			t.Fatalf("status %d: got %+v, %v; want skipped %s", tc.status, res, err, tc.want)
		}
		results, err := c.CheckBatch(context.Background(), []CheckRequest{{Content: "a"}, {Content: "b"}})
		if err != nil || len(results) != 2 || !results[0].Skipped || !results[1].Skipped || results[1].SkipCategory != tc.want {
			t.Fatalf("batch, status %d: got %+v, %v", tc.status, results, err)
		}
	}
}

func TestCheckFailedCallIsAnError(t *testing.T) {
	cases := map[string]func() (*Client, int){
		"401": func() (*Client, int) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 401, `{}`) })
			return c, 0
		},
		"500": func() (*Client, int) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 500, `{}`) })
			return c, 0
		},
		"no key": func() (*Client, int) { return NewClient(""), 0 },
	}
	for name, mk := range cases {
		c, _ := mk()
		if res, err := c.Check(context.Background(), &CheckRequest{Content: "x"}); err == nil || res != nil {
			t.Fatalf("%s: want an error, got %+v, %v", name, res, err)
		}
		if res, err := c.CheckBatch(context.Background(), []CheckRequest{{Content: "x"}}); err == nil || res != nil {
			t.Fatalf("%s: batch: want an error, got %+v, %v", name, res, err)
		}
	}
}

func TestNormalizedScore(t *testing.T) {
	score := func(raw string, opts ...Option) *Result {
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, `{"success":true,"data":{"status":"blocked","spam_score":`+raw+`}}`)
		}, opts...)
		res, err := c.Check(context.Background(), &CheckRequest{Content: "x"})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if got := score("15").NormalizedScore(); got != 0.5 {
		t.Fatalf("15/30 = %v", got)
	}
	if got := score("34.8").NormalizedScore(); got != 1 {
		t.Fatalf("above the denominator must be 1, got %v", got)
	}
	if got := score("-3").NormalizedScore(); got != 0 {
		t.Fatalf("negative must be 0, got %v", got)
	}
	if got := score("15", WithScoreDenominator(60)).NormalizedScore(); got != 0.25 {
		t.Fatalf("15/60 = %v", got)
	}
	if got := score("15", WithScoreDenominator(0)).NormalizedScore(); got != 0.5 {
		t.Fatalf("a bad denominator must be ignored, got %v", got)
	}
	skipped := NewClient("").CheckOrHam(context.Background(), &CheckRequest{Content: "x"})
	if skipped.NormalizedScore() != 0 {
		t.Fatalf("skipped must be 0")
	}
	if (&Result{SpamScore: 15}).NormalizedScore() != 0.5 {
		t.Fatalf("a Result made by hand must use the default denominator")
	}
}

func TestRetriesAServerErrorOnceForPost(t *testing.T) {
	var calls int32
	var keys []string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		if atomic.AddInt32(&calls, 1) == 1 {
			writeJSON(w, 503, `{}`)
			return
		}
		writeJSON(w, 200, blockedBody)
	}, WithMaxRetries(5))

	res, err := c.Check(context.Background(), &CheckRequest{Content: "x"})
	if err != nil || !res.ShouldBlock() {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if calls != 2 || keys[0] == "" || keys[0] != keys[1] {
		t.Fatalf("calls=%d keys=%v", calls, keys)
	}
}

func TestPostIsSentAtMostTwiceOnServerErrors(t *testing.T) {
	var calls int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		writeJSON(w, 500, `{}`)
	}, WithMaxRetries(5))

	if _, err := c.Check(context.Background(), &CheckRequest{Content: "x"}); err == nil {
		t.Fatal("want an error")
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

func TestDoesNotRetryClientErrors(t *testing.T) {
	for _, status := range []int{401, 402, 422, 429} {
		var calls int32
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&calls, 1)
			writeJSON(w, status, `{}`)
		}, WithMaxRetries(5))
		_, _ = c.Check(context.Background(), &CheckRequest{Content: "x"})
		if calls != 1 {
			t.Fatalf("status %d: calls = %d, want 1", status, calls)
		}
	}
}

func TestRetriesNetworkErrors(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
			return
		}
		writeJSON(w, 200, blockedBody)
	}))
	defer srv.Close()
	c := NewClient("k", WithBaseURL(srv.URL), WithRetryBaseDelay(0))

	res, err := c.Check(context.Background(), &CheckRequest{Content: "x"})
	if err != nil || !res.ShouldBlock() || calls != 2 {
		t.Fatalf("res=%+v err=%v calls=%d", res, err, calls)
	}
}

func TestTotalBudgetStopsASlowServer(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}, WithTimeout(time.Second), WithTotalBudget(100*time.Millisecond), WithMaxRetries(3))

	start := time.Now()
	res := c.CheckOrHam(context.Background(), &CheckRequest{Content: "x"})
	if time.Since(start) > time.Second {
		t.Fatalf("took %s", time.Since(start))
	}
	if !res.Skipped || res.ShouldBlock() || res.SkipCategory != SkipTransport {
		t.Fatalf("unexpected: %+v", res)
	}
}

func TestCancelledContextFailsOpen(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, blockedBody) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := c.CheckOrHam(ctx, &CheckRequest{Content: "x"})
	if !res.Skipped || res.ShouldBlock() {
		t.Fatalf("unexpected: %+v", res)
	}
}

func TestHugeAnswerIsNoVerdict(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"success":true,"data":{"status":"blocked","pad":"`+strings.Repeat("a", 2<<20)+`"}}`)
	})
	res := c.CheckOrHam(context.Background(), &CheckRequest{Content: "x"})
	if !res.Skipped || res.SkipCategory != SkipNoVerdict {
		t.Fatalf("unexpected: %+v", res)
	}
}

func TestLongContentIsCutOnACharacterBoundary(t *testing.T) {
	var got string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var b struct{ Content string }
		_ = json.NewDecoder(r.Body).Decode(&b)
		got = b.Content
		writeJSON(w, 200, `{"success":true,"data":{"status":"safe"}}`)
	})
	req := &CheckRequest{Content: strings.Repeat("ą", MaxContentBytes)} // 2 bytes each
	if !req.ContentTruncated() {
		t.Fatal("content should count as too long")
	}
	if _, err := c.Check(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if len(got) > MaxContentBytes || len(got) < MaxContentBytes-1 || strings.ContainsRune(got, '�') {
		t.Fatalf("bad cut: %d bytes", len(got))
	}
	if len(req.Content) != 2*MaxContentBytes {
		t.Fatal("the caller's request must not change")
	}
}

func TestInvalidUTF8IsStillSent(t *testing.T) {
	var got string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var b struct{ Content string }
		_ = json.NewDecoder(r.Body).Decode(&b)
		got = b.Content
		writeJSON(w, 200, `{"success":true,"data":{"status":"safe"}}`)
	})
	if _, err := c.Check(context.Background(), &CheckRequest{Content: "caf\xe9 pharma"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "pharma") {
		t.Fatalf("got %q", got)
	}
}

func TestBatch(t *testing.T) {
	var gotPath string
	var gotBody struct {
		Items []map[string]any `json:"items"`
	}
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		writeJSON(w, 200, `{"success":true,"data":{"results":[`+
			`{"status":"blocked","spam_score":20,"submission_id":"a"},`+
			`{"status":"error"},`+
			`{"status":"safe"}]}}`)
	})

	results, err := c.CheckBatch(context.Background(), []CheckRequest{{Content: "one"}, {Content: "two"}, {Content: "three"}})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/scan/batch" || len(gotBody.Items) != 3 || gotBody.Items[1]["content"] != "two" {
		t.Fatalf("bad request: %s %v", gotPath, gotBody)
	}
	if len(results) != 3 || !results[0].ShouldBlock() || results[0].SubmissionID != "a" {
		t.Fatalf("bad results: %+v", results)
	}
	if !results[1].Skipped || results[1].ShouldBlock() || results[1].SkipCategory != SkipNoVerdict {
		t.Fatalf("item with an error must be skipped: %+v", results[1])
	}
	if !results[2].IsSafe() || results[2].Skipped {
		t.Fatalf("bad result: %+v", results[2])
	}
}

func TestBatchSkipsItemsMissingFromTheAnswer(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"success":true,"data":{"results":[{"status":"blocked"}]}}`)
	})
	results := c.CheckBatchOrHam(context.Background(), []CheckRequest{{Content: "a"}, {Content: "b"}})
	if len(results) != 2 || !results[0].ShouldBlock() || !results[1].Skipped || results[1].ShouldBlock() {
		t.Fatalf("unexpected: %+v", results)
	}
}

func TestBatchOrHamNeverBlocksOnFailure(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 402, `{}`) })
	results := c.CheckBatchOrHam(context.Background(), []CheckRequest{{Content: "a"}, {Content: "b"}})
	if len(results) != 2 {
		t.Fatalf("len = %d", len(results))
	}
	for _, r := range results {
		if !r.Skipped || r.ShouldBlock() || r.SkipCategory != SkipQuota {
			t.Fatalf("unexpected: %+v", r)
		}
	}
}

func TestBatchLimits(t *testing.T) {
	c := NewClient("k")
	if _, err := c.CheckBatch(context.Background(), nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty batch: %v", err)
	}
	if _, err := c.CheckBatch(context.Background(), make([]CheckRequest, MaxBatchItems+1)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("big batch: %v", err)
	}
	results := c.CheckBatchOrHam(context.Background(), make([]CheckRequest, MaxBatchItems+1))
	if len(results) != MaxBatchItems+1 || results[0].ShouldBlock() || !results[0].Skipped {
		t.Fatal("OrHam must skip every item")
	}
}

func TestSubmitFeedback(t *testing.T) {
	var gotPath string
	var gotBody map[string]string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		writeJSON(w, 200, `{"success":true,"data":{"message":"Feedback processed successfully"}}`)
	})
	err := c.SubmitFeedback(context.Background(), &FeedbackRequest{SubmissionID: "abc", CorrectLabel: LabelHam, ReviewerNotes: "fine"})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/scan/feedback" || gotBody["submission_id"] != "abc" || gotBody["correct_label"] != "ham" || gotBody["reviewer_notes"] != "fine" {
		t.Fatalf("bad request: %s %v", gotPath, gotBody)
	}
}

func TestSubmitFeedbackValidatesAndReportsErrors(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 404, `{"success":false,"error":{"code":"NOT_FOUND","message":"not found"}}`)
	})
	if err := c.SubmitFeedback(context.Background(), &FeedbackRequest{CorrectLabel: LabelSpam}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing ID: %v", err)
	}
	if err := c.SubmitFeedback(context.Background(), &FeedbackRequest{SubmissionID: "a", CorrectLabel: "maybe"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("bad label: %v", err)
	}
	var apiErr *APIError
	if err := c.SubmitFeedback(context.Background(), &FeedbackRequest{SubmissionID: "a", CorrectLabel: LabelSpam}); !errors.As(err, &apiErr) || apiErr.StatusCode != 404 {
		t.Fatalf("want a 404 APIError, got %v", err)
	}
}

func TestStatus(t *testing.T) {
	var gotMethod, gotKey string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotKey = r.Method, r.Header.Get("X-API-Key")
		if r.Header.Get("Idempotency-Key") != "" {
			t.Error("a GET needs no idempotency key")
		}
		writeJSON(w, 200, `{"success":true,"data":{"status":"ok"}}`)
	})
	data, err := c.Status(context.Background())
	if err != nil || data["status"] != "ok" || gotMethod != "GET" || gotKey != "test-key" {
		t.Fatalf("data=%v err=%v method=%s key=%s", data, err, gotMethod, gotKey)
	}

	bad, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 401, `{}`) })
	var apiErr *APIError
	if _, err := bad.Status(context.Background()); !errors.As(err, &apiErr) || apiErr.StatusCode != 401 {
		t.Fatalf("want a 401 APIError, got %v", err)
	}
}

func TestRedirectsAreNotFollowedAndKeyIsNotLeaked(t *testing.T) {
	var otherSawKey int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "" {
			atomic.StoreInt32(&otherSawKey, 1)
		}
		writeJSON(w, 200, blockedBody)
	}))
	defer other.Close()

	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}, WithHTTPClient(&http.Client{})) // a client that would follow redirects
	res := c.CheckOrHam(context.Background(), &CheckRequest{Content: "x"})
	if !res.Skipped || res.SkipCategory != SkipRedirected || otherSawKey != 0 {
		t.Fatalf("res=%+v leaked=%d", res, otherSawKey)
	}
}

func TestOptions(t *testing.T) {
	var ua string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		writeJSON(w, 200, `{"status":"safe"}`) // flat answers work too
	}, WithUserAgent("my-plugin/1.0"))
	res, err := c.Check(context.Background(), &CheckRequest{Content: "x"})
	if err != nil || !res.IsSafe() || ua != "my-plugin/1.0" {
		t.Fatalf("res=%+v err=%v ua=%q", res, err, ua)
	}

	d := NewClient("k")
	if d.baseURL != DefaultBaseURL || !strings.HasPrefix(d.userAgent, "spamtroll-go-sdk/") || !d.IsConfigured() || NewClient("").IsConfigured() {
		t.Fatal("bad defaults")
	}
	if NewClient("k", WithBaseURL("https://example.com/api/")).baseURL != "https://example.com/api" {
		t.Fatal("trailing slash must be removed")
	}
}
