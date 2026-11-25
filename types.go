package spamtroll

import (
	"math"
	"unicode/utf8"
)

// Source tells the API what kind of content you are scanning.
const (
	SourceForum        = "forum"
	SourceComment      = "comment"
	SourceMessage      = "message"
	SourceRegistration = "registration"
	SourceContactForm  = "contact_form"
	// SourceEmail switches the API to the e-mail model.
	SourceEmail   = "email"
	SourceGeneric = "generic"
)

// Limits of the API.
const (
	// MaxContentBytes is the longest content the API accepts for one item.
	// The SDK cuts longer content on a character boundary.
	MaxContentBytes = 64 * 1024
	// MaxBatchItems is the most items in one batch.
	MaxBatchItems = 100
)

// Verdicts in Result.Status.
const (
	StatusBlocked    = "blocked"
	StatusSuspicious = "suspicious"
	StatusSafe       = "safe"
)

// CheckRequest is one item to scan.
type CheckRequest struct {
	// Content is the text to scan. It is required.
	Content string `json:"content"`
	// Source is one of the Source constants. It defaults to SourceGeneric.
	Source string `json:"source,omitempty"`
	// IPAddress is the IP of the author. It is strongly recommended.
	IPAddress string `json:"ip_address,omitempty"`
	Username  string `json:"username,omitempty"`
	Email     string `json:"email,omitempty"`
	// RawMessage is the full RFC 822 message, for real DKIM checks.
	RawMessage string `json:"raw_message,omitempty"`
	// Headers are e-mail headers, such as From and Subject.
	Headers map[string]string `json:"headers,omitempty"`
}

// ContentTruncated reports whether the content is longer than MaxContentBytes.
func (r *CheckRequest) ContentTruncated() bool {
	return len(r.Content) > MaxContentBytes
}

// payload returns a copy of the request that is safe to send.
func (r *CheckRequest) payload() CheckRequest {
	p := *r
	if p.Source == "" {
		p.Source = SourceGeneric
	}
	if len(p.Content) > MaxContentBytes {
		cut := MaxContentBytes
		for cut > 0 && !utf8.RuneStart(p.Content[cut]) {
			cut--
		}
		p.Content = p.Content[:cut]
	}
	return p
}

// Symbol is one rule that matched the content.
type Symbol struct {
	Name        string  `json:"name"`
	Score       float64 `json:"score"`
	Description string  `json:"description,omitempty"`
	Category    string  `json:"category,omitempty"`
}

// scanData is the verdict part of an API answer.
type scanData struct {
	SubmissionID     string   `json:"submission_id"`
	Status           string   `json:"status"`
	SpamScore        float64  `json:"spam_score"`
	PreAIScore       float64  `json:"pre_ai_score"`
	Symbols          []Symbol `json:"symbols"`
	ThreatCategories []string `json:"threat_categories"`
	StagesPassed     []string `json:"stages_passed"`
	DecidingStage    string   `json:"deciding_stage"`
	AIUsed           bool     `json:"ai_used"`
	AIModel          string   `json:"ai_model"`
	AIClassification string   `json:"ai_classification"`
	AIConfidence     float64  `json:"ai_confidence"`
	AIThreatType     string   `json:"ai_threat_type"`
	ProcessingTimeMs int64    `json:"processing_time_ms"`
}

// Result is the answer to one scan.
//
// A result with Skipped set to true has no verdict. It never blocks anything.
type Result struct {
	// Status is StatusBlocked, StatusSuspicious or StatusSafe. When the scan
	// was skipped it is StatusSafe.
	Status string
	// SubmissionID is needed to send feedback. It can be empty.
	SubmissionID string
	// SpamScore is the raw score from the API. It is open-ended: the API
	// counts a score of about 15 as spam by default. Use Status to decide.
	SpamScore        float64
	Symbols          []Symbol
	ThreatCategories []string
	StagesPassed     []string
	DecidingStage    string
	AIUsed           bool
	AIModel          string
	AIClassification string
	AIConfidence     float64
	AIThreatType     string
	ProcessingTimeMs int64

	// Skipped is true when there is no verdict.
	Skipped bool
	// SkipCategory says why. It is SkipNone when Skipped is false.
	SkipCategory SkipCategory
	// Err is the reason for a skipped result. It is nil otherwise.
	Err error

	scoreDivisor float64
}

// NormalizedScore is SpamScore as a number from 0 to 1: the raw score divided
// by the client's score denominator (30 by default), at most 1. It is 0 for a
// skipped result. Use it to show a score. Status is what decides.
func (r *Result) NormalizedScore() float64 {
	if r.Skipped || r.SpamScore <= 0 {
		return 0
	}
	d := r.scoreDivisor
	if d <= 0 {
		d = DefaultScoreDenominator
	}
	return math.Min(1, r.SpamScore/d)
}

// ShouldBlock is true only for an explicit "blocked" verdict.
func (r *Result) ShouldBlock() bool { return !r.Skipped && r.Status == StatusBlocked }

// ShouldModerate is true only for an explicit "suspicious" verdict.
func (r *Result) ShouldModerate() bool { return !r.Skipped && r.Status == StatusSuspicious }

// IsSafe is true for a "safe" verdict and for every skipped result.
func (r *Result) IsSafe() bool { return r.Skipped || r.Status == StatusSafe }

func newResult(d *scanData, scoreDivisor float64) *Result {
	return &Result{
		scoreDivisor:     scoreDivisor,
		Status:           d.Status,
		SubmissionID:     d.SubmissionID,
		SpamScore:        d.SpamScore,
		Symbols:          d.Symbols,
		ThreatCategories: d.ThreatCategories,
		StagesPassed:     d.StagesPassed,
		DecidingStage:    d.DecidingStage,
		AIUsed:           d.AIUsed,
		AIModel:          d.AIModel,
		AIClassification: d.AIClassification,
		AIConfidence:     d.AIConfidence,
		AIThreatType:     d.AIThreatType,
		ProcessingTimeMs: d.ProcessingTimeMs,
	}
}

func skippedResult(err error) *Result {
	return &Result{
		Status:       StatusSafe,
		Skipped:      true,
		SkipCategory: categoryOf(err),
		Err:          err,
	}
}

func validStatus(s string) bool {
	return s == StatusBlocked || s == StatusSuspicious || s == StatusSafe
}

// Feedback labels.
const (
	LabelSpam = "spam"
	LabelHam  = "ham"
)

// FeedbackRequest is a moderator's correction of a verdict.
type FeedbackRequest struct {
	// SubmissionID comes from Result.SubmissionID.
	SubmissionID string `json:"submission_id"`
	// CorrectLabel is LabelSpam or LabelHam.
	CorrectLabel  string `json:"correct_label"`
	ReviewerNotes string `json:"reviewer_notes,omitempty"`
}
