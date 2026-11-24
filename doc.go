// Package spamtroll is a client for the Spamtroll spam detection API.
//
// Create a client with your API key and call CheckOrHam for every piece of
// content you want to scan:
//
//	client := spamtroll.NewClient(os.Getenv("SPAMTROLL_API_KEY"))
//	res := client.CheckOrHam(ctx, &spamtroll.CheckRequest{
//		Content:   comment,
//		Source:    spamtroll.SourceComment,
//		IPAddress: ip,
//	})
//	if res.ShouldBlock() {
//		// reject the comment
//	}
//
// CheckOrHam never returns an error. If the API cannot be reached, the key is
// wrong, the quota is used up, or the answer makes no sense, the result is
// marked as skipped and ShouldBlock returns false. Only a successful scan with
// an explicit "blocked" verdict can block content. Use Result.Skipped,
// Result.SkipCategory and Result.Err to log what went wrong.
//
// Check, CheckBatch, SubmitFeedback and Status return errors instead, for
// code that wants to handle them itself.
package spamtroll
