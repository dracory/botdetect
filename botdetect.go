// Package botdetect provides bot, crawler, and malicious-traffic detection
// for HTTP requests, plus an optional blocking middleware.
//
// Detection is split into pure, request-agnostic functions (Detect,
// DetectRequest, IsBot, IsBotPath, IsMaliciousPath, IsReferrerSpam,
// IsDataCenterIP) so the verdicts can be reused from middleware, ingestion
// pipelines, or batch jobs.
package botdetect
