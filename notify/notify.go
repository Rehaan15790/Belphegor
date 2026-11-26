// Package notify implements the adapter layer for pushing vulnerability findings to IM / email channels.
//
// Layering: this package is a **leaf package** that depends only on the standard library. It knows nothing about the database or the server. Channel config
// is passed in as map[string]any (matching the notification_channels.config JSONB column),
// and the content to push is passed in as a Message. The benefit of this split is that the places that are really error-prone, such as signature computation, UTF-8 truncation and filter matching,
// can be unit tested without PostgreSQL, and the host only needs to orchestrate on the server side.
//
// Concurrency contract: Channel implementations must be **stateless**. The same Channel instance is reused concurrently by multiple channel configs
// (even multiple bot instances of the same channel), and all credentials are passed in through the cfg parameter;
// caching things like the webhook URL in the implementation's own fields is not allowed.
package notify

// Channel type identifiers. The values are also the valid set for notification_channels.kind, validated by an allowlist
// on the server side (like findings.status, no DB CHECK is used, to make adding channels easier later).
const (
	KindDingTalk = "dingtalk" // DingTalk custom bot
	KindFeishu   = "feishu"   // Feishu (including Lark) custom bot
	KindWeCom    = "wecom"    // WeCom group bot
	KindWebhook  = "webhook"  // Generic Webhook: custom method/headers/JSON template
	KindTelegram = "telegram" // Telegram Bot API
	KindEmail    = "email"    // SMTP email
)

// Event types, matching notification_events.kind.
const (
	EventFindingCreated       = "finding_created"
	EventFindingStatusChanged = "finding_status_changed"
)

// InitKind is the fallback value when kind is empty in the config.
const InitKind = KindDingTalk

// severityRank maps vulnerability severity to a comparable ordinal. An unknown severity returns 0, so any
// min_severity setting keeps unknown severities out: when in doubt, do not push, to avoid flooding with false alarms.
var severityRank = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// SeverityRank returns the ordinal of a severity; an unknown severity returns 0.
func SeverityRank(severity string) int { return severityRank[severity] }

var severityLabels = map[string]string{
	"critical": "🔴 Critical", "high": "🟠 High", "medium": "🟡 Medium", "low": "🔵 Low",
}

var statusLabels = map[string]string{
	"pending": "Pending", "in_progress": "In progress", "confirmed": "Confirmed", "resolved": "Resolved", "fixed": "Fixed",
	"false_positive": "False positive", "ignored": "Ignored", "duplicate": "Duplicate", "risk_accepted": "Risk accepted",
}

// SeverityLabel returns the severity name with an emoji (in the current output language), used for message titles and card colors.
// An unknown severity is echoed as is, not invented.
func SeverityLabel(severity string) string {
	if v, ok := severityLabels[severity]; ok {
		return v
	}
	return severity
}

// StatusLabel translates a handling status into the current output language, used for status change messages. An unknown status is echoed as is.
func StatusLabel(status string) string {
	if v, ok := statusLabels[status]; ok {
		return v
	}
	return status
}

// AtLeast tells whether severity meets the min threshold. An empty min means no threshold, and everything passes.
// Note that an unknown severity has ordinal 0 and is rejected by any non-empty min (see the severityRank comment).
func AtLeast(severity, min string) bool {
	if min == "" {
		return true
	}
	return SeverityRank(severity) >= SeverityRank(min)
}
