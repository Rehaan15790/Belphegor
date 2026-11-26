package notify

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Filter is the contract of the notification_channels.filter JSONB column: the filter conditions of a channel instance.
// All fields are optional, and the default means "no filtering", which is the fallback semantics for malformed config; see ParseFilter.
type Filter struct {
	// MinSeverity is the minimum severity threshold (low/medium/high/critical); empty = no threshold.
	MinSeverity string `json:"min_severity"`
	// TaskIDs / AssetIDs: an empty array means unrestricted; if non-empty, the event must intersect with it.
	TaskIDs  []int64 `json:"task_ids"`
	AssetIDs []int64 `json:"asset_ids"`
	// VulnClassInclude empty means accept all; if non-empty, vulnclass must match any one of the keywords.
	// VulnClassExclude excludes on matching any keyword (exclude takes precedence over include).
	// Matching is a case-insensitive substring, which is safer than regex: a user's wrong regex will not silently disable the channel.
	VulnClassInclude []string `json:"vulnclass_include"`
	VulnClassExclude []string `json:"vulnclass_exclude"`
	// OnStatusChange decides whether this channel receives finding status change events (meaningful only in realtime mode).
	OnStatusChange bool `json:"on_status_change"`
}

// ParseFilter parses the channel filter config.
//
// **Never returns an error.** This is a deliberate design choice: a malformed filter config always degrades to a zero-value
// Filter (= no filtering = match everything), because for a vulnerability notification system, **one extra push is far better than
// silently missing a high-severity one**. Turning a parse failure into "no push" would give the user a channel that looks configured
// but pushes nothing, which is the worst failure mode.
func ParseFilter(raw []byte) Filter {
	var f Filter
	if len(raw) == 0 {
		return f
	}
	// On a parse failure f stays at its zero value, i.e. no filtering.
	_ = json.Unmarshal(raw, &f)
	return f
}

// ValidMinSeverity reports whether s is a valid severity threshold (an empty string means no threshold).
func ValidMinSeverity(s string) bool {
	if s == "" {
		return true
	}
	_, ok := severityRank[s]
	return ok
}

// Validate checks the **restricted-value** fields in the filter config, called when saving a channel.
//
// Why it must be blocked at write time: Match treats an unknown threshold as `rank >= 0`, which is always true,
// so a single typo in min_severity ("hgih") makes the filter **silently ineffective** and turn into
// "push everything". This is consistent with this package's "better to over-push than miss" tradeoff (nothing is missed),
// but the result is that the user thinks they are doing tiered pushes while actually flooding the group with all findings,
// with no sign at all that the config is wrong. This kind of "silent degradation" should be blocked at the entry point.
//
// Note that Validate is used only on the **write** path. The read path still uses ParseFilter's lenient semantics,
// so bad values already present in historical data do not make the whole channel unreadable.
func (f Filter) Validate() error {
	if !ValidMinSeverity(f.MinSeverity) {
		return fmt.Errorf("invalid minimum severity: %q. Choose from low / medium / high / critical, or leave it empty for no restriction", f.MinSeverity)
	}
	return nil
}

// Match decides whether an event should be delivered to a channel with this filter.
//
// **Never returns an error**, for the same reason as ParseFilter: any internal anomaly is treated as a "match".
// Decision order: event type → severity threshold → task/asset scope → vulnerability type keywords.
func Match(f Filter, s Snapshot) bool {
	// Status change events are received only by channels that explicitly enable them. Off by default, because most users
	// expect "push" to mean "new finding discovered", not a running log tracking every status transition.
	if s.Kind == EventFindingStatusChanged && !f.OnStatusChange {
		return false
	}
	if !AtLeast(s.Severity, f.MinSeverity) {
		return false
	}
	if len(f.TaskIDs) > 0 && !slices.Contains(f.TaskIDs, s.TaskID) {
		return false
	}
	if len(f.AssetIDs) > 0 && !intersectsInt(f.AssetIDs, s.AssetIDs) {
		return false
	}
	// Exclude takes precedence: matching any exclude keyword drops the event, even if it also matches the include list.
	if len(f.VulnClassExclude) > 0 && containsAnyFold(s.VulnClass, f.VulnClassExclude) {
		return false
	}
	if len(f.VulnClassInclude) > 0 && !containsAnyFold(s.VulnClass, f.VulnClassInclude) {
		return false
	}
	return true
}

func intersectsInt(a, b []int64) bool {
	// A linear scan is fine for small sets; both sides are on the order of "a few dozen hand-picked entries",
	// and building a map costs more than it gains.
	for _, v := range b {
		if slices.Contains(a, v) {
			return true
		}
	}
	return false
}

// containsAnyFold reports whether s contains any keyword in keywords (case-insensitive).
func containsAnyFold(s string, keywords []string) bool {
	lower := strings.ToLower(s)
	for _, kw := range keywords {
		kw = strings.ToLower(strings.TrimSpace(kw))
		if kw != "" && strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
