package notify

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// Channel is the adapter for a notification channel. Implementations must be **stateless**:
// the same instance is reused concurrently by multiple channel configs, and credentials
// are always passed in through the cfg parameter.
type Channel interface {
	// Kind returns the channel type identifier, which must match the registry key.
	Kind() string
	// Validate is called when saving the config and checks required fields and format.
	// The returned error is shown directly to the person configuring, so the message
	// should say "which field is missing" rather than a vague "invalid config".
	Validate(cfg map[string]any) error
	// Send delivers one message and returns the **number of items actually delivered** and an error.
	//
	// Why return a count: every platform has a message length limit, and a digest message
	// that cannot hold the whole batch is truncated. If the caller unconditionally marked
	// the whole batch as delivered, the truncated items would vanish: not visible in the
	// message, yet shown as successful in the delivery history, so nothing would reveal
	// that the finding was never sent. With kept returned, the caller marks only the
	// first kept items and leaves the rest for the next batch.
	//
	// A returned error means delivery failed; a *PermanentError means it should not be retried.
	// On failure kept is meaningless and the caller should ignore it.
	Send(ctx context.Context, cfg map[string]any, m Message) (int, error)
	// DefaultRatePerMin returns the channel's officially recommended per-minute delivery
	// limit, used as the default rate limit when a new channel instance is created.
	// Returning 0 means there is no known limit.
	DefaultRatePerMin() int
	// SecretKeys returns the key names in this channel's config that are credentials.
	// When the API echoes the config, the values of these keys are masked, and on update,
	// receiving a masked value keeps the original value in the database. Only the
	// implementation knows which fields count as credentials (for WeCom the whole Webhook
	// URL is a credential, while for DingTalk it is only the secret), so this knowledge
	// must come from the channel and cannot be guessed by upper layers.
	SecretKeys() []string
	// DestinationKeys returns the key names in this channel's config that decide "where the
	// message goes".
	//
	// Like SecretKeys this is security-relevant: the destination and the credentials are two
	// independent sets of fields, and if "change only the address and keep the credentials as
	// they are" were allowed, anyone who can edit channel config could send the real stored
	// credentials to a server they control, which would make the channel config masking
	// meaningless.
	// See PrepareConfigUpdate for details.
	DestinationKeys() []string
}

// registry is the channel registry. It is deliberately an explicit literal rather than
// init() self-registration: that way "which channels exist" can be seen in one place,
// and a newly added channel exposes omissions at compile time instead of relying on
// runtime side effects.
var registry = map[string]Channel{
	KindDingTalk: dingTalkChannel{},
	KindFeishu:   feishuChannel{},
	KindWeCom:    weComChannel{},
	KindWebhook:  webhookChannel{},
	KindTelegram: telegramChannel{},
	KindEmail:    emailChannel{},
}

// Get returns the channel implementation by kind.
func Get(kind string) (Channel, bool) {
	c, ok := registry[kind]
	return c, ok
}

// ValidKind reports whether kind is a supported channel type.
func ValidKind(kind string) bool {
	_, ok := registry[kind]
	return ok
}

// Kinds returns all supported channel types in lexicographic order (so the UI dropdown is stable).
func Kinds() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// PermanentError marks a delivery failure that should not be retried: bad credentials,
// target rejection, an invalid request body, and so on.
// Retrying only makes sense for transient faults (network jitter, rate limits, peer 5xx);
// retrying a permanent failure with backoff will not succeed and would bury the real
// error in the retry log.
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// Permanent marks err as a permanent failure. It returns nil when err is nil,
// so it can be written as `return Permanent(someCheck())`.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &PermanentError{Err: err}
}

// IsPermanent reports whether the err chain carries the permanent-failure mark.
func IsPermanent(err error) bool {
	var pe *PermanentError
	return errors.As(err, &pe)
}

// ---- config reading helpers ----
//
// Channel config comes from a database JSONB column and, after encoding/json
// deserialization, is a map[string]any: numbers are always float64 and arrays are []any.
// The helpers below unify this conversion and tolerate type deviations caused by
// the user leaving fields blank in the UI (such as entering the port as a string).

// cfgString gets a string config item and trims leading and trailing whitespace; copy-pasting from a web form easily brings it along.
func cfgString(cfg map[string]any, key string) string {
	v, ok := cfg[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

// cfgInt gets an integer config item, accepting both float64 (the JSON default) and string sources.
func cfgInt(cfg map[string]any, key string) int {
	switch v := cfg[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

// cfgBool gets a boolean config item, also accepting the strings "true"/"1".
func cfgBool(cfg map[string]any, key string) bool {
	switch v := cfg[key].(type) {
	case bool:
		return v
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		return s == "true" || s == "1" || s == "yes"
	default:
		return false
	}
}

// cfgStrings gets a string-array config item, trimming whitespace and dropping empty strings.
func cfgStrings(cfg map[string]any, key string) []string {
	raw, ok := cfg[key].([]any)
	if !ok {
		// A single string is also accepted, which makes form submission easy when there is only one value.
		if s := cfgString(cfg, key); s != "" {
			return []string{s}
		}
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// cfgMap gets a string-map config item (such as custom HTTP headers), trimming whitespace on keys and values and dropping empty keys.
func cfgMap(cfg map[string]any, key string) map[string]string {
	raw, ok := cfg[key].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		out[k] = s
	}
	return out
}
