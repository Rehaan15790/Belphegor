package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"
)

// dingTalkChannel implements the DingTalk custom robot.
//
// Platform characteristics (which drive the trade-offs here):
//   - Per-robot rate limit of 20 messages/minute; excess is silently dropped (HTTP may
//     still return 200), so rate limiting must be done client-side; see DefaultRatePerMin.
//   - Security settings are one of three: signing / custom keywords / IP allowlist. Signing
//     is the only scheme that does not depend on message content, so only signing is
//     supported (plus a bare webhook with none of the three enabled).
//   - Both success and failure return HTTP 200, distinguished by errcode in the body;
//     without checking errcode a delivery failure would be recorded as success.
type dingTalkChannel struct{}

func (dingTalkChannel) Kind() string { return KindDingTalk }

func (dingTalkChannel) DefaultRatePerMin() int { return 20 }

// The DingTalk Webhook URL carries an access_token and is itself a credential, so it is masked as a whole.
func (dingTalkChannel) SecretKeys() []string { return []string{"webhook", "secret"} }

// The destination is the DingTalk Webhook URL itself; changing the URL requires re-stating the signing secret for the new URL.
func (dingTalkChannel) DestinationKeys() []string { return []string{"webhook"} }

func (dingTalkChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("Webhook URL is missing")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("Webhook URL is invalid: %w", err)
	}
	return nil
}

// Send delivers one message. Uses ActionCard (with a button) when there is a back link and a single item, otherwise markdown.
func (c dingTalkChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	hook := cfgString(cfg, "webhook")
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	endpoint, err := dingTalkSignedURL(hook, cfgString(cfg, "secret"), time.Now())
	if err != nil {
		return 0, Permanent(err)
	}

	title := markdownTitle(m)
	// The DingTalk markdown body has no explicit byte limit, but a cap is still applied to keep evidence fields from growing abnormally.
	text, kept := markdownBody(m, 20000)

	var payload any
	if !m.Batch && len(m.Items) == 1 && m.Items[0].DetailURL != "" {
		payload = map[string]any{
			"msgtype": "actionCard",
			"actionCard": map[string]any{
				"title":          title,
				"text":           text,
				"btnOrientation": "0",
				"singleTitle":    "View details",
				"singleURL":      m.Items[0].DetailURL,
			},
		}
	} else {
		payload = map[string]any{
			"msgtype":  "markdown",
			"markdown": map[string]any{"title": title, "text": text},
		}
	}

	raw, err := doJSON(ctx, "POST", endpoint, nil, payload)
	if err != nil {
		return 0, err
	}
	// DingTalk hides business errors inside a 200 response.
	var res struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("Failed to parse DingTalk response: %w (%s)", err, snippet(raw))
	}
	if res.ErrCode != 0 {
		// 301000 is a signature verification failure and 310000 is a keyword mismatch; both are
		// config errors that retrying will not heal.
		return 0, Permanent(fmt.Errorf("DingTalk returned an error (%d): %s", res.ErrCode, res.ErrMsg))
	}
	return kept, nil
}

// dingTalkSignedURL appends the timestamp and sign parameters to the webhook per the official signing rules.
//
// Rule: string to sign = timestamp + "\n" + secret, the HMAC-SHA256 **key is also the secret**,
// and the result is base64-encoded then URL-encoded. timestamp is in milliseconds. When secret
// is empty the URL is returned as is, to support robots without signing enabled.
func dingTalkSignedURL(hook, secret string, now time.Time) (string, error) {
	if secret == "" {
		return hook, nil
	}
	ts := strconv.FormatInt(now.UnixMilli(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "\n" + secret))
	sign := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	u, err := url.Parse(hook)
	if err != nil {
		// Do not pass err through: the url.Parse error text carries the full URL (including access_token).
		return "", fmt.Errorf("Failed to parse Webhook URL: %s", redactRequestTarget(hook))
	}
	q := u.Query()
	q.Set("timestamp", ts)
	q.Set("sign", sign)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// validateHTTPURL checks that the URL is usable and the scheme is supported, and does an internal-network check on literal IP targets.
//
// Two points of care:
//
//  1. **The error message must be sanitized**. url.Parse itself returns a *url.Error whose
//     Error() carries the **full original URL**, and for the providers in this feature the
//     URL embeds credentials (DingTalk access_token, WeCom key, Telegram bot token,
//     Feishu hook id). This used to `return err` directly, so the "invalid URL format"
//     error leaked the credentials into the 400 response of the test endpoint, the
//     last_error stored on every delivery, the server logs and the delivery history endpoint.
//
//  2. **Literal IPs are judged internal directly**, while domain names are left to the dial
//     stage (blockInternalDial is the final enforcement point and also covers DNS rebinding).
//     This is done once here so the hint appears when the config is saved, not after the
//     first delivery fails.
//
// Restricting the scheme is defensive: file:/// gopher:// and the like would make
// http.Client behave unexpectedly (already stopped by the scheme check, but there is no
// reason to open up this surface).
func validateHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("Cannot parse URL (%s)", redactRequestTarget(raw))
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("Only http or https is supported. Got: %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("Host name is missing")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && isBlockedDialIP(ip) && !allowLocalTargets() {
		return fmt.Errorf("Not sending to local or link-local address %s (set %s=1 if you must send to a local service)", ip, AllowLocalTargetsEnv)
	}
	return nil
}
