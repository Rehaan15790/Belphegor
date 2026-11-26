package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// allowLocalTargets decides whether messages may be delivered to loopback / link-local addresses.
//
// Denied by default. These ranges are not where IM bots or public mail servers live, yet what they can
// reach is sensitive: the admin port of another service on the same machine, and the cloud metadata endpoint
// (169.254.169.254, which can expose instance credentials). The delivery address is set by an admin, but an admin session
// borrowed through XSS/CSRF, or a second person sharing the same JWT, could change the config to read response content back
// (doJSON writes the first 200 bytes of a 4xx/5xx response body into last_error, and the delivery history endpoint
// echoes it), which is a semi-blind read primitive.
//
// However, a "local SMTP relay" (postfix on 127.0.0.1:25) is a common self-hosted mail setup,
// and a blanket ban would block people. So an explicit escape hatch is left instead of a hardcoded allowance:
// setting BELPHEGOR_NOTIFY_ALLOW_LOCAL=1 allows it.
//
// It is exported as AllowLocalTargetsEnv so tests can turn it on explicitly: many cases in this package and the server package
// use httptest fake receivers on 127.0.0.1, and without it all of them would be stopped by the guard.
const AllowLocalTargetsEnv = "BELPHEGOR_NOTIFY_ALLOW_LOCAL"

func allowLocalTargets() bool {
	v := strings.TrimSpace(os.Getenv(AllowLocalTargetsEnv))
	return v == "1" || strings.EqualFold(v, "true")
}

// isBlockedDialIP reports whether the target IP is in a range that is "not allowed for delivery by default".
//
// Only loopback, link-local (including the cloud metadata address 169.254.169.254), unspecified and multicast are denied.
// RFC1918 private ranges are **not denied**: a self-hosted Mattermost / SMTP relay on the internal network is a very common legitimate use,
// and blocking them too would make the feature unusable in real environments. This tradeoff is deliberate:
// the protection must block the truly sensitive targets without ruining normal deployments.
func isBlockedDialIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// IPv4-mapped IPv6 (::ffff:127.0.0.1) must be converted back to IPv4 before checking, otherwise it bypasses the check.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// blockInternalDial is the Control hook of the http.Transport dialer; it checks the target address
// **at connection time**.
//
// Why it is placed at the dial stage rather than only validating when saving config: this is where the check finally takes effect.
// It covers both ways of bypassing config validation: DNS rebinding (resolving to a public IP at validation time
// and to an internal one at connect time) and redirects (although cross-host redirects are already rejected, a same-host redirect
// could still point the path elsewhere).
func blockInternalDial(_, address string, _ syscall.RawConn) error {
	if allowLocalTargets() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("cannot resolve target address: %q", host)
	}
	if isBlockedDialIP(ip) {
		return fmt.Errorf("Not sending to local or link-local address %s (set %s=1 if you must send to a local service)", ip, AllowLocalTargetsEnv)
	}
	return nil
}

// notifyTransport adds only a dial guard on top of the default Transport.
// It uses Clone to keep all the default tuning (connection pool, HTTP/2, timeouts, proxy, etc.),
// avoiding changes to other behavior just to add one check.
var notifyTransport = func() *http.Transport {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Transport{}
	}
	clone := t.Clone()
	clone.DialContext = (&net.Dialer{Timeout: 10 * time.Second, Control: blockInternalDial}).DialContext
	return clone
}()

// httpClient is the client shared by all channel deliveries.
//
// It deliberately does **not** reuse the project's global egress proxy (the server-side GlobalProxy): that proxy is for penetration
// target traffic and is often an unstable tunnel, and notification availability should not be held hostage by jitter in the target network.
// IM pushes can connect directly. The timeout is 15 seconds; a peer slower than that is effectively already in a failed state.
//
// Cross-host redirects are rejected: the delivery addresses of this feature are all of the "one fixed endpoint" form and normally do not
// redirect to another host; and these vendors' credentials (DingTalk's access_token, WeCom's key, Telegram's
// bot token) are **in the URL**, so following a cross-host redirect would hand the credentials to the redirect target. Same-host
// redirects (such as adding a trailing slash) are still allowed.
var httpClient = &http.Client{
	Timeout:   15 * time.Second,
	Transport: notifyTransport,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if len(via) > 0 && req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("redirects to another host are not allowed (%s → %s)", via[0].URL.Host, req.URL.Host)
		}
		return nil
	},
}

// respBodyLimit limits how much of the response body is read. A misbehaving peer may send back huge content, while we only need
// the error code and a short error description to show in the delivery history.
const respBodyLimit = 8 << 10

// doJSON sends one request and returns the response body (length-limited).
//
// When payload is nil an empty body is sent (for GET or platforms that do not require a body).
// The key-value pairs in headers are attached as is, for custom headers of the generic webhook.
//
// Error classification is this function's core job: network-layer failures and 5xx/408/429 are "retryable",
// and other 4xx are "permanent failures"; retrying a 403 just logs the same error 3 times.
func doJSON(ctx context.Context, method, url string, headers map[string]string, payload any) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			// A serialization failure is a local bug (wrong config field type); retrying will not help.
			return nil, Permanent(fmt.Errorf("failed to build request body: %w", err))
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		// Invalid URL, most likely the user entered the address wrong, so it is a permanent failure.
		// err must not be passed through here either: the error text from url.Parse contains the full address.
		return nil, Permanent(fmt.Errorf("invalid request address: %s", redactRequestTarget(url)))
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// Connection refused, DNS failure, timeout: mostly transient faults, left to backoff retry.
		//
		// The error text must be redacted before being passed on. Reason: http.Client.Do returns a *url.Error,
		// whose Error() is `Op "full URL": underlying error`, and the credentials of these vendors are **in the URL**
		// (DingTalk access_token, WeCom key, Feishu hook id, Telegram /bot<token>/).
		// Without redaction, credentials would flow through this error string to four places: last_error in notification_deliveries
		// (stored in plaintext), the delivery history endpoint response (**bypassing the channel config masking**),
		// server logs, and the 502 text the test-send endpoint returns to the frontend.
		return nil, fmt.Errorf("request failed: %s", redactTransportError(err))
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, respBodyLimit))
	if readErr != nil {
		return nil, fmt.Errorf("failed to read response: %w", readErr)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return raw, nil
	}
	// 429 (rate limited) and 408 (timeout) are worth retrying; other 4xx are config or permission problems, and retrying is pointless.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout {
		return nil, fmt.Errorf("the remote server throttled the request or responded slowly (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("the remote server returned an error (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}
	return nil, Permanent(fmt.Errorf("the remote server rejected the request (HTTP %d): %s", resp.StatusCode, snippet(raw)))
}

// snippet compresses a response body into a short single line for error messages. A response may contain newlines and lots of whitespace,
// and putting it straight into last_error would break the layout of the delivery history page.
func snippet(raw []byte) string {
	return OneLine(string(raw), 200)
}

// redactRequestTarget compresses a delivery address to "scheme://host/..." for error messages.
//
// This is the only address redaction policy in this package, and it is deliberately **blunt**: everything except scheme and host
// is dropped. The reason is that there is no "generic and safe" way to tell which part of a URL is the credential:
//
//	DingTalk   credential in query      /robot/send?access_token=xxx
//	WeCom      credential in query      /cgi-bin/webhook/send?key=xxx
//	Feishu     credential at the **end of the path** /open-apis/bot/v2/hook/<hook_id>
//	Telegram   credential in the **middle of the path** /bot<token>/sendMessage
//
// Trying to "keep only the useful part" would need per-channel patches, and missing any one vendor is a credential leak.
// Keeping the host is enough for troubleshooting (DNS failure, cannot connect, wrong certificate can all be located),
// and which bot it is can be identified from the masked tail hint in the channel config.
//
// On a parse failure a fixed placeholder is returned; the raw string is never echoed.
func redactRequestTarget(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(address could not be parsed)"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// redactTransportError strips the address from a transport-layer error, keeping only the underlying cause.
//
// The structure of *url.Error is {Op, URL, Err}, and Error() prints the URL as well.
// Here the Err field is taken explicitly, bypassing its Error(); this is more reliable than string replacement afterwards,
// because replacement has to handle all the URL-encoded/escaped variants correctly and easily misses some.
func redactTransportError(err error) string {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		host := ""
		if u, parseErr := url.Parse(uerr.URL); parseErr == nil {
			host = u.Host
		}
		if uerr.Err != nil {
			return fmt.Sprintf("%s %s: %s", uerr.Op, host, uerr.Err)
		}
		return fmt.Sprintf("%s %s: unknown error", uerr.Op, host)
	}
	// A non-*url.Error (such as an error returned by the redirect policy) may also carry an address, so it all goes through redaction.
	return redactURLsInText(err.Error())
}

// redactURLsInText replaces the http(s) addresses appearing in a text with their redacted form.
//
// Used as a fallback for errors without structured fields (redirect policy errors, custom errors from third-party libraries).
// Only the http/https prefix is recognized, and the text is split on whitespace and quotes, since an address contains neither.
func redactURLsInText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		rest := s[i:]
		if strings.HasPrefix(rest, "http://") || strings.HasPrefix(rest, "https://") {
			end := len(rest)
			if j := strings.IndexAny(rest, " \t\n\"'"); j >= 0 {
				end = j
			}
			b.WriteString(redactRequestTarget(rest[:end]))
			i += end
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
