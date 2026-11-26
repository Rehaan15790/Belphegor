package notify

import (
	"fmt"
	"strings"
)

// This file is the message rendering shared by the "Markdown family" channels (DingTalk, WeCom).
// Feishu uses card JSON, Telegram uses HTML, and mail uses HTML; each renders in its own adapter.

// maxAssetsShown is the maximum number of assets listed in a message. A finding may anchor dozens of assets,
// and listing them all would crowd the message with no informational value; nobody reads the 4th and later domains in an IM.
const maxAssetsShown = 3

// maxSummaryRunes is how many characters the summary is compressed to. An IM message is a "pointer to go see the details",
// not the report itself; the full content is on the platform.
const maxSummaryRunes = 120

// markdownReservedBytes is reserved for the message header (digest line + severity distribution + a possible truncation notice)
// and the footer (platform link). It is deducted from the budget when packing whole items, so the header and footer are not cut off;
// once they are cut, the reader cannot even tell "which batch this is and how many items are not shown".
const markdownReservedBytes = 320

// markdownEscape escapes markdown metacharacters.
//
// Why this is required: vulnerability titles, summaries, types and asset display names all come from **untrusted sources**.
// Titles and summaries come from model output (the model reads responses from the tested target), and an asset url is the
// full scanned URL (including a target-controlled query string). Without escaping, a vulnerability titled
//
//	Login SQL injection\n[Urgent: click to verify account](http://attacker.tld)
//
// would render as a **clickable external link** in a security engineer's DingTalk/Feishu, and
// `![](http://attacker.tld/beacon)` would be fetched by the client at render time, which tells the attacker
// "this vulnerability has been viewed" and leaks the reader's IP. Even harmless injected bold text or
// quote blocks can push the serious vulnerabilities below the fold.
//
// The escape set covers the characters for headings, links, emphasis, lists, quotes and strikethrough, which change
// structure or create clickable elements. `\` must be handled first, otherwise the backslashes added later would be escaped again.
func markdownEscape(s string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		"`", "\\`",
		"*", `\*`,
		"_", `\_`,
		"[", `\[`,
		"]", `\]`,
		"(", `\(`,
		")", `\)`,
		"!", `\!`,
		"#", `\#`,
		">", `\>`,
		"|", `\|`,
		"~", `\~`,
	)
	return replacer.Replace(s)
}

// markdownText squeezes untrusted text into one line and escapes it, for use in markdown body text.
// Collapsing to one line is the other half of escaping: a newline alone can forge a new list item or quote block,
// and escaping characters cannot stop it.
func markdownText(s string, maxRunes int) string {
	return markdownEscape(OneLine(s, maxRunes))
}

// markdownTitle returns the message title (the IM platform's title bar / card title) as **unescaped raw text**.
//
// Deliberately not escaped here: this title is shared by four rendering contexts: the markdown body, Telegram's
// HTML, the Feishu card's plain_text, and the generic Webhook's JSON and email subject. Each context has different
// escaping rules (markdown escaping put into HTML leaves visible backslashes, and put into JSON pollutes the
// data), so escaping must be done by each output side, see writeItem / feishuItemLines /
// telegramEscape. Markdown escaping was once added to the shared function, and the result was visible
// backslashes such as `\(1\)` in Telegram messages.
func markdownTitle(m Message) string {
	if m.Batch {
		return fmt.Sprintf("Vulnerability summary · %d total", len(m.Items))
	}
	if len(m.Items) == 0 {
		return "Vulnerability alert"
	}
	it := m.Items[0]
	return fmt.Sprintf("[%s] %s", SeverityLabel(it.Severity), OneLine(it.Title(), 0))
}

// markdownBody renders the message body and returns the body and the **number of items actually written**.
//
// The return value kept is the number of items this delivery really reached. The caller marks only the first kept items
// as delivered: items blocked by the channel length limit must wait for the next batch instead of being
// marked successful along with the rest. This is the source of "silent loss": the message was truncated, but the delivery record shows
// everything delivered, and nowhere can you see that the second half was never sent.
//
// maxBytes<=0 means no limit.
func markdownBody(m Message, maxBytes int) (string, int) {
	if !m.Batch {
		if len(m.Items) == 0 {
			return "", 0
		}
		var b strings.Builder
		writeItem(&b, m.Items[0], "", true)
		// A single message is sent even if it is too long (the final truncation is the fallback): partial information about one vulnerability
		// is better than sending none.
		return TruncateBytes(b.String(), maxBytes), 1
	}

	footer := ""
	if m.HomeURL != "" {
		footer = fmt.Sprintf("\n[View all on the platform](%s)\n", m.HomeURL)
	}
	kept := packItemCount(m.Items, maxBytes, markdownReservedBytes, footer, byteSize, func(it Item, idx int) string {
		var b strings.Builder
		writeItem(&b, it, fmt.Sprintf("%d. ", idx+1), false)
		return b.String()
	})

	items := m.Items[:kept]
	var b strings.Builder
	b.WriteString(markdownBatchIntro(m, items, len(m.Items)))
	for i, it := range items {
		writeItem(&b, it, fmt.Sprintf("%d. ", i+1), false)
	}
	b.WriteString(footer)
	return TruncateBytes(b.String(), maxBytes), kept
}

// markdownBatchIntro renders the opening of a digest message: time window, count and severity breakdown.
// With these, the recipient of a digest can tell without opening the platform whether this batch needs immediate action.
//
// items are the items **actually fitted**, total is the total this batch should have. When they differ, it must say
// how many more are in the next message; otherwise the reader will think the number in the header is everything,
// and the items that were never sent do not exist anywhere in the UI.
func markdownBatchIntro(m Message, items []Item, total int) string {
	var b strings.Builder
	if m.WindowMinutes > 0 {
		fmt.Fprintf(&b, "**%d new vulnerabilities in the last %d minutes**", total, m.WindowMinutes)
	} else {
		fmt.Fprintf(&b, "**%d new vulnerabilities**", total)
	}
	if extra := total - len(items); extra > 0 {
		fmt.Fprintf(&b, "(This message shows only the first %d; the remaining %d will follow in the next message)", len(items), extra)
	}
	// Give the breakdown by severity so the reader sees at a glance whether there are serious items. Count only the
	// items **contained in this message**, so "Critical 3" matches the items that can be counted below.
	counts := map[string]int{}
	for _, it := range items {
		counts[it.Severity]++
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", SeverityLabel(sev), n))
		}
	}
	if len(parts) > 0 {
		b.WriteString("\n" + strings.Join(parts, " · "))
	}
	b.WriteString("\n\n")
	return b.String()
}

// writeItem renders a single vulnerability item.
//
// prefix is the sequence number for digest lists; with single=true it renders the full version (with summary and back link),
// while a digest list renders only a one-line summary, otherwise a 50-item digest becomes a long document.
//
// All externally sourced content (title/type/asset/summary) goes through markdownText:
// single-line collapsing plus escaping. The back link is built from the public_base_url configured by the admin, is not untrusted content,
// and must be a clickable link, so it is output as is.
func writeItem(b *strings.Builder, it Item, prefix string, single bool) {
	line := fmt.Sprintf("%s**%s · %s**", prefix, SeverityLabel(it.Severity), markdownText(it.Title(), 0))
	if !single {
		// Digest mode: present on one line, with the asset and summary compressed after it.
		var extras []string
		if a := assetLine(it.Assets, maxAssetsShown); a != "" {
			extras = append(extras, markdownText(a, 0))
		}
		if it.Summary != "" {
			extras = append(extras, markdownText(it.Summary, 60))
		}
		if len(extras) > 0 {
			line += " — " + strings.Join(extras, " · ")
		}
		b.WriteString(line + "\n")
		return
	}
	b.WriteString(line + "\n")
	if it.IsStatusChange() {
		fmt.Fprintf(b, "**Status change**: %s → %s\n",
			markdownText(StatusLabel(it.FromStatus), 0), markdownText(StatusLabel(it.ToStatus), 0))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		fmt.Fprintf(b, "**Type**: %s\n", markdownText(it.VulnClass, 0))
	}
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		fmt.Fprintf(b, "**Asset**: %s\n", markdownText(a, 0))
	}
	if it.Summary != "" {
		if s := markdownText(it.Summary, maxSummaryRunes); s != "" {
			fmt.Fprintf(b, "**Summary**: %s\n", s)
		}
	}
	if it.DetailURL != "" {
		fmt.Fprintf(b, "[View details](%s)\n", it.DetailURL)
	}
}
