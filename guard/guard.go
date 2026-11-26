// Package guard implements the safety boundary layer (docs §11): an audit log,
// user-configured intercept-rule evaluation, and Observer/G5 failure attribution.
// Every tool call passes through the PreToolUse hook before executing.
// (The RoE authorization-scope mechanism was removed; a replacement may be added
// later.) Destructive/exfil gating is no longer hard-coded here — it lives in the
// DB intercept rules (seeded as ordinary [built-in] rules, so users can disable or
// delete them), evaluated via applyIntercept.
package guard

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/norma/hook"
	"github.com/Rehaan15790/belphegor/intercept"
)

// AuditEntry records one gated tool call.
type AuditEntry struct {
	TS      int64  `json:"ts"`
	Tool    string `json:"tool"`
	Action  string `json:"action"` // allow|block
	Reason  string `json:"reason,omitempty"`
	Command string `json:"command,omitempty"`
}

// Guard enforces the side-effect policy via agent-core hooks.
type Guard struct {
	mu          sync.Mutex
	audit       []AuditEntry
	attrib      map[string]int // failure attribution counts (Observer / G5)
	reg         *hook.Registry
	interceptor *intercept.Interceptor // optional; nil disables user-configured rules
}

// New creates a Guard without user-configured intercept rules (used for pentest
// tasks where the Interceptor is not yet available).
func New() *Guard { return newGuard(nil) }

// NewWithInterceptor creates a Guard with user-configured intercept rules.
func NewWithInterceptor(ic *intercept.Interceptor) *Guard { return newGuard(ic) }

func newGuard(ic *intercept.Interceptor) *Guard {
	g := &Guard{attrib: map[string]int{}, interceptor: ic}
	g.reg = hook.NewRegistry().
		On(hook.PreToolUse, g.preToolUse).
		On(hook.PostToolUse, g.postToolUse)
	return g
}

// Hooks returns the hook registry to attach to an agent session.
func (g *Guard) Hooks() *hook.Registry { return g.reg }

func (g *Guard) preToolUse(ctx context.Context, ev hook.Event) hook.Result {
	// Extract the shell-command surface for the audit log: Bash + the interactive-shell
	// tools (shell_open's command, shell_send's text). Destructive/exfil gating is no
	// longer hard-coded here — it now lives in the DB intercept rules, evaluated by
	// applyIntercept below. Other tools record an empty command.
	var cmd string
	tool, input := canonicalCall(ev.ToolName, ev.Input)
	switch tool {
	case "Bash", "shell_open":
		var in struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(input, &in)
		cmd = in.Command
	case "shell_send":
		var in struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(input, &in)
		cmd = in.Text
	}
	g.record(tool, "allow", "", cmd)
	return g.applyIntercept(ctx, tool, input)
}

// RequireApproval makes calls that run a command, write a file, reach an MCP server or change
// the platform wait for a human unless a rule or the judge already decided. main sets it when
// Belphegor runs directly on the host instead of in a container.
var RequireApproval bool

// hostApprovalSeconds is how long such a call waits before it is denied.
const hostApprovalSeconds = 300

func needsApproval(tool string) bool {
	switch tool {
	case "Bash", "Monitor", "shell_open", "shell_send", "Write", "Edit", "MultiEdit",
		"create_mcp", "update_mcp", "create_custom_tool", "update_custom_tool",
		"create_skill", "update_skill_file":
		return true
	}
	return strings.HasPrefix(tool, "mcp__")
}

// canonicalNames maps a folded name (lower case, no underscores) to the official tool name, so
// the drift aliases registered in agent/toolcatalog.go ("bash", "web_fetch") hit the same rules.
var canonicalNames = func() map[string]string {
	m := map[string]string{}
	for _, n := range []string{
		"Bash", "Monitor", "shell_open", "shell_send", "Read", "Write", "Edit", "MultiEdit", "LS", "Glob", "Grep",
		"WebFetch", "web_search", "ExecuteExtraTool",
	} {
		m[foldName(n)] = n
	}
	return m
}()

func foldName(s string) string { return strings.ToLower(strings.ReplaceAll(s, "_", "")) }

func canonicalName(name string) string {
	if n, ok := canonicalNames[foldName(name)]; ok {
		return n
	}
	return name
}

// canonicalCall resolves aliases and unwraps ExecuteExtraTool, which invokes another tool
// directly and would otherwise carry it past the rules.
func canonicalCall(name string, input []byte) (string, []byte) {
	name = canonicalName(name)
	if name == "ExecuteExtraTool" {
		var in struct {
			ToolName string          `json:"tool_name"`
			Params   json.RawMessage `json:"params"`
		}
		if json.Unmarshal(input, &in) == nil && in.ToolName != "" {
			return canonicalName(in.ToolName), in.Params
		}
	}
	return name, input
}

// applyIntercept evaluates user-configured intercept rules against the tool call.
// Both rules and the fallback judge receive the complete tool input.
func (g *Guard) applyIntercept(ctx context.Context, tool string, input []byte) hook.Result {
	if g.interceptor == nil {
		return hook.Result{}
	}
	ctx = intercept.WithCall(ctx, tool, input)
	var dec intercept.Decision
	decided := false
	if g.interceptor.IsToolEnabled(tool) {
		if dec, decided = g.interceptor.Match(tool, input); !decided {
			// No rule matched. Ask the LLM fallback judge, if it is enabled.
			dec, decided = g.interceptor.Judge(ctx, tool, input)
		}
	}
	if !decided {
		if !RequireApproval || !needsApproval(tool) {
			return hook.Result{}
		}
		dec = intercept.Decision{
			Action: "ask", Message: "Belphegor runs directly on this computer, so this call needs approval",
			TimeoutEnabled: true, TimeoutSeconds: hostApprovalSeconds, TimeoutAction: "deny",
		}
	}
	switch dec.Action {
	case "deny":
		// A deny does not wait for approval; log it so it shows in history and on the task's intercept page.
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, tool, input, "denied")
		return g.block(tool, systemBlockMessage(dec.Message), "")
	case "allow":
		// Record explicit rule and model approvals so review details remain auditable.
		g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, tool, input, "allowed")
		return hook.Result{}
	case "ask":
		// If the worker context is already cancelled (task stopped / killed), block
		// immediately without creating a pending record — avoids orphaned DB entries
		// and makes execOne complete fast, reducing the race against drainSynthetic.
		if ctx.Err() != nil {
			return g.block(tool, systemBlockMessage("the work was cancelled, so platform safety control stopped it"), "")
		}
		convID := intercept.ConvIDFromContext(ctx)
		if !g.interceptor.HandleAsk(ctx, convID, dec, tool, input) {
			return g.block(tool, systemBlockMessage("not approved (denied by the operator, or approval timed out)"), "")
		}
		return hook.Result{}
	}
	return hook.Result{}
}

// systemBlockMessage frames an intercept block as an Belphegor platform-governance
// decision so the agent does not mistake it for a target-side defense.
//
// The bare reasons ("this tool is forbidden" / "user denied") read exactly like a WAF/403 on
// the target, so a pentest agent's instinct is to bypass them: rewrite the
// command, swap the payload, re-encode, retry. That is both futile (the platform
// blocks the class of action, not one string) and wrong (it's a policy decision,
// not an obstacle to defeat). This prefix states plainly that the block comes
// from the platform, is not the target's protection, and that the operation is
// forbidden, so the agent pivots to another approach instead of evading it.
// Audit/history rows keep the raw reason (see Interceptor.Log); only the
// model-facing tool_result carries this framing.
func systemBlockMessage(reason string) string {
	return "[Belphegor platform control - not a target defense]This call was intercepted by the platform. Reason: " + reason + ". This action is prohibited."
}

var reBlocked = regexp.MustCompile(`(?i)\b(403|forbidden|waf|blocked|rate.?limit|429|captcha|denied)\b`)

// postToolUse is the Observer failure-attribution hook (G5): it classifies tool
// results into blocked / error / ok so the planner can change strategy instead
// of giving up at a WAF.
func (g *Guard) postToolUse(_ context.Context, ev hook.Event) hook.Result {
	if canonicalName(ev.ToolName) != "Bash" {
		return hook.Result{}
	}
	class := "ok"
	switch {
	case reBlocked.Match(ev.Result):
		class = "blocked"
	case ev.IsError:
		class = "error"
	}
	g.mu.Lock()
	g.attrib[class]++
	g.mu.Unlock()
	return hook.Result{}
}

// Attributions returns failure-attribution counts (Observer / G5).
func (g *Guard) Attributions() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.attrib))
	for k, v := range g.attrib {
		out[k] = v
	}
	return out
}

func (g *Guard) block(tool, reason, cmd string) hook.Result {
	g.record(tool, "block", reason, cmd)
	return hook.Result{Decision: "block", Message: reason}
}

func (g *Guard) record(tool, action, reason, cmd string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.audit = append(g.audit, AuditEntry{TS: time.Now().Unix(), Tool: tool, Action: action, Reason: reason, Command: cmd})
	if len(g.audit) > 2000 {
		g.audit = g.audit[len(g.audit)-2000:]
	}
}

// Audit returns a snapshot of recent gated calls (most recent last).
func (g *Guard) Audit() []AuditEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuditEntry, len(g.audit))
	copy(out, g.audit)
	return out
}
