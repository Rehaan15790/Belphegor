package guard

import (
	"encoding/json"
	"testing"
)

func TestCanonicalCallClosesBypasses(t *testing.T) {
	cases := []struct{ name, input, tool, want string }{
		{"bash", `{"command":"id"}`, "Bash", `{"command":"id"}`},
		{"BASH", `{}`, "Bash", `{}`},
		{"web_fetch", `{}`, "WebFetch", `{}`},
		{"multi_edit", `{}`, "MultiEdit", `{}`},
		{"execute_extra_tool", `{"tool_name":"mcp__browser__click","params":{"x":1}}`, "mcp__browser__click", `{"x":1}`},
		{"ExecuteExtraTool", `{"tool_name":"bash","params":{"command":"id"}}`, "Bash", `{"command":"id"}`},
		{"record_fact", `{}`, "record_fact", `{}`},
	}
	for _, c := range cases {
		tool, input := canonicalCall(c.name, json.RawMessage(c.input))
		if tool != c.tool || string(input) != c.want {
			t.Errorf("canonicalCall(%q) = %q %s, want %q %s", c.name, tool, input, c.tool, c.want)
		}
	}
}

func TestNeedsApproval(t *testing.T) {
	for _, n := range []string{"Bash", "shell_send", "Write", "create_mcp", "mcp__browser__click"} {
		if !needsApproval(n) {
			t.Errorf("%s must need approval on the host", n)
		}
	}
	for _, n := range []string{"Read", "record_fact", "report_finding"} {
		if needsApproval(n) {
			t.Errorf("%s must not need approval", n)
		}
	}
}
