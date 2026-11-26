package agent

import (
	"strings"
	"testing"
	"unicode"
)

// The DB seed leaves wrapup_prompt / task_timeout_wrapup_prompt as empty strings (the builtin agent INSERT in db/db.go does not fill these columns),
// and when empty it falls back to these constants.
// So these constants are the only source of the wrap-up text.
func TestWrapupPromptsAreEnglish(t *testing.T) {
	all := map[string]string{
		"settleWrapUpPrompt":        settleWrapUpPrompt,
		"plannerWrapUpDefault":      plannerWrapUpDefault,
		"mainAgentWrapUpDefault":    mainAgentWrapUpDefault,
		"genericWrapUpDefault":      genericWrapUpDefault,
		"workerTaskTimeoutDefault":  workerTaskTimeoutDefault,
		"plannerTaskTimeoutDefault": plannerTaskTimeoutDefault,
	}

	hasScript := func(s string, table *unicode.RangeTable) bool {
		for _, r := range s {
			if unicode.Is(table, r) {
				return true
			}
		}
		return false
	}

	for name, p := range all {
		if hasScript(p, unicode.Hangul) || hasScript(p, unicode.Han) {
			t.Errorf("%s: non-English (CJK) text remains, translation incomplete: %q", name, p)
		}
	}

	// Tool names are identifiers, so they must be preserved as-is, not translated.
	// The worker kinds (per-run, task-timeout) keep the instructions to write conclusions with record_fact,
	// vulnerabilities with report_finding, and finish with a one-sentence plain-text summary.
	mustContain := func(name, p string, subs ...string) {
		for _, s := range subs {
			if !strings.Contains(p, s) {
				t.Errorf("%s: instruction meaning %q must be preserved but is missing", name, s)
			}
		}
	}
	mustContain("settleWrapUpPrompt", settleWrapUpPrompt,
		"insert_assets", "record_fact", "report_finding", "sentence", "plain text")
	mustContain("workerTaskTimeoutDefault", workerTaskTimeoutDefault,
		"insert_assets", "record_fact", "report_finding", "sentence", "plain text")
	mustContain("genericWrapUpDefault", genericWrapUpDefault, "sentence", "plain text")
	mustContain("mainAgentWrapUpDefault", mainAgentWrapUpDefault, "sentence", "plain text")
	// The planner emits no summary sentence (it only judges and ends) and keeps the intent, goal and todo tools.
	mustContain("plannerWrapUpDefault", plannerWrapUpDefault, "add_intent", "prove_goal", "TodoWrite")
	mustContain("plannerTaskTimeoutDefault", plannerTaskTimeoutDefault, "prove_goal")
}

// per-run and task-timeout must differ in meaning (especially for the planner): per-run means "only this round
// ends" and task-timeout means "the whole task ends". The constant mapping must not get mixed up.
func TestWrapupDefaultsRouting(t *testing.T) {
	if WrapupDefault("worker") != settleWrapUpPrompt {
		t.Error("worker per-run default is not settleWrapUpPrompt")
	}
	if WrapupDefault("planner") != plannerWrapUpDefault {
		t.Error("planner per-run default is not plannerWrapUpDefault")
	}
	if WrapupDefault("mainagent") != mainAgentWrapUpDefault {
		t.Error("mainagent per-run default is not mainAgentWrapUpDefault")
	}
	// Unregistered keys (custom agents) fall back to generic.
	if WrapupDefault("unknown-agent") != genericWrapUpDefault {
		t.Error("unregistered key does not fall back to genericWrapUpDefault")
	}
	// task-timeout exists only for worker/planner; others get an empty string (the caller falls back to per-run).
	if TaskTimeoutWrapupDefault("worker") != workerTaskTimeoutDefault {
		t.Error("worker task-timeout default is not workerTaskTimeoutDefault")
	}
	if TaskTimeoutWrapupDefault("planner") != plannerTaskTimeoutDefault {
		t.Error("planner task-timeout default is not plannerTaskTimeoutDefault")
	}
	if TaskTimeoutWrapupDefault("mainagent") != "" {
		t.Error("mainagent must have no task-timeout text (empty string)")
	}
	// If the per-run and task-timeout texts are identical, the distinction in meaning is lost.
	if workerTaskTimeoutDefault == settleWrapUpPrompt {
		t.Error("worker per-run and task-timeout texts are identical")
	}
	if plannerTaskTimeoutDefault == plannerWrapUpDefault {
		t.Error("planner per-run and task-timeout texts are identical")
	}
}
