package agent

import (
	"strings"

	"github.com/Autumn-27/norma/harness"
)

// Wrap-up prompt (wrap-up / settlement prompt): when an agent is terminated by [running out of steps (MaxTurns)] or
// [timeout (run_seconds/MaxDuration)], the SDK's settlement phase injects this prompt,
// so the agent first persists what it identified but has not yet written back, then outputs a one-sentence summary, avoiding unfinished work.
//
// Each agent's wrap-up prompt can be overridden in the admin console as needed (stored in agents.wrapup_prompt); if left empty, the
// built-in default here is used. Only the [prompt body] is editable; which tools are disabled and how many rounds of budget the wrap-up itself gets are fixed code policy.

// WrapupOverride, if set, returns the stored wrap-up prompt for an agent key and
// whether a non-empty one exists. Wired by the server to the agents table (like
// PromptOverride for system prompts). nil / empty → the built-in default is used.
var WrapupOverride func(agentKey string) (string, bool)

// WrapupMaxTurnsOverride, if set, returns the admin-configured turn budget for the
// wrap-up phase of an agent and whether a positive one exists. Wired to the agents
// table. nil / ≤0 → the built-in per-agent default (wrapupTurnDefaults) is used.
var WrapupMaxTurnsOverride func(agentKey string) (int, bool)

// Built-in default wrap-up prompts, indexed by agent key. The worker reuses the historically hard-coded settleWrapUpPrompt
// (defined in worker.go); planner/mainagent each have one; unmatched (custom agents) fall back to a generic default.
var wrapupDefaults = map[string]string{
	"worker":    settleWrapUpPrompt,
	"planner":   plannerWrapUpDefault,
	"mainagent": mainAgentWrapUpDefault,
}

// wrapupTurnDefaults: built-in default turn budget for each agent's [own] wrap-up phase (overridable by a backend value >0).
// All get 10 turns, enough steps to persist results during wrap-up. Misses fall back to genericWrapupTurns.
var wrapupTurnDefaults = map[string]int{
	"worker":    10,
	"planner":   10,
	"mainagent": 10,
}

const genericWrapupTurns = 10

const plannerWrapUpDefault = "The step budget for this planning round is about to run out. Only [this round] ends, though: the system will wake you again later as the situation changes so you can continue planning. The task itself is not ending, so you do not need to wrap up the whole plan here. Act on conclusions you have already clearly reached in this round so it is not wasted, but do not [invent intents just to wrap up] (zero intents in this round is a perfectly normal outcome). (1) If you have already decided on exploration directions that [should be dispatched right now], submit them together in one add_intent call (do not sit on decisions already made; send them immediately). (2) Mark goals already proven achieved by some finding or fact as met with prove_goal (do not miss any). (3) If you have identified a serial exploit chain that must be split into stages, record it with TodoWrite so you can continue dispatching it the next time you wake. When done, end this round immediately and do not output summary text."

const mainAgentWrapUpDefault = "The step budget is about to run out and this interaction is about to end. Do not start any new exploration or operation. In **a single sentence of plain text only**, summarize for the user in English the current progress, the key conclusion, and the recommended next step."

const genericWrapUpDefault = "The budget is about to run out and this run will end. First record any results you have completed but not yet saved, then in **a single sentence of plain text only** summarize in English what you did and what key conclusion you reached (this one sentence will be shown as the result of this run)."

// WrapupDefault returns the built-in default wrap-up prompt for an agent key —
// used by the admin UI as the "restore default" value and empty-field placeholder.
func WrapupDefault(agentKey string) string {
	if d, ok := wrapupDefaults[agentKey]; ok {
		return d
	}
	return genericWrapUpDefault
}

// WrapupTurnsDefault returns the built-in wrap-up turn budget for an agent key —
// used by the admin UI as the "0 = default N" hint.
func WrapupTurnsDefault(agentKey string) int {
	if n, ok := wrapupTurnDefaults[agentKey]; ok {
		return n
	}
	return genericWrapupTurns
}

// resolveWrapup returns the effective wrap-up prompt: the DB override (if set and
// non-empty) over the built-in default.
func resolveWrapup(agentKey string) string {
	if WrapupOverride != nil {
		if t, ok := WrapupOverride(agentKey); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return WrapupDefault(agentKey)
}

// resolveWrapupTurns returns the effective wrap-up turn budget: a positive DB
// override over the built-in per-agent default.
func resolveWrapupTurns(agentKey string) int {
	if WrapupMaxTurnsOverride != nil {
		if v, ok := WrapupMaxTurnsOverride(agentKey); ok && v > 0 {
			return v
		}
	}
	return WrapupTurnsDefault(agentKey)
}

// wrapupSettlement builds the settlement config for an agent's run. Prompt and the
// turn budget are admin-editable per agent; disabled tools are code-owned policy so
// a user can't edit away the "stop probing" guardrail. Resolved fresh each run
// (reads DB live), so edits apply on the next run without a restart.
func wrapupSettlement(agentKey string, disabledTools []string) *harness.Settlement {
	return &harness.Settlement{
		Prompt:        resolveWrapup(agentKey),
		DisabledTools: disabledTools,
		MaxTurns:      resolveWrapupTurns(agentKey),
	}
}

// ---------- Task-level timeout wrap-up prompts (see docs/task-timeout-wrapup-design.md) ----------
//
// These are [separate] from the per-run wrap-up prompts: per-run means "this run's budget is used up"; task timeout means
// "the whole task has hit its deadline and is about to end". The semantics are often opposite (especially for the planner: per-run says "don't stop, keep planning",
// task timeout says "deadline reached, stop planning and make the final judgment"). Configured for worker/planner only.

// WrapupTaskTimeoutOverride / ...TurnsOverride: DB overrides for the task-timeout wrap-up prompt and turn count
// (wired to agents.task_timeout_wrapup_prompt / _max_turns, worker/planner only).
var (
	WrapupTaskTimeoutOverride      func(agentKey string) (string, bool)
	WrapupTaskTimeoutTurnsOverride func(agentKey string) (int, bool)
)

var taskTimeoutWrapupDefaults = map[string]string{
	"worker":  workerTaskTimeoutDefault,
	"planner": plannerTaskTimeoutDefault,
}

const workerTaskTimeoutDefault = "**The whole task has reached its time limit and will end soon** (this is not the budget of this run: the entire exploration is ending). This is the last chance. (1) Save [everything] you have identified but not yet recorded. Record new assets with insert_assets, exploration conclusions and facts with record_fact, and confirmed vulnerabilities with report_finding. (2) Do not start any new command or probe. (3) **At the very end, in a single sentence of plain text only**, summarize in English the key conclusion obtained from this intent."

const plannerTaskTimeoutDefault = "**The whole task has reached its time limit and will end soon** (not just this round: the entire task is ending). Based on [all] facts and findings so far, make the final goal judgment. Mark goals proven achieved by evidence as met with prove_goal (do not miss any). **Do not create any new intent** (intents dispatched now will no longer be executed). When the judgment is done, end immediately and do not output summary text."

// TaskTimeoutWrapupDefault returns an agent's built-in default task-timeout wrap-up prompt (for backend placeholder/restoring defaults).
func TaskTimeoutWrapupDefault(agentKey string) string {
	return taskTimeoutWrapupDefaults[agentKey] // not configured (mainagent/chat) returns an empty string
}

// resolveTaskTimeoutWrapup: DB override (non-empty) > built-in default. An empty string means this agent has no task-timeout prompt
// (not worker/planner); the caller should then fall back to the per-run prompt.
func resolveTaskTimeoutWrapup(agentKey string) string {
	if WrapupTaskTimeoutOverride != nil {
		if t, ok := WrapupTaskTimeoutOverride(agentKey); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return TaskTimeoutWrapupDefault(agentKey)
}

func resolveTaskTimeoutTurns(agentKey string) int {
	if WrapupTaskTimeoutTurnsOverride != nil {
		if v, ok := WrapupTaskTimeoutTurnsOverride(agentKey); ok && v > 0 {
			return v
		}
	}
	return resolveWrapupTurns(agentKey) // by default reuse the per-run turn count
}

// wrapupSettlementForTask builds settlement for a worker/planner run that is aware
// of the task deadline. See §5 of the design doc:
//   - clamped=true  → this run was clamped by the task deadline: wrap-up caused by Timeout = task deadline reached → task-timeout prompt;
//     wrap-up caused by MaxTurns = steps ran out within the clamped window with a few minutes of task left → fall back to the per-run prompt.
//   - clamped=false → the task is still early: both reasons use the per-run prompt (degenerates to wrapupSettlement).
//
// The PromptByReason handed to harness is picked at wrap-up time by the [actual] reason, so nothing is mismatched at build time.
func wrapupSettlementForTask(agentKey string, disabledTools []string, clamped bool) *harness.Settlement {
	perRun := resolveWrapup(agentKey)
	st := &harness.Settlement{
		Prompt:        perRun, // fallback (also the value for both reasons when not clamped)
		DisabledTools: disabledTools,
		MaxTurns:      resolveWrapupTurns(agentKey),
	}
	if clamped {
		if tt := resolveTaskTimeoutWrapup(agentKey); tt != "" {
			st.PromptByReason = map[harness.TerminalReason]string{
				harness.ReasonTimeout:  tt,     // task deadline reached
				harness.ReasonMaxTurns: perRun, // steps ran out first, task still has time left
			}
			st.MaxTurns = resolveTaskTimeoutTurns(agentKey)
		}
	}
	return st
}
