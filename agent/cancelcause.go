package agent

import (
	"context"
	"errors"
	"fmt"
)

// AbortCause names why an agent run's context was cancelled. Every cancellation
// site should attach one so the activity trace can report the real initiator.
type AbortCause struct {
	Code  string
	Short string
	Text  string
}

func (c *AbortCause) Error() string { return c.Text }

func cause(code, short, text string) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: text}
}

// Causef builds a cause that includes runtime-specific detail.
func Causef(code, short, format string, args ...any) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: fmt.Sprintf(format, args...)}
}

var (
	// Task-level execution context.
	AbortPausedByUser = cause("paused_by_user", "User paused the task",
		"The user paused the task through the task control endpoint (POST /api/tasks/{id}/control, action=pause). This Planner/Worker run was cancelled on purpose; running intents return to frontier(open) and are claimed again and run from scratch when the task resumes")
	AbortPausedByOrchestrator = cause("paused_by_orchestrator", "Orchestrator agent paused the task",
		"The orchestrator agent called the pause_task tool to pause this task. This Planner/Worker run was cancelled on purpose; running intents return to frontier(open) and run again after resume")
	AbortTaskDeleted = cause("task_deleted", "Task was deleted",
		"The task is being deleted (DELETE /api/tasks/{id}). The delete barrier cancelled the task's running Planner, Workers and main agent; the results of this run will no longer be used")
	AbortPausedOnReload = cause("paused_on_reload", "Backend restored the task's paused state",
		"At backend startup the task pause was restored from the state persisted in the database. This run was cancelled; normally no agent is running during the restore phase")
	AbortGoalMet = cause("goal_met", "Planner judged the task goal met",
		"The planner judged the task goal met and set the task to done, then cancelled the Workers still running; these intents are marked stopped, not failed")
	AbortSettleDrainTimeout = cause("settle_drain_timeout", "Task timeout wrap-up wait time ran out",
		"After the task reached its timeout, it waited for running Workers to wrap up gracefully, but the 90-second drain grace was still not enough, so a hard cancel was performed; intents are marked exhausted, and facts and assets already written during wrap-up are kept")

	// Per-work context.
	AbortKilledByPlanner = cause("killed_by_planner", "Planner terminated this intent",
		"The planner called kill_work to terminate this intent on purpose, usually meaning the direction went off track or is no longer worth continuing; the intent is marked stopped and will not be claimed again automatically")
	AbortWorkPausedByUser = cause("work_paused_by_user", "User paused this Worker intent",
		"The user paused a running Worker. This call was cancelled and the intent became paused; registered intents, facts, vulnerabilities and activity records are all kept, and it re-runs from scratch after resume")
	AbortWorkCancelledByUser = cause("work_cancelled_by_user", "User deleted this Worker intent",
		"The user deleted a running Worker. This call was cancelled; after the Worker leaves the write zone, the server handles the intent according to the delete mode the user chose: a soft delete only marks it deleted and keeps all outputs, while a hard delete cascades to remove the intent and the downstream nodes supported only by it")
	AbortWorkFinished = cause("work_finished", "Worker finished normally",
		"The Worker finished normally, and the engine released its context resources in detachWork. This is not a run interruption; if it appears in an interruption message, the cancel and the finish event raced")
	AbortPausedRaceGuard = cause("paused_race_guard", "New runs refused while task is paused",
		"While the task is paused, the engine refuses to issue a new execution context, to prevent a race between claim and pause from letting a Worker keep starting; claimed intents return to frontier")

	// Main Agent and standalone conversation contexts.
	AbortChatStoppedByUser = cause("chat_stopped_by_user", "User stopped this conversation turn",
		"The user clicked stop, aborting this turn of the main agent or session agent run. Activity records already produced are kept, and the next message can be sent")
	AbortChatPausedWithTask = cause("chat_paused_with_task", "Task pause aborted the conversation",
		"When the user paused the task, the running main agent conversation was cancelled as well. Activity records already produced are kept; this turn's message is not replayed automatically after the task resumes")
	AbortChatTurnFinished = cause("chat_turn_finished", "Conversation turn finished normally",
		"This conversation turn finished normally, and the server is releasing that turn's context resources. This is not a run interruption; if it appears in an interruption message, the cancel and the finish event raced")

	// Process-level and per-run hard backstop.
	AbortShutdown = cause("shutdown", "Backend process is shutting down",
		"The backend process received SIGINT or SIGTERM and is restarting, updating or shutting down. All running agents are cancelled; after restart, leftover running intents are reset to open and run again")
	AbortRunHardTimeout = cause("run_hard_timeout", "Single-run hard timeout fired",
		"A single run exceeded the soft wall-clock budget plus the extra grace, meaning a model request or some tool did not return for a long time, so the normal turn-boundary wrap-up could not run. Check the last tool call that had not returned before the interruption")
)

// AbortReason resolves the named cause attached to a cancelled run context.
func AbortReason(ctx context.Context) (code, short, text string, ok bool) {
	c := context.Cause(ctx)
	if c == nil {
		return "", "", "", false
	}
	var ac *AbortCause
	if errors.As(c, &ac) {
		return ac.Code, ac.Short, ac.Text, true
	}
	switch {
	case errors.Is(c, context.DeadlineExceeded):
		return "deadline_exceeded", "Upstream context reached its deadline",
			"Upstream context reached its deadline, but the setter did not attach a named cause through WithTimeoutCause: " + c.Error(), true
	case errors.Is(c, context.Canceled):
		return "canceled_no_cause", "Canceller attached no named cause",
			"The upstream context was cancelled, but the canceller did not attach a named cause through context.WithCancelCause; register a cause in agent/cancelcause.go and wire it into that cancel point", true
	default:
		return "other", firstLine(c.Error(), 80), c.Error(), true
	}
}
