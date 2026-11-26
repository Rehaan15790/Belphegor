package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/Rehaan15790/belphegor/db"
)

const (
	errGoalTaskDeletingAdd    = "The task is being deleted, so no goal can be added"
	errGoalTaskDeletingEdit   = "Cannot modify the goal while the task is being deleted"
	errGoalTaskDeletingDelete = "The goal cannot be deleted because the task is being deleted"
	errGoalTextEmpty          = "The goal content cannot be empty"
	errGoalNotFound           = "Goal not found"
	errGoalReadAfterAdd       = "Failed to read back the goal after saving it"
	errGoalReadAfterEdit      = "Failed to read the goal after updating it"
)

// Manual CRUD endpoints for the overview "goal management". They write the same goal nodes as the agent-side set_goals tool,
// but the entry point is a human adding, deleting and editing directly in the UI; after add/edit they reuse the "revive task" logic
// (admitTask resume: terminal -> running, clear pause, queue if needed); delete does not revive (product decision). Every mutating handler goes through
// beginTaskOperation/decInflight to avoid racing with task deletion (same as intent CRUD).

// listGoals returns all goals of this task (text/vulnclass/state split out) for the goal management card to render.
func (s *Server) listGoals(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	goals, err := t.Store.ListByKind(db.KindGoal, 10000)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"goals": goalDTOs(goals)})
}

// addGoal adds a goal manually: persist it (attached under the task root spawns) -> record a "goal added" trigger that wakes the
// planner -> revive the task so the planner re-judges whether it is achieved based on the new goal.
func (s *Server) addGoal(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, errGoalTaskDeletingAdd)
		return
	}
	defer s.engine.decInflight(t.ID)

	var body struct {
		Text      string `json:"text"`
		VulnClass string `json:"vulnclass"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	text := strings.TrimSpace(body.Text)
	if text == "" {
		writeErr(w, 400, errGoalTextEmpty)
		return
	}
	payload := map[string]any{"text": text}
	if vc := strings.TrimSpace(body.VulnClass); vc != "" {
		payload["vulnclass"] = vc
	}
	id, err := t.Store.AddGoal(payload, "human")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if of, _ := t.Store.OriginFactID(); of > 0 && id > 0 {
		_ = t.Store.Link(of, db.RelSpawns, id) // goal descends from the task root (origin fact)
	}
	t.NotifyGoal([]string{text}) // record "human added a goal: ...", trigger and wake the planner
	s.reviveTask(t)              // pull a completed/paused task back to running so it keeps going
	node, _ := t.Store.GetNode(id)
	if node == nil {
		writeErr(w, 500, errGoalReadAfterAdd)
		return
	}
	writeJSON(w, 200, goalDTO(node))
}

// editGoal edits a goal's text (and vulnclass) manually: update the DB -> record "user changed the goal from old to new",
// trigger and wake the planner -> revive the task so the planner adjusts direction based on the new goal.
func (s *Server) editGoal(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, errGoalTaskDeletingEdit)
		return
	}
	defer s.engine.decInflight(t.ID)

	gid, err := strconv.ParseInt(r.PathValue("gid"), 10, 64)
	if err != nil || gid <= 0 {
		writeErr(w, 400, "bad goal id")
		return
	}
	var body struct {
		Text      string `json:"text"`
		VulnClass string `json:"vulnclass"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	text := strings.TrimSpace(body.Text)
	if text == "" {
		writeErr(w, 400, errGoalTextEmpty)
		return
	}
	node, err := t.Store.GetNode(gid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if node == nil || node.Kind != db.KindGoal {
		writeErr(w, 404, errGoalNotFound)
		return
	}
	oldText := goalDTO(node).Text
	if err := t.Store.UpdateGoalPayload(gid, text, strings.TrimSpace(body.VulnClass)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	t.NotifyGoalEdited(oldText, text) // record "human changed the goal from old to new", trigger and wake the planner
	s.reviveTask(t)                   // same as add: revive the task so it re-judges based on the new goal
	updated, _ := t.Store.GetNode(gid)
	if updated == nil {
		writeErr(w, 500, errGoalReadAfterEdit)
		return
	}
	writeJSON(w, 200, goalDTO(updated))
}

// deleteGoal deletes a goal manually (hard delete, cascading to edges/anchors): delete from the DB -> record "user deleted goal X",
// trigger and wake the planner to re-judge the remaining goals. By product decision, delete does NOT revive the task.
func (s *Server) deleteGoal(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, errGoalTaskDeletingDelete)
		return
	}
	defer s.engine.decInflight(t.ID)

	gid, err := strconv.ParseInt(r.PathValue("gid"), 10, 64)
	if err != nil || gid <= 0 {
		writeErr(w, 400, "bad goal id")
		return
	}
	node, err := t.Store.GetNode(gid)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if node == nil || node.Kind != db.KindGoal {
		writeErr(w, 404, errGoalNotFound)
		return
	}
	text := goalDTO(node).Text
	if err := t.Store.DeleteGoal(gid); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	t.NotifyGoalDeleted(text) // record "human deleted the goal: ...", trigger and wake the planner (does not revive the task)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
