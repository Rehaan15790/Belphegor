package agent

import (
	"encoding/json"
	"fmt"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/Rehaan15790/belphegor/db"
)

const findingIDGuidance = "\n\n**Vulnerability ID convention**: finding_id is the standalone vulnerability record ID; finding_node_id is the exploration node ID. The id returned by list_findings / list_task_findings / node_detail / get_task_node_detail stays the exploration node ID; read the standalone ID from finding_id in the same result. get_finding_traffic / bind_finding_traffic use the standalone finding_id. The finding_id parameter of the old update_finding_report still takes finding_node_id. Do not use the number on the first line of report_finding for evidence tools, and do not guess other numbers after an ID error."

// The server supplies the persisted setting. A missing setting/host is off.
// Consulted at assembly and again on writes so an already-running session
// cannot keep binding after the user switches the feature off.
var FindingTrafficBindingEnabled func() bool

func findingTrafficBindingEnabled() bool {
	return FindingTrafficBindingEnabled != nil && FindingTrafficBindingEnabled()
}

// Applied after ToolResolve: user descriptions and prompts remain intact, while
// all actual reporters (including Planner and custom chat agents) see the same
// API contract. Disabled/unbound tools are never reintroduced here.
func findingWorkflowTools(agentKey string, tools []actool.CoreTool) ([]actool.CoreTool, string) {
	if !findingTrafficBindingEnabled() {
		out := make([]actool.CoreTool, 0, len(tools))
		for _, tool := range tools {
			if tool.Name() == "bind_finding_traffic" {
				continue
			}
			if agentKey == "reporter" && (tool.Name() == "traffic_search" || tool.Name() == "traffic_get" || tool.Name() == "traffic_blob") {
				continue
			}
			switch tool.Name() {
			case "report_finding", "add_hint", "add_task_hint":
				// Work on a copy: toggling back on must restore the original schema.
				raw, _ := json.Marshal(tool.InputSchema())
				var schema map[string]any
				if json.Unmarshal(raw, &schema) == nil {
					stripTrafficParameters(schema)
					tool = DecorateTool(tool, tool.Description(), schema)
				}
			}
			out = append(out, tool)
		}
		return out, ""
	}
	out := append([]actool.CoreTool(nil), tools...)
	has := map[string]bool{}
	for i, tool := range out {
		has[tool.Name()] = true
		note := ""
		switch tool.Name() {
		case "report_finding":
			note = "\nBy default the report agent verifies and binds traffic before writing the report. The reporter keeps the verification command, key output, any real traffic IDs already held and their purpose in evidence, so the report agent can check them against the execution record; no extra packet lookup is needed for binding. Explicit immediate binding is still supported: traffic_refs or evidence_hint_id can submit verified references, where the latter reads the structured references of the hint designated for this task; if either is invalid, the whole report submission fails. TCP / no-packet cases do not need these optional parameters. The returned finding_id and finding_node_id denote the standalone record and the exploration node respectively."
		case "add_hint", "add_task_hint":
			note = "\nWhen handing off a confirmed vulnerability, keep the ID, purpose, note and order of the verified traffic in the traffic_refs of the corresponding hint (put a single one at top level, a batch in the corresponding hints elements), and state in text the specific vulnerability it proves. The caller must not hand off only text and drop existing traffic references. Unverified candidates must not be passed on as evidence."
		case "get_finding_traffic", "bind_finding_traffic", "list_findings", "list_task_findings", "node_detail", "get_task_node_detail", "update_finding_report":
			note = findingIDGuidance
		}
		if note != "" {
			out[i] = DecorateTool(tool, tool.Description()+note, tool.InputSchema())
		}
	}
	guidance := ""
	if has["report_finding"] || has["add_task_hint"] || has["add_hint"] {
		guidance = "\n\n**Traffic evidence handoff (optional)**: automatic binding is done by default by the report agent after the vulnerability is stored and before the report is written. The reporter should keep the verification command, key output, any real traffic IDs already held and their purpose in evidence, and include intent_id in the task so the report agent can trace it; do not look up extra packets just for binding. When Auto / Planner reports on behalf of others, do not drop references the worker already holds. add_hint / add_task_hint can hand off with traffic_refs; explicit immediate binding via report_finding's traffic_refs / evidence_hint_id is still supported. For TCP or no-packet cases, register normally; do not guess IDs, and do not re-probe just to fill in packets."
		if has["add_task_hint"] && !has["add_hint"] {
			guidance += "\nWhen a platform conversation has no task context, do not call report_finding directly; hand off to the existing matching task through add_task_hint so the task agent registers it, and check the result with list_task_findings."
		}
		if has["prove_goal"] || has["goal_met"] {
			guidance += "\nBefore judging the goal complete, first finish reporting/handing off the evidence already held. Do not end the task or cancel Workers just because the text-only vulnerability is registered while the evidence handoff is not yet done; with no packets, do not wait or force a capture."
		}
	}
	if has["update_finding_report"] && has["bind_finding_traffic"] && has["get_finding_traffic"] {
		guidance += "\n\n**Auto-link traffic before report (enabled)**: you are responsible for verifying and binding traffic for the vulnerability triggered this time, then writing the report. First get the explicit finding_id and finding_node_id from the report_finding return JSON or from get_task_node_detail / list_task_findings. Read the vulnerability details, the execution record of the corresponding intent and the existing evidence list, and prefer the real IDs handed off by the reporter. If this verification is HTTP and the traffic tools are available, use traffic_search to filter candidates, then use traffic_get to check each request/response one by one to confirm it really supports the vulnerability; domain and time are only for filtering and do not prove ownership. Link the confirmed evidence in reproduction order with bind_finding_traffic(finding_id, traffic_refs), choose baseline / proof / verification / supporting and state the purpose. Operate only on this vulnerability; do not create duplicate vulnerabilities or re-probe the target. After binding succeeds, call get_finding_traffic again to get the latest version, read the needed body, then pass the version you actually read as evidence_version to update_finding_report (whose finding_id parameter still uses finding_node_id). Existing bindings need not be appended again. For TCP, not captured, tools unavailable, or no exact match, skip automatic binding, write the report normally from the text/command evidence and state the reason, and do not guess just to complete the traffic. If binding fails, do not claim success; keep the existing evidence and state in the report why nothing was bound."
	}
	if guidance != "" || has["get_finding_traffic"] || has["update_finding_report"] {
		guidance += findingIDGuidance
	}
	return out, guidance
}

func stripTrafficParameters(schema map[string]any) {
	props, _ := schema["properties"].(map[string]any)
	delete(props, "traffic_refs")
	delete(props, "evidence_hint_id")
	if required, ok := schema["required"].([]any); ok {
		kept := required[:0]
		for _, key := range required {
			if key != "traffic_refs" && key != "evidence_hint_id" {
				kept = append(kept, key)
			}
		}
		schema["required"] = kept
	}
	if hints, ok := props["hints"].(map[string]any); ok {
		if items, ok := hints["items"].(map[string]any); ok {
			stripTrafficParameters(items)
		}
	}
}

// HintTrafficSchema is shared by the task-local and cross-task hint tools.
func HintTrafficSchema() map[string]any {
	return map[string]any{"type": "array", "description": "Optional: references to verified traffic that corresponds to the specific vulnerability in this hint, order preserved; after handoff, report_finding can pass evidence_hint_id to carry these references.", "items": obj(map[string]any{"traffic_id": str("Real traffic ID"), "role": str("baseline / proof / verification / supporting"), "note": str("What conclusion this traffic supports")}, "traffic_id")}
}

func (t *ToolSet) findingRefsFromHint(hintID int64, explicit []db.TrafficRef) ([]db.TrafficRef, error) {
	if hintID <= 0 {
		return db.NormalizeTrafficRefs(explicit)
	}
	n, err := t.ts.GetNode(hintID) // local store only: inherited hints cannot supply evidence
	if err != nil {
		return nil, err
	}
	if n == nil || n.Kind != db.KindHint {
		return nil, fmt.Errorf("evidence_hint_id=%d must be a hint node of this task (an inherited hint cannot be used for binding directly)", hintID)
	}
	var payload struct {
		Refs []db.TrafficRef `json:"traffic_refs"`
	}
	if err := json.Unmarshal(n.Payload, &payload); err != nil {
		return nil, err
	}
	return db.NormalizeTrafficRefs(append(append([]db.TrafficRef{}, explicit...), payload.Refs...))
}
