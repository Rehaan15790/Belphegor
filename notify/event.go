package notify

// Snapshot is the contract of the notification_events.snapshot JSONB column. The writer is the db layer's
// finding persistence transaction; the readers are the server layer's delivery engine and filter matching. It is defined in this package because it is
// a payload of the "notification domain": db only serializes it and does not understand the field meanings.
//
// Why the finding fields are stored redundantly instead of looked up at render time: findings are later renamed, re-leveled and
// re-statused, while a notification should reflect the conclusion **at the time of the event**; a lookup would give a
// dangerously misleading "later changed to low". It also means fan-out and rendering need no JOIN across the findings/tasks/assets tables.
type Snapshot struct {
	// Event type: finding_created / finding_status_changed
	Kind      string  `json:"kind"`
	FindingID int64   `json:"finding_id"`
	TaskID    int64   `json:"task_id"`
	VulnClass string  `json:"vulnclass"`
	Name      string  `json:"name"`
	Severity  string  `json:"severity"`
	Summary   string  `json:"summary"`
	AssetIDs  []int64 `json:"asset_ids"`
	// Non-empty only when kind=finding_status_changed.
	FromStatus string `json:"from_status,omitempty"`
	ToStatus   string `json:"to_status,omitempty"`
}

// Item is one finding to be pushed, for channels to render.
type Item struct {
	FindingID int64
	Name      string
	VulnClass string
	Severity  string
	Summary   string
	// Assets are the resolved asset display names (such as domain/IP). Filled in by the server layer;
	// this package does not touch the database and cannot get the names.
	Assets []string
	// DetailURL is the backlink to the finding detail; empty means public_base_url is not configured, and it is omitted when rendering.
	DetailURL string
	// Used only by status change events; when both are non-empty it renders as "Pending → Fixed".
	FromStatus string
	ToStatus   string
}

// IsStatusChange reports whether this item is a status change event.
func (i Item) IsStatusChange() bool { return i.FromStatus != "" || i.ToStatus != "" }

// Title returns the display title of the item: the manually set name first, falling back to the vulnerability type vulnclass,
// and a placeholder when both are empty; it never outputs an empty title.
func (i Item) Title() string {
	if i.Name != "" {
		return i.Name
	}
	if i.VulnClass != "" {
		return i.VulnClass
	}
	return "(unnamed vulnerability)"
}

// Message is the complete content of one channel send.
type Message struct {
	// Length is 1 for a single push; for a digest push it is a whole batch.
	// An empty slice is invalid; the caller must guarantee at least one item.
	Items []Item
	// When Batch=true it is rendered as a digest message (different title, with the time window and item count).
	Batch bool
	// WindowMinutes is the digest period (minutes), used only when Batch=true for the text "last N minutes".
	// It is deliberately passed in explicitly from config instead of computing time.Since at render time: rendering stays deterministic and so is easy to test.
	WindowMinutes int
	// HomeURL is the platform dashboard address (global public_base_url); when empty, no dashboard link is included.
	HomeURL string
}
