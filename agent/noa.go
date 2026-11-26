package agent

import (
	"log"
	"path/filepath"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/noaadapter"
)

// noaWarn returns a diagnostics sink tagging non-fatal noa messages with the
// session, routed through the package logger (agents have no per-instance one).
func noaWarn(session string) func(string) {
	return func(msg string) { log.Printf("[noa] %s: %s", session, msg) }
}

// noa is the "model-driven context compression" mechanism introduced in norma v0.4.0, exposed as a platform
// experimental feature that users toggle in system settings. It is mutually exclusive with built-in compaction:
// noaadapter.Enable is the only entry point and attaches the context takeover (Compactor), the Compress tool
// and three resident prompts in one go; not calling Enable means it is off (built-in compaction works as
// usual). The toggle is resolved by the noaEnabledFn injected into each agent and read once per run, so
// switching only affects runs started afterwards; no need to rebuild agents.

// enableNoa attaches noa to opts when the resolver reports it enabled. archiveRoot is the persistent base
// directory for the original compressed text (the global workDir; all agents use <workDir>/noa, not spread
// across task/intent directories), and sessionID names the archive subdirectory under it (globally unique,
// so no conflicts within the same base directory).
//
// noa is experimental: a failed attach must not interrupt real tasks. On error, report via onWarn and fall
// back to built-in compression. On success, opts.Compaction is cleared so agentcore does not warn about
// "two context managers set at once".
func enableNoa(opts *agentcore.Options, enabled func() bool, archiveRoot, sessionID string, onWarn func(string)) {
	if enabled == nil || !enabled() {
		return
	}
	if opts.OnWarn == nil {
		opts.OnWarn = onWarn
	}
	if err := noaadapter.Enable(opts, noaadapter.Options{
		ArchiveBaseDir: filepath.Join(archiveRoot, "noa"),
		SessionID:      sessionID,
		OnWarn:         onWarn,
	}); err != nil {
		if onWarn != nil {
			onWarn("noa compression failed to enable, falling back to built-in compression:" + err.Error())
		}
		return
	}
	// Compactor overrides Compaction, but agentcore warns every time when both exist; clear it explicitly.
	opts.Compaction = nil
}
