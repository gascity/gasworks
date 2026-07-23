package runwrap

import (
	"context"
	"io/fs"
	"path/filepath"
	"time"
)

// Explicit-run usage binding: teach the daemon which native agent session belongs to this run.
//
// The watcher captures a child agent's transcript into a SYNTHETIC run keyed by the native session
// id, independent of this explicit run. To put that session's real cost on THIS run's bead, the
// daemon needs a native-session -> run association. The wrapper is the one process that knows both
// GASWORKS_RUN_ID and can observe the child's new transcript file appear, so it discovers the
// child's native session id(s) and binds them. The daemon's sink then stamps run_context onto that
// session's observations (see internal/observer/daemon.Registry.BindSession).
//
// The discovery reads only file NAMES (never content) through an injected provider-specific
// extractor, so the wrapper stays provider-agnostic and judgment-free. It is best-effort and
// bounded by the child's lifetime; a failure never affects the run.

// defaultBindPoll is the session-discovery poll cadence. It is short so the binding lands before the
// session's first USAGE is captured (usage follows the first model turn, seconds into a session),
// while a scan of a narrow provider root stays cheap.
const defaultBindPoll = 150 * time.Millisecond

// preLaunchSessions is the set of transcript paths already present under the configured session
// roots before the child launches, so discovery ignores co-resident sessions and binds only the new
// file the child creates. It returns nil (binding disabled) when no roots or extractor are set.
func preLaunchSessions(cfg Config) map[string]bool {
	if cfg.NativeSessionID == nil || len(cfg.SessionRoots) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for _, root := range cfg.SessionRoots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			seen[path] = true
			return nil
		})
	}
	return seen
}

// startSessionBinding launches the best-effort discovery goroutine when binding is configured. It
// returns immediately; the goroutine runs until ctx is cancelled (the child exits).
func (r *runner) startSessionBinding(ctx context.Context, preLaunch map[string]bool) {
	if r.cfg.NativeSessionID == nil || len(r.cfg.SessionRoots) == 0 {
		return
	}
	go r.discoverAndBind(ctx, preLaunch)
}

// discoverAndBind polls the session roots for transcript files that appeared after launch, extracts
// each native session id, and binds it to the run exactly once. It runs a final scan after ctx is
// cancelled so a session file created just before the child exited is still bound.
func (r *runner) discoverAndBind(ctx context.Context, preLaunch map[string]bool) {
	poll := r.cfg.bindPoll
	if poll <= 0 {
		poll = defaultBindPoll
	}
	bound := map[string]bool{}
	scan := func() {
		for _, root := range r.cfg.SessionRoots {
			_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() || preLaunch[path] {
					return nil
				}
				native, ok := r.cfg.NativeSessionID(path)
				if !ok || native == "" || bound[native] {
					return nil
				}
				if berr := r.d.BindSession(ctx, native, r.runID); berr == nil {
					bound[native] = true
				}
				return nil
			})
		}
	}
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		scan()
		select {
		case <-ctx.Done():
			scan() // final pass: catch a file created just before the child exited
			return
		case <-ticker.C:
		}
	}
}
