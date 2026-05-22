// Package wallclock implements the 1.5C-Polish wall-clock smoke loop.
//
// The 1.5C accelerated soak proves correctness of the budget /
// cooldown FSM / refresh logic against a fake clock; it does not
// exercise long-running fd/handle hygiene because the simulated
// process only lives for a few seconds. This package fills that gap
// by running ONE client against ONE scenario for a real wall-clock
// duration (default 7 × 24 h, configurable to seconds for tests),
// periodically driving the same engine commands the per-day soak
// drives, and sampling the engine process's open-file-descriptor
// count from /proc/<pid>/fd.
//
// The exit criterion is bounded fd growth: the loop reports
// max(fd_count) - min(fd_count) and the run is considered green when
// that delta stays below `MaxFDGrowth`. The default is generous (50)
// because the helper, libsqlite, and the Go runtime can wobble by a
// few fds; what we are catching is unbounded growth — a steady
// climb of one fd per refresh, for example, would blow past 50
// within minutes at our cadence.
//
// Loop cadence per real-wall-clock minute, drives:
//   - subscription_list  (always)
//   - subscription_refresh on every known subscription
//   - revocation_refresh_all
//   - bootstrap_refresh
//   - pointer_rotation_status
//   - diag_explain
//
// and samples /proc/<pid>/fd at the end. Each tick is one row in the
// JSONL artifact.
package wallclock

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"daal/soak-driver/internal/client"
)

// Config controls one Run.
type Config struct {
	Client      *client.Client
	OutDir      string
	Duration    time.Duration // total wall-clock duration
	TickEvery   time.Duration // how often to drive + sample
	MaxFDGrowth int           // max(fd) - min(fd) above which we fail
	NowFn       func() time.Time
}

// Tick is one sample of one moment.
type Tick struct {
	UnixSec    int64  `json:"unix_sec"`
	FDCount    int    `json:"fd_count"`
	GoroutineN int    `json:"goroutines_in_driver"`
	Refreshes  int    `json:"refreshes_this_tick"`
	Errors     int    `json:"errors_this_tick"`
	NoteBuffer string `json:"note,omitempty"`
}

// Result is the artifact emitted at the end of a Run.
type Result struct {
	StartUnix  int64  `json:"start_unix"`
	EndUnix    int64  `json:"end_unix"`
	Ticks      int    `json:"ticks"`
	MinFD      int    `json:"min_fd"`
	MaxFD      int    `json:"max_fd"`
	FDGrowth   int    `json:"fd_growth"`
	Errors     int    `json:"errors"`
	Failed     bool   `json:"failed"`
	FailReason string `json:"fail_reason,omitempty"`
}

// Run executes the wall-clock smoke. The caller is responsible for
// spawning the Client (and Closing it after Run returns).
func Run(cfg Config) (*Result, error) {
	if cfg.Client == nil {
		return nil, errors.New("wallclock: nil Client")
	}
	if cfg.Duration <= 0 {
		return nil, errors.New("wallclock: Duration must be positive")
	}
	if cfg.TickEvery <= 0 {
		cfg.TickEvery = time.Minute
	}
	if cfg.MaxFDGrowth <= 0 {
		cfg.MaxFDGrowth = 50
	}
	if cfg.NowFn == nil {
		cfg.NowFn = time.Now
	}
	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		return nil, err
	}
	jsonlPath := filepath.Join(cfg.OutDir, "wallclock_ticks.jsonl")
	jf, err := os.Create(jsonlPath)
	if err != nil {
		return nil, err
	}
	defer jf.Close()

	pid, err := childPid(cfg.Client)
	if err != nil {
		return nil, fmt.Errorf("wallclock: %w", err)
	}

	res := &Result{
		StartUnix: cfg.NowFn().Unix(),
		MinFD:     -1,
	}

	deadline := cfg.NowFn().Add(cfg.Duration)
	for {
		now := cfg.NowFn()
		if !now.Before(deadline) {
			break
		}
		tick := driveOnce(cfg.Client)
		fdN, _ := countFDs(pid)
		tick.FDCount = fdN
		tick.UnixSec = now.Unix()
		tick.GoroutineN = runtime.NumGoroutine()
		_ = appendJSONL(jf, tick)

		res.Ticks++
		res.Errors += tick.Errors
		if res.MinFD < 0 || fdN < res.MinFD {
			res.MinFD = fdN
		}
		if fdN > res.MaxFD {
			res.MaxFD = fdN
		}

		// Sleep until the next tick or the deadline, whichever comes first.
		next := now.Add(cfg.TickEvery)
		if next.After(deadline) {
			next = deadline
		}
		time.Sleep(time.Until(next))
	}

	res.EndUnix = cfg.NowFn().Unix()
	res.FDGrowth = res.MaxFD - res.MinFD
	if res.FDGrowth > cfg.MaxFDGrowth {
		res.Failed = true
		res.FailReason = fmt.Sprintf(
			"fd growth %d exceeded MaxFDGrowth=%d (min=%d max=%d)",
			res.FDGrowth, cfg.MaxFDGrowth, res.MinFD, res.MaxFD,
		)
	}

	body, _ := json.MarshalIndent(res, "", "  ")
	_ = os.WriteFile(filepath.Join(cfg.OutDir, "wallclock_result.json"), body, 0o644)
	return res, nil
}

func driveOnce(c *client.Client) Tick {
	t := Tick{}
	// 1. List subscriptions; refresh any we know about.
	if list, err := c.SubscriptionList(); err == nil {
		var parsed struct {
			Subscriptions []struct {
				SubscriptionID string `json:"subscription_id"`
			} `json:"subscriptions"`
		}
		_ = json.Unmarshal(list, &parsed)
		for _, sub := range parsed.Subscriptions {
			if _, err := c.SubscriptionRefresh(sub.SubscriptionID, 5000); err != nil {
				t.Errors++
			}
			t.Refreshes++
		}
	} else {
		t.Errors++
	}
	// 2. Revocation, bootstrap, status calls — count error but tolerate.
	if _, err := c.RevocationRefreshAll(5000); err != nil {
		t.Errors++
	}
	if _, err := c.BootstrapRefresh(5000); err != nil {
		t.Errors++
	}
	if _, err := c.PointerRotationStatus(); err != nil {
		t.Errors++
	}
	if _, err := c.DiagExplain(); err != nil {
		t.Errors++
	}
	return t
}

// childPid extracts the engine subprocess PID via the client's Cmd.
// We deliberately keep this in /internal/wallclock so the client
// package's surface stays the rig-side IPC contract; here we use a
// very small reflection-free accessor that takes advantage of the
// fact that exec.Cmd.Process is exported.
func childPid(c *client.Client) (int, error) {
	pid := c.Pid()
	if pid <= 0 {
		return 0, errors.New("wallclock: client has no PID")
	}
	return pid, nil
}

// countFDs returns the number of open file descriptors in /proc/pid/fd.
// Linux-only; on non-Linux we return 0 and the caller treats the
// growth check as advisory.
func countFDs(pid int) (int, error) {
	if runtime.GOOS != "linux" {
		return 0, nil
	}
	dir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

func appendJSONL(f *os.File, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	_, err = f.Write(body)
	return err
}
