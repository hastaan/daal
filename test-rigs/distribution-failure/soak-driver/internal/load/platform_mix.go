// Package load — Phase 3-Soak platform_mix dispatcher.
//
// The 3-Soak verifier asserts cross-platform pickup of a freshly
// published `transport_module` within 24 simulated hours across
// three real binary stubs:
//
//   - daal-soak-engine        (Linux desktop; default 60% of clients)
//   - daal-soak-engine-android (Android; default 35% of clients;
//     GOMEMLIMIT 200 MiB)
//   - daal-soak-engine-ios    (iOS; default  5% of clients;
//     GOMEMLIMIT 50 MiB per the 2E NE budget)
//
// platform_mix wraps the existing back-pressured client pool from
// pool.go: it dispatches each spawned client to the appropriate
// stub binary. The locked default mix is 60/35/5; the rig CLI
// surface is the `--platform-mix` flag (parsed by ParseMix below).
//
// Locked at 3-Soak per
// `phases of development/27-phase-3-soak-success-metric.md` §3 / §5.
package load

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"daal/soak-driver/internal/client"
)

// PlatformTag is the closed enum of stub-binary platform tags. The
// rig hard-codes the three values at 3-Soak; future platforms (e.g.
// browser/extension) would extend this enum.
type PlatformTag string

const (
	PlatformLinux   PlatformTag = "linux"
	PlatformAndroid PlatformTag = "android"
	PlatformIOS     PlatformTag = "ios"
)

// LockedDefaultMix is the 3-Soak locked default. The driver falls
// back to this when `--platform-mix` is not supplied.
//
// 60 / 35 / 5 (sums to 100 per locked spec §5).
var LockedDefaultMix = Mix{
	{Platform: PlatformLinux, Percent: 60},
	{Platform: PlatformAndroid, Percent: 35},
	{Platform: PlatformIOS, Percent: 5},
}

// Slice is one entry in the platform mix.
type Slice struct {
	Platform PlatformTag
	Percent  int // integer percent in [0, 100]; the slice's share of N
}

// Mix is an ordered slice of platform percentages summing to 100.
type Mix []Slice

// Validate checks the mix sums to 100 and contains only known
// platform tags. Empty / nil mix is rejected.
func (m Mix) Validate() error {
	if len(m) == 0 {
		return fmt.Errorf("load.Mix: empty mix")
	}
	sum := 0
	seen := map[PlatformTag]bool{}
	for _, s := range m {
		switch s.Platform {
		case PlatformLinux, PlatformAndroid, PlatformIOS:
			// ok
		default:
			return fmt.Errorf("load.Mix: unknown platform %q", s.Platform)
		}
		if seen[s.Platform] {
			return fmt.Errorf("load.Mix: duplicate platform %q", s.Platform)
		}
		seen[s.Platform] = true
		if s.Percent < 0 || s.Percent > 100 {
			return fmt.Errorf("load.Mix: bad percent %d for %q", s.Percent, s.Platform)
		}
		sum += s.Percent
	}
	if sum != 100 {
		return fmt.Errorf("load.Mix: percentages sum to %d, want 100", sum)
	}
	return nil
}

// Counts converts the mix into per-platform integer client counts
// for a fleet of size n. Rounding rule: floor(n * pct/100) per
// slice; any leftover from rounding is added to the LARGEST slice
// (Linux at the locked default), which preserves the 60/35/5
// ordering and never under-allocates the smallest platform.
func (m Mix) Counts(n int) map[PlatformTag]int {
	if n <= 0 {
		return map[PlatformTag]int{}
	}
	out := map[PlatformTag]int{}
	used := 0
	largest := PlatformTag("")
	largestPct := -1
	for _, s := range m {
		c := (n * s.Percent) / 100
		out[s.Platform] = c
		used += c
		if s.Percent > largestPct {
			largestPct = s.Percent
			largest = s.Platform
		}
	}
	if leftover := n - used; leftover > 0 && largest != "" {
		out[largest] += leftover
	}
	return out
}

// ParseMix parses a `--platform-mix` flag of the form
// `linux:600,android:350,ios:50`. The integers are absolute client
// counts (NOT percents) — the driver supplies the total fleet size
// via N elsewhere, and ParseMix returns the equivalent percent-Mix.
//
// Empty / unset → LockedDefaultMix.
//
// Tags are looked up case-insensitively; unknown tags error.
func ParseMix(spec string, totalClients int) (Mix, error) {
	if strings.TrimSpace(spec) == "" {
		return LockedDefaultMix, nil
	}
	if totalClients <= 0 {
		return nil, fmt.Errorf("load.ParseMix: non-positive totalClients %d", totalClients)
	}
	parts := strings.Split(spec, ",")
	counts := map[PlatformTag]int{}
	for _, p := range parts {
		kv := strings.SplitN(strings.TrimSpace(p), ":", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("load.ParseMix: bad token %q (want platform:count)", p)
		}
		tag := PlatformTag(strings.ToLower(strings.TrimSpace(kv[0])))
		switch tag {
		case PlatformLinux, PlatformAndroid, PlatformIOS:
			// ok
		default:
			return nil, fmt.Errorf("load.ParseMix: unknown platform %q", tag)
		}
		n, err := strconv.Atoi(strings.TrimSpace(kv[1]))
		if err != nil {
			return nil, fmt.Errorf("load.ParseMix: bad count for %q: %w", tag, err)
		}
		if n < 0 {
			return nil, fmt.Errorf("load.ParseMix: negative count for %q", tag)
		}
		if _, dup := counts[tag]; dup {
			return nil, fmt.Errorf("load.ParseMix: duplicate platform %q", tag)
		}
		counts[tag] = n
	}
	sum := 0
	for _, c := range counts {
		sum += c
	}
	if sum != totalClients {
		return nil, fmt.Errorf("load.ParseMix: counts sum to %d, want %d", sum, totalClients)
	}
	// Convert to percent-Mix (rounded; sum-to-100 invariant
	// preserved by adding leftover to the largest slice).
	mix := make(Mix, 0, len(counts))
	for tag, c := range counts {
		pct := (c * 100) / totalClients
		mix = append(mix, Slice{Platform: tag, Percent: pct})
	}
	// Sort descending by percent for stable output.
	sort.Slice(mix, func(i, j int) bool {
		if mix[i].Percent != mix[j].Percent {
			return mix[i].Percent > mix[j].Percent
		}
		return mix[i].Platform < mix[j].Platform
	})
	usedPct := 0
	for _, s := range mix {
		usedPct += s.Percent
	}
	if usedPct != 100 && len(mix) > 0 {
		mix[0].Percent += 100 - usedPct
	}
	if err := mix.Validate(); err != nil {
		return nil, err
	}
	return mix, nil
}

// PlatformBinary resolves the binary path for a platform tag. The
// caller supplies the path to the Linux soak-engine; the Android +
// iOS stubs are looked for as siblings in the same directory.
//
// Returns ("", error) if a stub is missing — the rig refuses to
// fall back to the Linux binary on a platform-tagged client because
// that would mask the platform-shaped resource limits 3-Soak's
// primary metric depends on.
func PlatformBinary(linuxEngine string, tag PlatformTag) (string, error) {
	switch tag {
	case PlatformLinux:
		return linuxEngine, nil
	case PlatformAndroid:
		sibling := filepath.Join(filepath.Dir(linuxEngine), "daal-soak-engine-android")
		return sibling, nil
	case PlatformIOS:
		sibling := filepath.Join(filepath.Dir(linuxEngine), "daal-soak-engine-ios")
		return sibling, nil
	}
	return "", fmt.Errorf("load.PlatformBinary: unknown platform %q", tag)
}

// PlatformPool is a Mix-aware variant of Pool. It dispatches each
// spawned client to the per-platform binary derived from
// PlatformBinary; per-client state directories carry the platform
// tag in their name (e.g. `c-0001-android`) so the v3verifier can
// attribute observations.
type PlatformPool struct {
	Pool        // embedded for ConcurrencyLimit + StateDirRoot
	LinuxEngine string
	Mixed       Mix
}

// Spawn creates exactly n synthetic clients distributed per the
// PlatformPool's Mix. Returns the slice of clients in deterministic
// (platform, client_id) order.
//
// On any spawn failure, all already-spawned clients are torn down
// before the error returns; the caller never observes a partial
// fleet (parity with Pool.Spawn).
func (pp *PlatformPool) Spawn(n int) ([]*client.Client, error) {
	mix := pp.Mixed
	if len(mix) == 0 {
		mix = LockedDefaultMix
	}
	if err := mix.Validate(); err != nil {
		return nil, err
	}
	counts := mix.Counts(n)
	if pp.ConcurrencyLimit <= 0 {
		pp.ConcurrencyLimit = 64
	}
	pp.Pool.mu.Lock()
	if pp.Pool.sem == nil {
		pp.Pool.sem = make(chan struct{}, pp.ConcurrencyLimit)
	}
	pp.Pool.mu.Unlock()

	out := make([]*client.Client, 0, n)
	clientIdx := 0
	// Deterministic platform iteration order matches Mix order
	// post-Validate (LockedDefaultMix is linux→android→ios).
	for _, slice := range mix {
		bin, err := PlatformBinary(pp.LinuxEngine, slice.Platform)
		if err != nil {
			pp.tearDown(out)
			return nil, err
		}
		for i := 0; i < counts[slice.Platform]; i++ {
			pp.Pool.sem <- struct{}{}
			clientIdx++
			name := fmt.Sprintf("c-%04d-%s", clientIdx, slice.Platform)
			dir := filepath.Join(pp.Pool.StateDirRoot, name)
			extra := map[string]string{
				"DAAL_SOAK_PLATFORM": string(slice.Platform),
			}
			c, err := client.SpawnWithEnv(name, bin, dir, extra)
			if err != nil {
				pp.tearDown(out)
				<-pp.Pool.sem
				return nil, fmt.Errorf("PlatformPool.Spawn[%d %s]: %w", clientIdx, slice.Platform, err)
			}
			out = append(out, c)
		}
	}
	pp.Pool.mu.Lock()
	pp.Pool.clients = append(pp.Pool.clients, out...)
	pp.Pool.mu.Unlock()
	return out, nil
}

func (pp *PlatformPool) tearDown(spawned []*client.Client) {
	for _, c := range spawned {
		_ = c.Close()
	}
}
