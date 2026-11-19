package netmem

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// slowKV is a thread-safe SecretsKV whose reads take a moment: the gap
// between "read the record" and "write it back" that two threads of the
// engine (the host's network callback, a connect) fall into.
type slowKV struct {
	mu    sync.Mutex
	m     map[string][]byte
	delay time.Duration
}

func (f *slowKV) PutSecret(key string, b []byte) error {
	f.mu.Lock()
	f.m[key] = append([]byte(nil), b...)
	f.mu.Unlock()
	return nil
}

func (f *slowKV) GetSecret(key string) ([]byte, error) {
	f.mu.Lock()
	b, ok := f.m[key]
	b = append([]byte(nil), b...)
	f.mu.Unlock()
	time.Sleep(f.delay)
	if !ok {
		return nil, errors.New("not found")
	}
	return b, nil
}

func (f *slowKV) DeleteSecret(key string) error {
	f.mu.Lock()
	delete(f.m, key)
	f.mu.Unlock()
	return nil
}

func (f *slowKV) ListSecretKeys(prefix string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{}
	for k := range f.m {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Route outcomes recorded from several threads at once are all kept.
func TestStore_ConcurrentRouteOutcomesAreAllKept(t *testing.T) {
	st := New(&slowKV{m: map[string][]byte{}, delay: time.Millisecond})
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	const n = 12
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := st.RecordRouteOutcome("net", "r1", RouteOutcome{Carried: true, HasSetup: true, SetupMs: 300}, now); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	m := st.LookupRouteMemory("net")["r1"].Measured()
	if m.Carried != n || m.Samples != n {
		t.Fatalf("%d outcomes recorded at once, %d carried / %d samples kept", n, m.Carried, m.Samples)
	}
}

// The rewrite of a network's record on the way out of it (the host's
// thread) does not undo a route outcome a connect records meanwhile.
func TestStore_PutKeepingRouteMemoryDoesNotDropAnOutcomeRecordedBesideIt(t *testing.T) {
	kv := &slowKV{m: map[string][]byte{}, delay: 30 * time.Millisecond}
	st := New(kv)
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	if err := st.RecordRouteOutcome("net", "r1", RouteOutcome{Carried: true}, now); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = st.PutKeepingRouteMemory("net", Snapshot{Mode: "normal"}, now)
	}()
	go func() {
		defer wg.Done()
		time.Sleep(10 * time.Millisecond) // inside the other's read
		_ = st.RecordRouteOutcome("net", "r2", RouteOutcome{Category: "tcp_reset"}, now)
	}()
	wg.Wait()
	snap, err := st.Get("net")
	if err != nil {
		t.Fatal(err)
	}
	if snap.Mode != "normal" {
		t.Fatalf("mode %q", snap.Mode)
	}
	if _, ok := snap.RouteMemory["r1"]; !ok {
		t.Fatal("the route memory the record held was dropped by the rewrite")
	}
	if m, ok := snap.RouteMemory["r2"]; !ok || m.Measured().Failed != 1 {
		t.Fatalf("the outcome recorded beside the rewrite was lost: %+v", snap.RouteMemory)
	}
}

// Adopting an old record and recording into it at the same moment: the
// outcome ends up in the record that survives, not in the deleted one.
func TestStore_AdoptAndRecordDoNotLoseTheOutcome(t *testing.T) {
	kv := &slowKV{m: map[string][]byte{}, delay: 20 * time.Millisecond}
	st := New(kv)
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	_ = st.RecordRouteOutcome("old", "r1", RouteOutcome{Carried: true}, now)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if moved, err := st.AdoptRouteMemory("old", "new", now); err != nil || !moved {
			t.Errorf("adopt: moved=%t err=%v", moved, err)
		}
	}()
	go func() {
		defer wg.Done()
		time.Sleep(5 * time.Millisecond)
		_ = st.RecordRouteOutcome("new", "r2", RouteOutcome{Carried: true}, now)
	}()
	wg.Wait()
	mem := st.LookupRouteMemory("new")
	if _, ok := mem["r1"]; !ok {
		t.Fatalf("the adopted memory is gone: %+v", mem)
	}
	if _, ok := mem["r2"]; !ok {
		t.Fatalf("the outcome recorded during the adoption is gone: %+v", mem)
	}
}

func TestStore_PutIfAbsent(t *testing.T) {
	st := New(&slowKV{m: map[string][]byte{}})
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	_ = st.RecordRouteOutcome("net", "r1", RouteOutcome{Carried: true}, now)
	if wrote, _ := st.PutIfAbsent("net", Snapshot{Mode: "normal"}, now); wrote {
		t.Fatal("a stub replaced an existing record")
	}
	if _, ok := st.LookupRouteMemory("net")["r1"]; !ok {
		t.Fatal("record lost")
	}
	if wrote, _ := st.PutIfAbsent("other", Snapshot{Mode: "normal"}, now); !wrote {
		t.Fatal("no stub for a network with no record")
	}
}
