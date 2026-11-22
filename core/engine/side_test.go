package engine

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"daal/core/routestore"
)

func sideCfgFor(t *testing.T, family, profile string) []byte {
	t.Helper()
	cfg, err := BuildSingBoxConfig(routestore.RouteRow{RouteID: "r", TransportFamily: family}, []byte(profile))
	if err != nil {
		t.Fatalf("BuildSingBoxConfig(%s): %v", family, err)
	}
	t.Cleanup(retireRefreshInlet)
	body, err := MarshalSingBox(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// Which routes may be proved beside the running one — and, above all,
// which may not: naive (never raced; the survey alone may: below),
// wireguard (an endpoint; a second handshake moves the peer's session),
// anything detoured, and every type nobody vouched for.
func TestSideProbeable_Table(t *testing.T) {
	cases := []struct {
		family, profile string
		want            bool
	}{
		{"vless-reality", `{"type":"vless","server":"203.0.113.1","server_port":443}`, true},
		{"websocket-tls", `{"type":"vless","server":"relay.example","server_port":8443,"transport":{"type":"ws"}}`, true},
		{"hysteria2", `{"type":"hysteria2","server":"203.0.113.1","server_port":443}`, true},
		{"tuic", `{"type":"tuic","server":"203.0.113.1","server_port":443}`, true},
		{"shadowsocks", `{"type":"shadowsocks","server":"203.0.113.1","server_port":8388}`, true},
		{"anytls", `{"type":"anytls","server":"203.0.113.1","server_port":443}`, true},
		{"other", `{"type":"trojan","server":"203.0.113.1","server_port":443}`, true},
		{"other", `{"type":"http","server":"203.0.113.1","server_port":3128}`, true},
		{"naive", `{"type":"naive","server":"203.0.113.1","server_port":443}`, false},
		{"wireguard", `{"type":"wireguard","address":["10.0.0.2/32"],"private_key":"x","peers":[{"address":"203.0.113.1","port":51820,"public_key":"y","allowed_ips":["0.0.0.0/0"]}]}`, false},
		{"other", `{"type":"ssh","server":"203.0.113.1","server_port":22}`, false},
		{"other", `{"type":"shadowtls","server":"203.0.113.1","server_port":443}`, false},
		{"other", `{"type":"vless","server":"203.0.113.1","server_port":443,"detour":"x"}`, false},
		{"other", `{"type":"vless","server_port":443}`, false},
	}
	for _, c := range cases {
		if got := SideProbeable(sideCfgFor(t, c.family, c.profile)); got != c.want {
			t.Errorf("SideProbeable(%s %s) = %v, want %v", c.family, c.profile, got, c.want)
		}
	}
	if SideProbeable([]byte(`not json`)) || SideProbeable(nil) {
		t.Error("a config that does not parse was called side-probeable")
	}
	// tor never gets as far as a config on a machine with no tor binary;
	// its outbound type must be refused whatever the profile says.
	if SideProbeable([]byte(`{"outbounds":[{"tag":"active","type":"tor","server":"x"}]}`)) {
		t.Error("a tor outbound was called side-probeable")
	}
}

// The survey — and only a caller that says so (ProofConfig.SideCronet)
// — may also side-probe naive. Nothing else widens: wireguard, tor,
// ssh, a detoured naive stay refused.
func TestSurveyProbeable_NaiveOnlyWhenAskedFor(t *testing.T) {
	naive := sideCfgFor(t, "naive", `{"type":"naive","server":"203.0.113.1","server_port":443}`)
	if SideProbeable(naive) || !SurveyProbeable(naive) {
		t.Fatalf("naive: side %v, survey %v; want false, true", SideProbeable(naive), SurveyProbeable(naive))
	}
	for _, c := range [][2]string{
		{"wireguard", `{"type":"wireguard","address":["10.0.0.2/32"],"private_key":"x","peers":[{"address":"203.0.113.1","port":51820,"public_key":"y","allowed_ips":["0.0.0.0/0"]}]}`},
		{"other", `{"type":"ssh","server":"203.0.113.1","server_port":22}`},
		{"other", `{"type":"naive","server":"203.0.113.1","server_port":443,"detour":"x"}`},
	} {
		if SurveyProbeable(sideCfgFor(t, c[0], c[1])) {
			t.Errorf("SurveyProbeable(%s %s) = true", c[0], c[1])
		}
	}
	if SurveyProbeable([]byte(`{"outbounds":[{"tag":"active","type":"tor","server":"x"}]}`)) {
		t.Error("a tor outbound was called survey-probeable")
	}
	s := NewStub()
	s.SetSideProbeHook(func(context.Context, []byte, ProofConfig) (ProofResult, error) {
		return ProofResult{OK: true}, nil
	})
	if s.CanSideProbe(naive) || !s.CanSurveyProbe(naive) {
		t.Fatal("the Stub's answers for naive")
	}
	if _, err := s.SideProbe(context.Background(), naive, ProofConfig{}); !errors.Is(err, ErrSideProbeUnsupported) {
		t.Fatalf("naive without SideCronet: err = %v", err)
	}
	if res, err := s.SideProbe(context.Background(), naive, ProofConfig{SideCronet: true}); err != nil || !res.OK {
		t.Fatalf("naive with SideCronet: %+v err=%v", res, err)
	}
}

// The Stub side-probes only when a test scripts it; never more than
// MaxSideProbes at once; and StopSideProbes ends what is in flight.
func TestStubSideProbe_LimitAndStop(t *testing.T) {
	s := NewStub()
	cfg := sideCfgFor(t, "vless-reality", `{"type":"vless","server":"203.0.113.1","server_port":443}`)
	if s.CanSideProbe(cfg) {
		t.Fatal("a Stub with no hook said it can side-probe: every older test would start racing")
	}
	if _, err := s.SideProbe(context.Background(), cfg, ProofConfig{}); !errors.Is(err, ErrSideProbeUnsupported) {
		t.Fatalf("err = %v", err)
	}
	s.SetSideProbeHook(func(ctx context.Context, _ []byte, _ ProofConfig) (ProofResult, error) {
		<-ctx.Done()
		return ProofResult{}, nil
	})
	if !s.CanSideProbe(cfg) {
		t.Fatal("hook installed and a side-probeable route refused")
	}
	var wg sync.WaitGroup
	results := make([]ProofResult, MaxSideProbes)
	for i := 0; i < MaxSideProbes; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], _ = s.SideProbe(context.Background(), cfg, ProofConfig{})
		}(i)
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.SideProbesInFlight() < MaxSideProbes && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if _, err := s.SideProbe(context.Background(), cfg, ProofConfig{}); !errors.Is(err, ErrSideProbeBusy) {
		t.Fatalf("a probe beyond MaxSideProbes was admitted: err = %v", err)
	}
	s.StopSideProbes()
	wg.Wait()
	if n := s.SideProbesInFlight(); n != 0 {
		t.Fatalf("%d side probes in flight after StopSideProbes returned", n)
	}
	for i, r := range results {
		if !r.Cancelled {
			t.Errorf("probe %d was stopped and came back %+v, want Cancelled", i, r)
		}
	}
	if total, peak := s.SideProbeStats(); total != MaxSideProbes || peak != MaxSideProbes {
		t.Fatalf("total=%d peak=%d", total, peak)
	}
}
