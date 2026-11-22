package abi

import (
	"crypto/rand"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	"daal/core/bootstrap"
	"daal/core/refresh"
)

// The DNS carrier is usable once the host has named the link's resolver,
// and not after it says the network is gone.
func TestSetLinkResolvers_DNSCarrierUsable(t *testing.T) {
	t.Cleanup(bootstrap.ForgetHostLinkResolvers)
	var dnsC refresh.Carrier
	for _, c := range refresh.RegisteredCarriers() {
		if c.Info().Label == bundle.NoteCarrierDNS {
			dnsC = c
		}
	}
	if dnsC == nil {
		t.Fatal("no DNS carrier registered")
	}
	k, err := bundle.NewStandbyKey("93.184.216.34", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	st := bundle.SealedStandby(k)
	u := &bundle.UpdateSecret{Audience: bundle.AudiencePeople}
	u.Secret[0] = 1
	env := &refresh.CarrierEnv{
		RelayPackID: "rp",
		Secrets:     []*bundle.UpdateSecret{u},
		Carriers:    &bundle.UpdateCarriers{DNS: &bundle.DNSCarrier{Zone: "notes.example.org"}},
		Standby:     &st,
		Now:         time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC),
		Dialer:      refresh.NoDialer,
	}

	if n, err := SetLinkResolvers(`["192.168.1.1"]`); err != nil || n != 1 {
		t.Fatalf("set: %d %v", n, err)
	}
	if !dnsC.Usable(env) {
		t.Fatal("not usable with the link's resolver")
	}
	if n, err := SetLinkResolvers(`[]`); err != nil || n != 0 {
		t.Fatalf("clear: %d %v", n, err)
	}
	if dnsC.Usable(env) {
		t.Fatal("usable after the network was lost")
	}
	if n, _ := SetLinkResolvers(`["8.8.8.8"]`); n != 0 || dnsC.Usable(env) {
		t.Fatal("a public resolver made it usable")
	}
	if n, err := SetLinkResolvers(`{"x":1}`); err == nil || n != -1 {
		t.Fatalf("bad JSON: %d %v", n, err)
	}
}
