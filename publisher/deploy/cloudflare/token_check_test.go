package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestCheckToken_ExactlyTheFivePermissions(t *testing.T) {
	m := NewMockCFClient("example.com")
	res, err := CheckToken(context.Background(), m, []byte(testToken), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != VerdictOK || !res.Usable() || len(res.Zones) != 1 || res.Zone != "example.com" || res.TokenStatus != "active" {
		t.Fatalf("res = %+v", res)
	}
	if len(res.Unproven) == 0 {
		t.Error("an ok verdict must say what a read probe cannot prove")
	}
	for _, c := range m.Calls {
		if !strings.HasPrefix(c, "VerifyToken") && !strings.HasPrefix(c, "ListZones") && !strings.HasPrefix(c, "ProbeRead(") {
			t.Errorf("the check did more than read: %s", c)
		}
	}
}

// Refused only when the token cannot do the job: not working, no zone,
// not the zone asked for, or short of one of the five.
func TestCheckToken_Refusals(t *testing.T) {
	cases := map[string]struct {
		setup func(m *MockCFClient)
		want  string
		zone  string
	}{
		"disabled":     {func(m *MockCFClient) { m.TokenState = "disabled" }, VerdictInvalid, ""},
		"rejected":     {func(m *MockCFClient) { m.VerifyErr = &authError{msg: "403"} }, VerdictInvalid, ""},
		"no zone":      {func(m *MockCFClient) { m.Zones = nil }, VerdictNoZone, ""},
		"pending zone": {func(m *MockCFClient) { m.Zones[0].Status = "pending" }, VerdictNoZone, ""},
		"other zone":   {func(m *MockCFClient) {}, VerdictZoneNotVisible, "other.org"},
		"no dns":       {func(m *MockCFClient) { delete(m.ProbeAnswer, "/zones/zone-example.com/dns_records?per_page=1") }, VerdictMissingPermission, ""},
		"no settings":  {func(m *MockCFClient) { delete(m.ProbeAnswer, "/zones/zone-example.com/settings/ssl") }, VerdictMissingPermission, ""},
		"no rules": {func(m *MockCFClient) {
			m.ProbeAnswer["/zones/zone-example.com/rulesets/phases/http_request_origin/entrypoint"] = ProbeDenied
		}, VerdictMissingPermission, ""},
		// Short of one AND able to do more: refused for what is missing.
		"short and broad": {func(m *MockCFClient) {
			delete(m.ProbeAnswer, "/zones/zone-example.com/settings/ssl")
			m.ProbeAnswer["/accounts/acct-1/billing/profile"] = ProbeAllowed
		}, VerdictMissingPermission, ""},
	}
	for name, c := range cases {
		m := NewMockCFClient("example.com")
		c.setup(m)
		res, err := CheckToken(context.Background(), m, []byte(testToken), c.zone)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if res.Verdict != c.want {
			t.Errorf("%s: verdict %q, want %q (%+v)", name, res.Verdict, c.want, res)
		}
		if res.Usable() {
			t.Errorf("%s: a refusal is usable", name)
		}
	}
}

// A token that can do more than the five works: kept, with what it can
// do beyond them named.
func TestCheckToken_MoreThanNeededWorksAndIsNamed(t *testing.T) {
	for name, path := range map[string]string{
		"workers":       "/accounts/acct-1/workers/scripts",
		"registrar":     "/accounts/acct-1/registrar/domains",
		"billing":       "/accounts/acct-1/billing/profile",
		"token admin":   "/user/tokens?per_page=1",
		"worker routes": "/zones/zone-example.com/workers/routes",
	} {
		m := NewMockCFClient("example.com")
		m.ProbeAnswer[path] = ProbeAllowed
		res, err := CheckToken(context.Background(), m, []byte(testToken), "")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.Verdict != VerdictOKBroad || !res.Usable() || len(res.Extra) != 1 || res.Zone != "example.com" {
			t.Errorf("%s: %+v", name, res)
		}
		if len(res.Unproven) == 0 {
			t.Errorf("%s: a usable verdict must say what a read probe cannot prove", name)
		}
	}
}

// Several zones: none is refused. With no zone asked for, the answer is
// the list to pick from, and nothing is probed; with one asked for, the
// check is made on that zone and it is the one to use.
func TestCheckToken_SeveralZonesArePickedFrom(t *testing.T) {
	m := NewMockCFClient("example.com")
	other := Zone{ID: "zone-b.org", Name: "b.org", Status: "active", AccountID: "acct-1"}
	m.Zones = append(m.Zones, other)
	res, err := CheckToken(context.Background(), m, []byte(testToken), "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != VerdictPickZone || res.Usable() || len(res.Zones) != 2 || res.Zone != "" {
		t.Fatalf("res = %+v", res)
	}
	for _, c := range m.Calls {
		if strings.HasPrefix(c, "ProbeRead(") {
			t.Errorf("probed before a zone was picked: %s", c)
		}
	}

	res, err = CheckToken(context.Background(), m, []byte(testToken), "Example.com.")
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != VerdictOK || res.Zone != "example.com" || len(res.Zones) != 2 {
		t.Fatalf("picked example.com: %+v", res)
	}

	// The other zone is checked on its own paths: here it lacks them all.
	res, _ = CheckToken(context.Background(), m, []byte(testToken), "b.org")
	if res.Verdict != VerdictMissingPermission || res.Zone != "b.org" || len(res.Missing) == 0 {
		t.Fatalf("picked b.org: %+v", res)
	}
	for _, p := range requiredProbes(other) {
		m.ProbeAnswer[p.Path] = ProbeAllowed
	}
	res, _ = CheckToken(context.Background(), m, []byte(testToken), "b.org")
	if res.Verdict != VerdictOK || res.Zone != "b.org" {
		t.Fatalf("picked b.org with the five: %+v", res)
	}
	res, _ = CheckToken(context.Background(), m, []byte(testToken), "c.net")
	if res.Verdict != VerdictZoneNotVisible {
		t.Fatalf("a zone it does not see: %+v", res)
	}
}

// A missing-permission verdict names every missing permission, and also
// what is extra, so one answer says everything to fix.
func TestCheckToken_NamesWhatIsWrong(t *testing.T) {
	m := NewMockCFClient("example.com")
	m.ProbeAnswer["/accounts/acct-1/workers/scripts"] = ProbeAllowed
	res, _ := CheckToken(context.Background(), m, []byte(testToken), "")
	if len(res.Extra) != 1 || !strings.Contains(res.Extra[0], "Workers") {
		t.Errorf("extra = %v", res.Extra)
	}
	m = NewMockCFClient("example.com")
	delete(m.ProbeAnswer, "/zones/zone-example.com/dns_records?per_page=1")
	delete(m.ProbeAnswer, "/zones/zone-example.com/settings/ssl")
	m.ProbeAnswer["/accounts/acct-1/billing/profile"] = ProbeAllowed
	res, _ = CheckToken(context.Background(), m, []byte(testToken), "")
	if len(res.Missing) != 2 || !strings.Contains(res.Missing[0], "DNS") || !strings.Contains(res.Missing[1], "Zone Settings") {
		t.Errorf("missing = %v", res.Missing)
	}
	if len(res.Extra) != 1 || !strings.Contains(res.Extra[0], "Billing") {
		t.Errorf("extra = %v", res.Extra)
	}
}

// No answer, whatever its verdict, carries the token.
func TestCheckToken_TheAnswerNeverCarriesTheToken(t *testing.T) {
	setups := []func(m *MockCFClient){
		func(m *MockCFClient) {},
		func(m *MockCFClient) { m.TokenState = "disabled" },
		func(m *MockCFClient) { m.Zones = append(m.Zones, Zone{ID: "z2", Name: "b.org", Status: "active"}) },
		func(m *MockCFClient) { m.ProbeAnswer["/accounts/acct-1/billing/profile"] = ProbeAllowed },
		func(m *MockCFClient) { delete(m.ProbeAnswer, "/zones/zone-example.com/settings/ssl") },
	}
	for i, setup := range setups {
		m := NewMockCFClient("example.com")
		setup(m)
		res, err := CheckToken(context.Background(), m, []byte(testToken), "")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(res)
		if strings.Contains(string(b), testToken) {
			t.Fatalf("case %d: token in the answer: %s", i, b)
		}
	}
}

// A network error is an error, never a verdict, and never carries the
// token.
func TestCheckToken_ErrorsAreNotVerdictsAndCarryNoToken(t *testing.T) {
	m := NewMockCFClient("example.com")
	m.ProbeErr = map[string]error{"/user": errors.New("dial: " + testToken)}
	_, err := CheckToken(context.Background(), m, []byte(testToken), "")
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatalf("token in error: %v", err)
	}
	if res, err := CheckToken(context.Background(), m, nil, ""); err != nil || res.Verdict != VerdictInvalid {
		t.Errorf("empty token: %+v %v", res, err)
	}
}

func TestScrubKeepsSentinels(t *testing.T) {
	err := scrub(&ProvisionError{Step: "x", Err: errors.New(testToken + " " + ErrZoneNotFound.Error())}, []byte(testToken))
	if strings.Contains(err.Error(), testToken) {
		t.Fatal("not scrubbed")
	}
	wrapped := scrub(errors.Join(ErrHostnameInUse, errors.New(testToken)), []byte(testToken))
	if !errors.Is(wrapped, ErrHostnameInUse) {
		t.Error("errors.Is lost the sentinel")
	}
}
