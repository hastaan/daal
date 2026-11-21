package cloudflare

import (
	"context"
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
	if res.Verdict != VerdictOK || len(res.Zones) != 1 || res.TokenStatus != "active" {
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

func TestCheckToken_Refusals(t *testing.T) {
	cases := map[string]struct {
		setup func(m *MockCFClient)
		want  string
		zone  string
	}{
		"disabled":      {func(m *MockCFClient) { m.TokenState = "disabled" }, VerdictInvalid, ""},
		"rejected":      {func(m *MockCFClient) { m.VerifyErr = &authError{msg: "403"} }, VerdictInvalid, ""},
		"no zone":       {func(m *MockCFClient) { m.Zones = nil }, VerdictNoZone, ""},
		"pending zone":  {func(m *MockCFClient) { m.Zones[0].Status = "pending" }, VerdictNoZone, ""},
		"other zone":    {func(m *MockCFClient) {}, VerdictZoneNotVisible, "other.org"},
		"all zones":     {func(m *MockCFClient) { m.Zones = append(m.Zones, Zone{ID: "z2", Name: "b.org", Status: "active"}) }, VerdictTooBroad, ""},
		"workers":       {func(m *MockCFClient) { m.ProbeAnswer["/accounts/acct-1/workers/scripts"] = ProbeAllowed }, VerdictTooBroad, ""},
		"registrar":     {func(m *MockCFClient) { m.ProbeAnswer["/accounts/acct-1/registrar/domains"] = ProbeAllowed }, VerdictTooBroad, ""},
		"billing":       {func(m *MockCFClient) { m.ProbeAnswer["/accounts/acct-1/billing/profile"] = ProbeAllowed }, VerdictTooBroad, ""},
		"token admin":   {func(m *MockCFClient) { m.ProbeAnswer["/user/tokens?per_page=1"] = ProbeAllowed }, VerdictTooBroad, ""},
		"worker routes": {func(m *MockCFClient) { m.ProbeAnswer["/zones/zone-example.com/workers/routes"] = ProbeAllowed }, VerdictTooBroad, ""},
		"no dns":        {func(m *MockCFClient) { delete(m.ProbeAnswer, "/zones/zone-example.com/dns_records?per_page=1") }, VerdictMissingPermission, ""},
		"no settings":   {func(m *MockCFClient) { delete(m.ProbeAnswer, "/zones/zone-example.com/settings/ssl") }, VerdictMissingPermission, ""},
		"no rules": {func(m *MockCFClient) {
			m.ProbeAnswer["/zones/zone-example.com/rulesets/phases/http_request_origin/entrypoint"] = ProbeDenied
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
	}
}

// A missing-permission verdict names the permission; a too-broad one
// names what is extra.
func TestCheckToken_NamesWhatIsWrong(t *testing.T) {
	m := NewMockCFClient("example.com")
	m.ProbeAnswer["/accounts/acct-1/workers/scripts"] = ProbeAllowed
	res, _ := CheckToken(context.Background(), m, []byte(testToken), "")
	if len(res.Extra) != 1 || !strings.Contains(res.Extra[0], "Workers") {
		t.Errorf("extra = %v", res.Extra)
	}
	m = NewMockCFClient("example.com")
	delete(m.ProbeAnswer, "/zones/zone-example.com/dns_records?per_page=1")
	res, _ = CheckToken(context.Background(), m, []byte(testToken), "")
	if len(res.Missing) != 1 || !strings.Contains(res.Missing[0], "DNS") {
		t.Errorf("missing = %v", res.Missing)
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
