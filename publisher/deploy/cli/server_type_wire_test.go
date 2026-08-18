package cli

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"daal/publisher/deploy/providers/hetzner"
	"daal/publisher/deploy/providers/vultr"
)

// ONE WIRE SHAPE FOR `list-server-types`, ACROSS BOTH PROVIDERS.
//
// `runListServerTypes` dispatches on --provider and each branch encodes
// its OWN adapter struct. Nothing made those structs agree, and they
// drifted: Vultr added `currency` — deliberately, with a comment saying
// the field is "what stops a dollar figure being drawn behind a euro
// sign" — while Hetzner and this package's own mirror did not have it.
//
// The consequence was not a Go bug. It was that the single Rust struct
// deserialising BOTH branches had no field to put the currency in, so
// serde dropped it, and the L5 sheet drew a euro sign in front of a USD
// Vultr price on the one screen whose job is to get an operator to
// accept a second bill.
//
// A per-provider field is therefore not a local decision. Any field one
// branch emits and the other does not is a field the shared consumer
// must either always handle or never see.
func TestListServerTypes_BothProvidersEmitTheSameFields(t *testing.T) {
	fields := func(v any) []string {
		rt := reflect.TypeOf(v)
		out := make([]string, 0, rt.NumField())
		for i := 0; i < rt.NumField(); i++ {
			tag := rt.Field(i).Tag.Get("json")
			if tag == "" || tag == "-" {
				t.Fatalf("%s.%s has no json tag; it would cross the wire under its Go name",
					rt.Name(), rt.Field(i).Name)
			}
			name := strings.Split(tag, ",")[0]
			out = append(out, name)
		}
		sort.Strings(out)
		return out
	}

	het := fields(hetzner.ServerTypeEntry{})
	vul := fields(vultr.ServerTypeEntry{})
	mine := fields(ServerTypeInfo{})

	if !reflect.DeepEqual(het, vul) {
		t.Errorf("the two providers do not emit the same fields for one screen:\n hetzner: %v\n vultr:   %v", het, vul)
	}
	if !reflect.DeepEqual(het, mine) {
		t.Errorf("cli.ServerTypeInfo has drifted from the adapters it documents:\n adapters: %v\n cli:      %v", het, mine)
	}

	// Named explicitly rather than left to the set comparison: this is
	// the field the drift was in, and a future edit that drops it from
	// BOTH adapters at once would satisfy the comparison above while
	// re-creating the exact bug.
	found := false
	for _, f := range het {
		if f == "currency" {
			found = true
		}
	}
	if !found {
		t.Error("no `currency` field: the UI renders one price list for two providers that " +
			"bill in different money, and it cannot pick the symbol from a shape that omits it")
	}
}

// Hetzner really does stamp its currency rather than leaving it empty
// for the renderer to assume. "Assume EUR when absent" is the
// compatibility rule for OLD binaries; a current one must say so.
func TestHetznerServerTypeEntry_DeclaresItsCurrency(t *testing.T) {
	f, ok := reflect.TypeOf(hetzner.ServerTypeEntry{}).FieldByName("Currency")
	if !ok {
		t.Fatal("hetzner.ServerTypeEntry has no Currency field")
	}
	if got := f.Tag.Get("json"); got != "currency,omitempty" {
		t.Errorf("json tag = %q, want \"currency,omitempty\"", got)
	}
}
