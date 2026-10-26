package node

import (
	"encoding/json"
	"os"
	"testing"
)

// testdata/control-urls.json is shared with TunnelCore's TailnetTests.swift: the engine and the
// app apply the same rules, so they run the same cases (quality-9 L1). "DEFAULT" stands for
// Tailscale's own server.
type urlFixture struct {
	Canonical map[string]string `json:"canonical"`
	Refused   []string          `json:"refused"`
	Login     [][3]any          `json:"login"`
}

func loadURLFixture(t *testing.T) urlFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/control-urls.json")
	if err != nil {
		t.Fatal(err)
	}
	var f urlFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Canonical) == 0 || len(f.Refused) == 0 || len(f.Login) == 0 {
		t.Fatal("empty fixture")
	}
	return f
}

func fixtureURL(s string) string {
	if s == "DEFAULT" {
		return DefaultControlURL
	}
	return s
}

func TestCanonicalControlURL(t *testing.T) {
	f := loadURLFixture(t)
	for in, want := range f.Canonical {
		got, err := CanonicalControlURL(in)
		if err != nil || got != fixtureURL(want) {
			t.Errorf("CanonicalControlURL(%q) = %q, %v; want %q", in, got, err, fixtureURL(want))
		}
	}
	if got, _ := CanonicalControlURL("https://controlplane.tailscale.com"); got != DefaultControlURL {
		t.Errorf("Tailscale's server canonicalizes to %q", got)
	}
	for _, in := range f.Refused {
		if got, err := CanonicalControlURL(in); err == nil {
			t.Errorf("CanonicalControlURL(%q) = %q, want an error", in, got)
		}
	}
}

func TestControlKey(t *testing.T) {
	a, b := ControlKey("https://hs.example.com"), ControlKey("https://hs2.example.com")
	if len(a) != 16 || a == b {
		t.Fatalf("ControlKey: %q %q", a, b)
	}
}

func TestValidLoginURL(t *testing.T) {
	for _, c := range loadURLFixture(t).Login {
		login, control, want := c[0].(string), fixtureURL(c[1].(string)), c[2].(bool)
		if got := ValidLoginURL(login, control); got != want {
			t.Errorf("ValidLoginURL(%q, %q) = %v, want %v", login, control, got, want)
		}
	}
}
