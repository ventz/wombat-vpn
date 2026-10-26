package node

import (
	"fmt"
	"slices"
	"testing"

	"tailscale.com/net/dns"
	"tailscale.com/util/dnsname"
)

// The MagicDNS suffix (a search domain too) and the 64 reverse zones survive the cap, however
// many other names the coordination server sends first (quality-9 L9).
func TestPlanKeepsTailnetDomainsUnderTheCap(t *testing.T) {
	cfg := dns.OSConfig{SearchDomains: []dnsname.FQDN{"tail1234.ts.net."}}
	for i := 0; i < 300; i++ {
		cfg.MatchDomains = append(cfg.MatchDomains, dnsname.FQDN(fmt.Sprintf("z%d.example.", i)))
	}
	for i := 64; i < 128; i++ {
		cfg.MatchDomains = append(cfg.MatchDomains, dnsname.FQDN(fmt.Sprintf("%d.100.in-addr.arpa.", i)))
	}
	cfg.MatchDomains = append(cfg.MatchDomains, "tail1234.ts.net.")
	p := makePlan(nil, &cfg)
	if len(p.MatchDomains) != maxDomains {
		t.Fatalf("%d domains", len(p.MatchDomains))
	}
	if p.MatchDomains[0] != "tail1234.ts.net" {
		t.Fatalf("the MagicDNS suffix isn't first: %v", p.MatchDomains[:3])
	}
	for i := 64; i < 128; i++ {
		if !slices.Contains(p.MatchDomains, fmt.Sprintf("%d.100.in-addr.arpa", i)) {
			t.Fatalf("reverse zone %d cut by the cap", i)
		}
	}
}

// A public suffix never reaches the plan: it would route lookups for everyone's names under it
// to the coordination server (security-9 M3). A registrable name ("amazonaws.com") is the
// suffix pin's job, in the Swift gate.
func TestPlanDropsPublicSuffixes(t *testing.T) {
	cfg := dns.OSConfig{
		SearchDomains: []dnsname.FQDN{"co.uk.", "github.io.", "wombat-test.internal."},
		MatchDomains:  []dnsname.FQDN{"co.uk.", "github.io.", "com.", "s3.amazonaws.com.", "wombat-test.internal.", "64.100.in-addr.arpa."},
	}
	p := makePlan(nil, &cfg)
	for _, bad := range []string{"co.uk", "github.io", "com", "s3.amazonaws.com"} {
		if slices.Contains(p.MatchDomains, bad) || slices.Contains(p.SearchDomains, bad) {
			t.Errorf("%s passed: match %v, search %v", bad, p.MatchDomains, p.SearchDomains)
		}
	}
	if !slices.Contains(p.MatchDomains, "wombat-test.internal") || !slices.Contains(p.MatchDomains, "64.100.in-addr.arpa") ||
		!slices.Equal(p.SearchDomains, []string{"wombat-test.internal"}) {
		t.Errorf("tailnet names lost: match %v, search %v", p.MatchDomains, p.SearchDomains)
	}
	// Tailscale's own suffix is a private-section public suffix; its tailnets are below it.
	cfg = dns.OSConfig{SearchDomains: []dnsname.FQDN{"tail1234.ts.net."}, MatchDomains: []dnsname.FQDN{"tail1234.ts.net.", "ts.net."}}
	p = makePlan(nil, &cfg)
	if !slices.Equal(p.MatchDomains, []string{"tail1234.ts.net"}) {
		t.Errorf("ts.net handling: %v", p.MatchDomains)
	}
}
