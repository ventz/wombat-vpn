package node

import (
	"encoding/json"
	"slices"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"
	"tailscale.com/net/dns"
	"tailscale.com/wgengine/router"
)

var (
	_ router.Router      = (*facade)(nil)
	_ dns.OSConfigurator = (*facade)(nil)
)

// Plan is the network configuration handed to Swift as JSON. It is a proposal: Swift's
// TailnetNetworkPlan gate decides what reaches NEPacketTunnelNetworkSettings (design 2.6).
type Plan struct {
	Addresses     []string `json:"addresses"`
	Routes        []string `json:"routes"`
	MTU           int      `json:"mtu"`
	DNSServers    []string `json:"dnsServers"`
	MatchDomains  []string `json:"matchDomains"`
	SearchDomains []string `json:"searchDomains"`
}

// Caps bound the JSON whatever the coordination server sends; Swift checks them again.
const (
	maxRoutes  = 1024
	maxDomains = 256
)

// facade is the engine's router and DNS configurator. It never touches the OS: it records
// what the engine asks for and, on ReconfigureVPN, hands both to Swift as one Plan. A port of
// tailscale-android's VPNFacade (BSD-3-Clause), with split DNS supported so MagicDNS names go
// to quad100 while everything else keeps the Mac's resolver.
type facade struct {
	onPlan func([]byte)

	mu   sync.Mutex
	rcfg *router.Config
	dcfg *dns.OSConfig
	last []byte
}

func newFacade(onPlan func([]byte)) *facade { return &facade{onPlan: onPlan} }

func (f *facade) Up() error { return nil }

func (f *facade) Set(rcfg *router.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rcfg = rcfg.Clone()
	return nil
}

func (f *facade) UpdateMagicsockPort(uint16, string) error { return nil }

func (f *facade) SetDNS(cfg dns.OSConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := dns.OSConfig{
		Nameservers:   slices.Clone(cfg.Nameservers),
		SearchDomains: slices.Clone(cfg.SearchDomains),
		MatchDomains:  slices.Clone(cfg.MatchDomains),
	}
	f.dcfg = &c
	return nil
}

func (f *facade) SupportsSplitDNS() bool { return true }

func (f *facade) GetBaseConfig() (dns.OSConfig, error) {
	return dns.OSConfig{}, dns.ErrGetBaseConfigNotSupported
}

func (f *facade) Close() error { return nil }

// ReconfigureVPN is wgengine.Config.ReconfigureVPN: the engine has finished a batch of router
// and DNS changes. An unchanged plan isn't sent again.
func (f *facade) ReconfigureVPN() error {
	f.mu.Lock()
	plan := makePlan(f.rcfg, f.dcfg)
	data, err := json.Marshal(plan)
	if err != nil || string(data) == string(f.last) {
		f.mu.Unlock()
		return err
	}
	f.last = data
	f.mu.Unlock()
	if f.onPlan != nil {
		f.onPlan(data)
	}
	return nil
}

// isPublicSuffix: the name is on the Public Suffix List (ICANN or private section) itself, so
// it has no registrable domain of its own.
func isPublicSuffix(name string) bool {
	_, err := publicsuffix.EffectiveTLDPlusOne(name)
	return err != nil
}

func makePlan(rcfg *router.Config, dcfg *dns.OSConfig) Plan {
	p := Plan{Addresses: []string{}, Routes: []string{}, DNSServers: []string{}, MatchDomains: []string{}, SearchDomains: []string{}}
	if rcfg != nil {
		for _, a := range rcfg.LocalAddrs {
			p.Addresses = append(p.Addresses, a.String())
		}
		for _, r := range rcfg.Routes {
			if len(p.Routes) == maxRoutes {
				break
			}
			p.Routes = append(p.Routes, r.String())
		}
		p.MTU = rcfg.NewMTU
	}
	if dcfg != nil {
		for _, ns := range dcfg.Nameservers {
			p.DNSServers = append(p.DNSServers, ns.String())
		}
		// A domain that is itself a public suffix ("co.uk", "github.io") would send lookups
		// for everyone's names under it to the coordination server's resolvers; never pass one
		// on (security-9 M3, astra S9-1). The Swift gate then decides what remains.
		var search []string
		for _, d := range dcfg.SearchDomains {
			if name := strings.TrimSuffix(string(d), "."); !isPublicSuffix(name) && len(search) < maxDomains {
				search = append(search, name)
			}
		}
		p.SearchDomains = append(p.SearchDomains, search...)
		// Order before the cap: the MagicDNS suffix (also a search domain), then the reverse
		// zones (64 for 100.64.0.0/10 alone), then other names, so neither of the first two is
		// ever cut (ts-probe; quality-9 L9).
		var suffix, reverse, others []string
		for _, d := range dcfg.MatchDomains {
			name := strings.TrimSuffix(string(d), ".")
			switch {
			case isPublicSuffix(name):
			case slices.Contains(search, name):
				suffix = append(suffix, name)
			case strings.HasSuffix(name, ".arpa"):
				reverse = append(reverse, name)
			default:
				others = append(others, name)
			}
		}
		for _, name := range slices.Concat(suffix, reverse, others) {
			if len(p.MatchDomains) < maxDomains {
				p.MatchDomains = append(p.MatchDomains, name)
			}
		}
	}
	return p
}
