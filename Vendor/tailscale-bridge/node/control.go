// Package node runs one Tailscale node for Wombat's tailnet extension: control-server and
// sign-in URL rules, the state directory, the engine and LocalBackend, and the network plan
// handed to Swift. The cgo layer in the parent package only marshals calls into it.
package node

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// DefaultControlURL is Tailscale's coordination server, used when a profile names none.
const DefaultControlURL = "https://controlplane.tailscale.com"

// allowLoopbackHTTP lets the command-line probe use a plain-http Headscale on 127.0.0.1. It is
// only ever true in builds with the wombat_devprobe tag (devprobe.go); build-ts-go.sh refuses
// that tag, so the extension's archive keeps the https-only rule.
var allowLoopbackHTTP = false

// devBuild names a dev-probe build in its first log line; build-ts-go.sh refuses an archive
// that contains the text (security-7 L5: checking the tag list alone could never fail).
var devBuild = ""

var (
	tailnetIPv4 = netip.MustParsePrefix("100.64.0.0/10")
	tailnetIPv6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// CanonicalControlURL checks a coordination server URL and returns its canonical form:
// lowercase scheme and host, the port only when it isn't the default, the path without a
// trailing slash. Empty means Tailscale's own server.
//
// Rules (design 2.4): https only; no userinfo, query or fragment; no ".." in the path; the host
// is a DNS name or an IP literal that isn't loopback, link-local, multicast, unspecified or in
// the tailnet ranges (a control server inside the tailnet could never be reached to sign in).
func CanonicalControlURL(raw string) (string, error) {
	if raw == "" {
		return DefaultControlURL, nil
	}
	if len(raw) > 512 {
		return "", errors.New("the coordination server URL is too long")
	}
	if strings.ContainsFunc(raw, func(r rune) bool { return r < 0x20 || r == 0x7f || r == ' ' }) {
		return "", errors.New("the coordination server URL contains spaces or control characters")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("the coordination server URL isn't a valid URL")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	switch {
	case u.Opaque != "" || host == "":
		return "", errors.New("the coordination server URL has no host")
	case u.User != nil:
		return "", errors.New("the coordination server URL must not contain a user name or password")
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#"):
		return "", errors.New("the coordination server URL must not contain a query or fragment")
	case strings.Contains(u.Path, "..") || strings.Contains(strings.ToLower(u.EscapedPath()), "%2e"):
		return "", errors.New("the coordination server URL path must not contain \"..\"")
	}
	loopbackDev := allowLoopbackHTTP && scheme == "http" && isLoopbackHost(host)
	if scheme != "https" && !loopbackDev {
		return "", errors.New("the coordination server must use https")
	}
	if !loopbackDev {
		if err := checkControlHost(host); err != nil {
			return "", err
		}
	}
	if port != "" {
		if !validPort(port) {
			return "", errors.New("the coordination server URL has an invalid port")
		}
		if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
			port = ""
		}
	}
	canonical := scheme + "://" + bracketed(host)
	if port != "" {
		canonical += ":" + port
	}
	return canonical + strings.TrimRight(u.EscapedPath(), "/"), nil
}

// ControlKey names a coordination server in the state directory: the first 16 hex digits of
// SHA-256 of its canonical URL. A different server is a different node, never a migration.
func ControlKey(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:8])
}

// IsDefaultControl reports whether a canonical URL is Tailscale's own coordination server.
func IsDefaultControl(canonical string) bool {
	return canonical == DefaultControlURL || canonical == "https://login.tailscale.com"
}

// ValidLoginURL reports whether a sign-in URL pushed by the coordination server may be shown
// to the user (design 2.5, checked again in Swift by TailnetLoginURL). Tailscale's own check
// allows any host for a custom server; ours requires the server's own host, or tailscale.com
// and its subdomains only when the server is Tailscale's.
func ValidLoginURL(loginURL, canonicalControl string) bool {
	if loginURL == "" || len(loginURL) > 2048 {
		return false
	}
	if strings.ContainsFunc(loginURL, func(r rune) bool { return r < 0x20 || r == 0x7f || r == ' ' }) {
		return false
	}
	u, err := url.Parse(loginURL)
	if err != nil || u.User != nil || u.Opaque != "" {
		return false
	}
	control, err := url.Parse(canonicalControl)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if scheme != control.Scheme || (scheme != "https" && !(allowLoopbackHTTP && scheme == "http")) {
		return false
	}
	if IsDefaultControl(canonicalControl) {
		return u.Port() == "" && (host == "tailscale.com" || strings.HasSuffix(host, ".tailscale.com"))
	}
	// Effective ports: Headscale may build the page from a server_url with ":443", which the
	// canonical control URL leaves out (quality-9 M1).
	if host != control.Hostname() || effectivePort(scheme, u.Port()) != effectivePort(scheme, control.Port()) {
		return false
	}
	// No IP-literal sign-in hosts, except the probe's loopback server.
	if _, err := netip.ParseAddr(host); err == nil && !(allowLoopbackHTTP && isLoopbackHost(host)) {
		return false
	}
	return true
}

func checkControlHost(host string) error {
	if addr, err := netip.ParseAddr(host); err == nil {
		// IPv4-mapped IPv6 addresses hide an IPv4 address from these checks (security-7 L1).
		if addr.Is4In6() {
			return errors.New("the coordination server address must not be an IPv4-mapped IPv6 address")
		}
		switch {
		case addr.IsLoopback(), addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast(),
			addr.IsMulticast(), addr.IsUnspecified(), addr.Zone() != "",
			addr.Is4() && (addr.As4()[0] == 0 || addr == netip.AddrFrom4([4]byte{255, 255, 255, 255})):
			return errors.New("the coordination server address must be a public or private network address")
		case tailnetIPv4.Contains(addr), tailnetIPv6.Contains(addr):
			return errors.New("the coordination server can't be inside the tailnet")
		}
		return nil
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return errors.New("the coordination server address must be a public or private network address")
	}
	if len(host) > 253 {
		return errors.New("the coordination server host name is too long")
	}
	// A trailing dot names the same host, but the server's sign-in page never carries it, so
	// sign-in could never match (quality-9 L11).
	if strings.HasSuffix(host, ".") {
		return errors.New("the coordination server host name must not end with a dot")
	}
	// "127.1" or "2130706433": numeric forms resolvers may turn into an address refused above.
	// No real host name ends in an all-digit label.
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	if last := labels[len(labels)-1]; last != "" && strings.Trim(last, "0123456789") == "" {
		return errors.New("the coordination server address isn't valid")
	}
	// Hex forms too ("0x7f000001", "0x7f.0.0.1"): inet_aton reads them as addresses, which
	// would get past the address checks above (security-9-astra S9-3).
	for _, label := range labels {
		if len(label) > 2 && label[:2] == "0x" && strings.Trim(label[2:], "0123456789abcdef") == "" {
			return errors.New("the coordination server address isn't valid")
		}
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return errors.New("the coordination server host name isn't valid")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return errors.New("the coordination server host name isn't valid")
			}
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Unmap().IsLoopback()
}

// effectivePort is the port a URL really uses: the scheme's default when none is given.
func effectivePort(scheme, port string) int {
	if port == "" {
		if scheme == "http" {
			return 80
		}
		return 443
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return -1
	}
	return n
}

func validPort(port string) bool {
	if len(port) > 5 {
		return false
	}
	n := 0
	for _, r := range port {
		if r < '0' || r > '9' {
			return false
		}
		n = n*10 + int(r-'0')
	}
	return n > 0 && n <= 65535
}

func bracketed(host string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}
