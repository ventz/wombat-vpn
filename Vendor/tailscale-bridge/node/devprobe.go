//go:build wombat_devprobe

package node

// The command-line probe talks to a plain-http Headscale on 127.0.0.1 (scripts/dev/headscale-peer.sh).
// Never in the extension: build-ts-go.sh refuses the wombat_devprobe tag.
func init() {
	allowLoopbackHTTP = true
	devBuild = "wombat_devprobe build: plain http allowed on loopback"
}
