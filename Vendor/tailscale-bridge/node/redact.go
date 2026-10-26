package node

import (
	"bytes"
	"regexp"
	"strings"
	"sync"
)

// redactedLine replaces a whole line that names a secret (design 2.8).
const redactedLine = "[redacted line]"

// lineMarkers: a line containing any of these (case-insensitive) is dropped whole. Private key
// text forms ("privkey:" is both node and machine keys, "nlpriv:" tailnet lock), the Prefs JSON
// that carries Persist, auth keys, and sign-in URLs, which are bearer links for days.
var lineMarkers = []string{
	"privkey:", "nlpriv:", "privatekey", "persist", "authkey", "auth url", "authurl",
	"browsetourl", "/register/", "login.tailscale.com/a/",
}

// keyLike: 64 hex digits or 43-44 base64 characters, the untyped forms of a 32-byte key.
// Public keys show up as these too; they are replaced as well, which costs nothing useful:
// Tailscale's own lines name keys by their short "[AbCdE]" form.
var keyLike = regexp.MustCompile(`[0-9a-fA-F]{64}|[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/_-]{43}(?:[^A-Za-z0-9+/_=-]|$)`)

// urlPath: everything after a URL's host. Sign-in links are bearer URLs whatever their path
// ("/register/", "/a/", a fork's "/auth/<id>"), and upstream prints some without any marker
// above ("control says to open URL %v"), so every URL keeps only its scheme and host
// (security-9 L3).
var urlPath = regexp.MustCompile(`(?i)(https?://[^/\s"'<>]+)/[^\s"'<>]*`)

// Redact returns line with secrets removed.
func Redact(line string) string {
	lower := strings.ToLower(line)
	for _, m := range lineMarkers {
		if strings.Contains(lower, m) {
			return redactedLine
		}
	}
	line = urlPath.ReplaceAllString(line, "$1/[path]")
	return keyLike.ReplaceAllStringFunc(line, func(s string) string {
		last := s[len(s)-1]
		if len(s) == 44 && !(last == '=' || isB64(last)) {
			return "[key]" + string(last)
		}
		return "[key]"
	})
}

func isB64(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '_' || c == '-'
}

// LineWriter is an io.Writer for log.SetOutput and logf sinks: it splits on newlines,
// truncates each line at 1024 bytes, redacts it, and hands it to sink. Safe for concurrent use.
type LineWriter struct {
	mu   sync.Mutex
	buf  []byte
	sink func(string)
}

func NewLineWriter(sink func(string)) *LineWriter { return &LineWriter{sink: sink} }

func (w *LineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		w.emit(w.buf[:i])
		w.buf = w.buf[i+1:]
	}
	// A line that never ends is still bounded.
	if len(w.buf) > 4096 {
		w.emit(w.buf)
		w.buf = w.buf[:0]
	}
	return len(p), nil
}

func (w *LineWriter) emit(line []byte) {
	// Redacted whole, then cut: cutting first could split a key and leave a fragment that no
	// longer matches (quality-7).
	// Tailscale's structured lines carry a NUL ("[v\x00JSON]"), which would end the C string
	// early; no control character survives.
	s := strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimRight(string(line), "\r"))
	if s == "" {
		return
	}
	s = Redact(s)
	if len(s) > 1024 {
		s = s[:1024]
	}
	w.sink(s)
}
