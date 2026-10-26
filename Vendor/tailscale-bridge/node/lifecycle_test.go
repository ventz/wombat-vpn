package node

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// quality-9 M2: the extension outlives every tunnel, so a start/stop cycle must not leave
// goroutines behind (the event bus and the dialer leaked about 3 per cycle).
func TestStartStopLeavesNoGoroutines(t *testing.T) {
	cycle := func() int {
		control := "https://hs.example.invalid"
		dir := filepath.Join(t.TempDir(), ControlKey(control))
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		n, err := Start(Config{StateDir: dir, ControlURL: control, Log: func(string) {}})
		if err != nil {
			t.Fatalf("start: %v", err)
		}
		time.Sleep(300 * time.Millisecond)
		n.Stop()
		time.Sleep(500 * time.Millisecond)
		runtime.GC()
		return runtime.NumGoroutine()
	}
	first := cycle()
	var last int
	for i := 0; i < 4; i++ {
		last = cycle()
	}
	if last > first+1 {
		t.Fatalf("goroutines grew from %d to %d over 4 more start/stop cycles", first, last)
	}
}
