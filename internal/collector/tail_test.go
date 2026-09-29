package collector

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

var discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// The tailer tests run in a synctest bubble: the tailer's poll timer uses the
// bubble's fake clock, so the tests advance time explicitly instead of sleeping
// and waiting for timeouts. synctest also fails a test whose goroutines do not
// exit, which checks that the tailer stops on cancellation.

const testPoll = 5 * time.Millisecond

// startTailer runs a tailer in the background and returns a channel with the emitted lines.
func startTailer(t *testing.T, path string, fromStart bool) <-chan string {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	lines := make(chan string, 100)
	done := make(chan struct{})

	tl := &tailer{path: path, fromStart: fromStart, poll: testPoll, maxLine: 100, logger: discardLogger}
	go func() {
		defer close(done)
		_ = tl.run(ctx, func(l string) { lines <- l })
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return lines
}

// settle lets the tailer run one poll cycle and waits until it is idle again.
func settle() { synctest.Sleep(2 * testPoll) }

// expectLines lets the tailer catch up and checks exactly these lines were emitted.
func expectLines(t *testing.T, lines <-chan string, want ...string) {
	t.Helper()
	settle()
	for _, w := range want {
		select {
		case got := <-lines:
			if got != w {
				t.Fatalf("got line %q, want %q", got, w)
			}
		default:
			t.Fatalf("line %q was not emitted", w)
		}
	}
	select {
	case extra := <-lines:
		t.Fatalf("unexpected extra line %q", extra)
	default:
	}
}

func appendFile(t *testing.T, path, data string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(data); err != nil {
		t.Fatal(err)
	}
}

func TestTailer_FromStartAndFollow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "access.log")
		appendFile(t, path, "one\ntwo\r\n")

		lines := startTailer(t, path, true)
		expectLines(t, lines, "one", "two")

		appendFile(t, path, "three\n")
		expectLines(t, lines, "three")
	})
}

func TestTailer_SkipsExistingContentByDefault(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "access.log")
		appendFile(t, path, "old\n")

		lines := startTailer(t, path, false)
		settle()
		appendFile(t, path, "new\n")
		expectLines(t, lines, "new")
	})
}

func TestTailer_PartialLinesAreJoined(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "access.log")
		appendFile(t, path, "")

		lines := startTailer(t, path, false)
		settle()
		appendFile(t, path, "hel")
		expectLines(t, lines) // nothing yet: the line is incomplete
		appendFile(t, path, "lo\n")
		expectLines(t, lines, "hello")
	})
}

func TestTailer_WaitsForFile(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "access.log")

		lines := startTailer(t, path, false)
		settle()
		appendFile(t, path, "first\n")
		expectLines(t, lines, "first")
	})
}

func TestTailer_Truncation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "access.log")
		appendFile(t, path, "")

		lines := startTailer(t, path, false)
		settle()
		appendFile(t, path, "before truncate\n")
		expectLines(t, lines, "before truncate")

		if err := os.Truncate(path, 0); err != nil {
			t.Fatal(err)
		}
		settle()
		appendFile(t, path, "after\n")
		expectLines(t, lines, "after")
	})
}

func TestTailer_Rotation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "access.log")
		appendFile(t, path, "")

		lines := startTailer(t, path, false)
		settle()
		appendFile(t, path, "old file\n")
		expectLines(t, lines, "old file")

		if err := os.Rename(path, filepath.Join(dir, "access.log.1")); err != nil {
			t.Skipf("renaming an open file is not supported here: %v", err)
		}
		appendFile(t, path, "new file\n")
		expectLines(t, lines, "new file")
	})
}

func TestTailer_DropsOversizedLines(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "access.log")
		appendFile(t, path, strings.Repeat("x", 500)+"\nok\n")

		lines := startTailer(t, path, true)
		expectLines(t, lines, "ok")
	})
}
