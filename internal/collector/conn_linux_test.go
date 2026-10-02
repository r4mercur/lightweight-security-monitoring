//go:build linux

package collector

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// readTable must return the whole file even when it exceeds the buffer.
func TestReadTable_GrowsBuffer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tcp")
	want := bytes.Repeat([]byte("0123456789abcdef\n"), 100)
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}

	p := &procNetSource{buf: make([]byte, 0, 64)}
	for range 2 { // the second read reuses the grown buffer
		got, err := p.readTable(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("read %d bytes, want %d", len(got), len(want))
		}
	}
}
