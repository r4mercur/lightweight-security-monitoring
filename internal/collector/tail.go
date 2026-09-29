package collector

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"time"
)

// tailer follows a file like `tail -F`: it waits for the file to appear,
// emits every complete line and survives rotation (rename + create) and
// truncation (copytruncate). It polls instead of using OS notifications,
// which keeps it dependency-free and works the same on every platform.
type tailer struct {
	path      string
	fromStart bool
	poll      time.Duration
	maxLine   int
	logger    *slog.Logger
}

// run blocks until ctx is cancelled and calls emit for every line (without
// the trailing newline). Lines longer than maxLine are dropped.
func (t *tailer) run(ctx context.Context, emit func(line string)) error {
	seekEnd := !t.fromStart
	for {
		f, waited, err := t.open(ctx)
		if err != nil {
			return err
		}
		// A file that did not exist when we started contains only new lines.
		err = t.follow(ctx, f, seekEnd && !waited, emit)
		_ = f.Close()
		if err != nil {
			return err
		}
		// The file was rotated: read the new one from its beginning.
		seekEnd = false
	}
}

// open waits until the file can be opened. waited reports whether the first
// attempt failed.
func (t *tailer) open(ctx context.Context) (f *os.File, waited bool, err error) {
	var lastErr string
	for {
		f, err := openShared(t.path)
		if err == nil {
			return f, waited, nil
		}
		waited = true
		// Log each distinct error once instead of on every poll.
		if msg := err.Error(); msg != lastErr {
			lastErr = msg
			level := slog.LevelWarn
			if errors.Is(err, fs.ErrNotExist) {
				level = slog.LevelInfo
			}
			t.logger.Log(ctx, level, "waiting for log file", slog.String("path", t.path), slog.String("error", msg))
		}
		if err := sleep(ctx, t.poll); err != nil {
			return nil, waited, err
		}
	}
}

// follow reads f until ctx is cancelled (returns ctx.Err()) or the file on
// disk has been replaced and the old one is fully drained (returns nil).
func (t *tailer) follow(ctx context.Context, f *os.File, seekEnd bool, emit func(string)) error {
	var offset int64
	if seekEnd {
		var err error
		if offset, err = f.Seek(0, io.SeekEnd); err != nil {
			return nil // reopen
		}
	}

	r := bufio.NewReaderSize(f, 64<<10)
	var (
		partial    []byte
		discarding bool // inside a line that exceeded maxLine
		rotated    bool
	)
	for {
		chunk, err := r.ReadSlice('\n')
		offset += int64(len(chunk))

		switch {
		case err == nil:
			line := bytes.TrimRight(append(partial, chunk...), "\r\n")
			switch {
			case discarding:
			case len(line) > t.maxLine:
				t.logger.Warn("dropping oversized log line", slog.String("path", t.path), slog.Int("max_bytes", t.maxLine))
			case len(line) > 0:
				emit(string(line))
			}
			partial, discarding = partial[:0], false
			continue

		case errors.Is(err, bufio.ErrBufferFull), errors.Is(err, io.EOF):
			if !discarding {
				if len(partial)+len(chunk) > t.maxLine {
					t.logger.Warn("dropping oversized log line", slog.String("path", t.path), slog.Int("max_bytes", t.maxLine))
					partial, discarding = partial[:0], true
				} else {
					partial = append(partial, chunk...)
				}
			}
			if errors.Is(err, bufio.ErrBufferFull) {
				continue
			}

		default:
			t.logger.Warn("reading log file failed, reopening", slog.String("path", t.path), slog.String("error", err.Error()))
			return nil
		}

		// EOF: the old file is drained after a rotation, switch to the new one.
		if rotated {
			return nil
		}
		if err := sleep(ctx, t.poll); err != nil {
			return err
		}

		current, errCur := f.Stat()
		onDisk, errDisk := os.Stat(t.path)
		switch {
		case errCur != nil:
			return nil
		case errDisk != nil:
			// Removed and not yet recreated: keep reading the old file.
		case !os.SameFile(current, onDisk):
			// Drain what was written to the old file before switching.
			rotated = true
		case onDisk.Size() < offset:
			t.logger.Info("log file truncated, reading from start", slog.String("path", t.path))
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return nil
			}
			r.Reset(f)
			offset, partial, discarding = 0, partial[:0], false
		}
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
