// Package logger provides a pre-configured slog.Logger for structured JSON logging.
package logger

import (
	"log/slog"
	"os"
)

// New returns a JSON-structured slog.Logger writing to stdout.
// The log level defaults to Info but can be overridden by the logLevel parameter.
func New(level slog.Level) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}
